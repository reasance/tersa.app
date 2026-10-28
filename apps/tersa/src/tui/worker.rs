// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded account-local network workers and owned shutdown, using Tokio only.
//!
//! Each account gets one instance of the existing current-thread Tokio worker.
//! A blocking store call therefore cannot occupy another account's executor.
//! The UI admits one sync per account and at most eight unsettled fetch jobs;
//! completed-but-unconsumed events count against that same admission bound.

use std::collections::{HashMap, HashSet};
use std::pin::pin;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};
use std::task::Poll;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tersa_application::mailbox::AccountId;
use tersa_application::unified_mailbox::MAX_ACCOUNTS;

use super::{MessageKey, Remote, SYNC_EVERY};

/// Allows a short burst of navigation while bounding queued jobs and results.
const MAX_FETCHES: usize = 8;
/// Shared grace period for cooperative shutdown. Native calls may outlast it;
/// finalization must still join their owners before releasing the app lock.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(30);

enum Job {
    Fetch(MessageKey, u64),
    Sync,
}

pub(super) enum Done {
    Fetched(MessageKey, Result<Vec<u8>, String>, u64),
    Skipped(MessageKey, u64),
    Synced(AccountId, Result<(), String>),
}

pub(super) struct Workers {
    pub accounts: Vec<Worker>,
}

impl Workers {
    pub fn start(remotes: Vec<(AccountId, Box<dyn Remote>)>) -> Result<Self, String> {
        let mut ids = HashSet::new();
        if remotes.len() > MAX_ACCOUNTS || remotes.iter().any(|(id, _)| !ids.insert(id.clone())) {
            return Err("network workers require at most five distinct accounts".to_owned());
        }
        let mut workers = Self {
            accounts: Vec::new(),
        };
        for (account, remote) in remotes {
            workers.accounts.push(Worker::start(account, remote)?);
        }
        Ok(workers)
    }

    pub fn shutdown_until(&mut self, deadline: Instant) -> bool {
        for worker in &mut self.accounts {
            worker.stop();
        }
        let mut joined = true;
        for worker in &mut self.accounts {
            joined &= worker.join_until(deadline);
        }
        joined
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Cancels only old-view downloads; automatic account sync stays active.
    pub fn change_view(&self, epoch: u64) {
        for worker in &self.accounts {
            worker.view.send_replace(epoch);
        }
    }

    pub fn set_open(&self, key: Option<&MessageKey>) {
        for worker in &self.accounts {
            worker.set_open(key);
        }
    }

    pub fn fetch(&mut self, key: &MessageKey) -> bool {
        let Some(index) = self
            .accounts
            .iter()
            .position(|worker| worker.account == key.0)
        else {
            return false;
        };
        self.set_open(Some(key));
        self.accounts[index].fetch(key)
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        // Signal EVERY worker before waiting, with one grace deadline for the
        // group. A native call cannot be interrupted safely. Keep its handle
        // and join normally after grace expires, without forcing process exit.
        let _ = self.shutdown_until(shutdown_deadline());
        for worker in &mut self.accounts {
            worker.join_remaining();
        }
    }
}

pub(super) struct Worker {
    pub account: AccountId,
    jobs: tokio::sync::mpsc::UnboundedSender<Job>,
    pub done: Receiver<Done>,
    pub fetching: HashMap<MessageKey, u64>,
    open: tokio::sync::watch::Sender<Option<MessageKey>>,
    view: tokio::sync::watch::Sender<u64>,
    pub syncing: bool,
    /// Starts, not repeated/coalesced requests, advance the five-minute clock.
    last_sync: Option<(Instant, SystemTime)>,
    pub dead: bool,
    shutdown: tokio::sync::watch::Sender<bool>,
    stopped: Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(account: AccountId, remote: Box<dyn Remote>) -> Result<Self, String> {
        let (jobs, mut incoming) = tokio::sync::mpsc::unbounded_channel::<Job>();
        let (outgoing, done) = mpsc::channel();
        let (open, wanted) = tokio::sync::watch::channel(None::<MessageKey>);
        let (views, view) = tokio::sync::watch::channel(0_u64);
        let (shutdown, mut stopping) = tokio::sync::watch::channel(false);
        let (alive, stopped) = mpsc::channel::<()>();
        let own_account = account.clone();
        let thread = std::thread::Builder::new()
            .name("tersa-network".to_owned())
            .spawn(move || {
                // Last local dropped: acknowledgement follows task, remote, store
                // and executor cleanup. Only then may the UI join this thread.
                let _alive = alive;
                let (remote, outgoing, wanted, view) = (remote, outgoing, wanted, view);
                let Ok(executor) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                let remote: Rc<dyn Remote> = Rc::from(remote);
                let tasks = tokio::task::LocalSet::new();
                tasks.block_on(&executor, async move {
                    loop {
                        let job = match first(until_stopped(&mut stopping), incoming.recv()).await {
                            First::Left(()) | First::Right(None) => break,
                            First::Right(Some(job)) => job,
                        };
                        let remote = Rc::clone(&remote);
                        let outgoing = outgoing.clone();
                        let wanted = wanted.clone();
                        let view = view.clone();
                        let account = own_account.clone();
                        tokio::task::spawn_local(async move {
                            let finished = match job {
                                Job::Fetch(key, epoch) => {
                                    download(&*remote, wanted, view, key, epoch).await
                                }
                                Job::Sync => {
                                    let result = remote.sync(&account).await;
                                    Done::Synced(account, result)
                                }
                            };
                            let _ = outgoing.send(finished);
                        });
                    }
                });
                // Cancels owned network futures. DNS lookups already dispatched by
                // Tokio may finish detached, retaining no store state (old contract).
                drop(tasks);
                executor.shutdown_background();
            })
            .map_err(|_error| "could not start an account network worker".to_owned())?;
        Ok(Self {
            account,
            jobs,
            done,
            fetching: HashMap::new(),
            open,
            view: views,
            syncing: false,
            last_sync: None,
            dead: false,
            shutdown,
            stopped,
            thread: Some(thread),
        })
    }

    pub fn set_open(&self, key: Option<&MessageKey>) {
        // Returning to the list keeps the LAST wanted key, so a rapid A -> B
        // -> list cannot erase B's cancellation of A before a worker polls it.
        if let Some(key) = key {
            self.open.send_if_modified(|open| {
                if open.as_ref() == Some(key) {
                    return false;
                }
                *open = Some(key.clone());
                true
            });
        }
    }

    pub fn fetch(&mut self, key: &MessageKey) -> bool {
        if key.0 != self.account || self.dead {
            return false;
        }
        if self.fetching.contains_key(key) {
            return true;
        }
        if self.fetching.len() >= MAX_FETCHES {
            return false;
        }
        let epoch = *self.view.borrow();
        let sent = self.jobs.send(Job::Fetch(key.clone(), epoch)).is_ok();
        if sent {
            self.fetching.insert(key.clone(), epoch);
        }
        sent
    }

    /// A stale completion cannot settle a newer same-key request.
    pub fn finish_fetch(&mut self, key: &MessageKey, epoch: u64) -> bool {
        if self.fetching.get(key) != Some(&epoch) {
            return false;
        }
        self.fetching.remove(key);
        true
    }

    pub fn sync_at(&mut self, monotonic: Instant, wall: SystemTime) -> bool {
        if self.dead {
            return false;
        }
        if self.syncing {
            return true;
        }
        if self.jobs.send(Job::Sync).is_err() {
            return false;
        }
        self.last_sync = Some((monotonic, wall));
        self.syncing = true;
        true
    }

    pub fn sync_due_at(&self, monotonic: Instant, wall: SystemTime) -> bool {
        !self.dead
            && !self.syncing
            && self.last_sync.is_none_or(|(started, wall_started)| {
                monotonic.saturating_duration_since(started) >= SYNC_EVERY
                    || wall
                        .duration_since(wall_started)
                        .is_ok_and(|elapsed| elapsed >= SYNC_EVERY)
            })
    }

    pub fn next_sync_millis(&self) -> Option<i64> {
        let (_, started) = self.last_sync?;
        let at = started
            .checked_add(SYNC_EVERY)?
            .duration_since(UNIX_EPOCH)
            .ok()?;
        i64::try_from(at.as_millis()).ok()
    }

    fn stop(&mut self) {
        self.dead = true;
        self.shutdown.send_replace(true);
        let (closed, _) = tokio::sync::mpsc::unbounded_channel();
        drop(std::mem::replace(&mut self.jobs, closed));
    }

    fn join_until(&mut self, deadline: Instant) -> bool {
        if self.thread.is_none() {
            return true;
        }
        match self
            .stopped
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                // The final owner acknowledgement guarantees no store/TLS or
                // user cleanup remains on the thread before join is called.
                while self
                    .thread
                    .as_ref()
                    .is_some_and(|thread| !thread.is_finished())
                {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return false;
                    }
                    std::thread::park_timeout(remaining.min(Duration::from_millis(1)));
                }
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
                true
            }
            Err(mpsc::RecvTimeoutError::Timeout) => false,
        }
    }

    fn join_remaining(&mut self) {
        if let Some(thread) = self.thread.take() {
            #[cfg(test)]
            tests::JOIN_OBSERVER.with(|observer| {
                if let Some(observer) = observer.borrow().as_ref() {
                    let _ = observer.send(self.account.clone());
                }
            });
            // The local JoinHandle remains owned throughout this wait. There
            // is no hard exit deadline if an already-running native call hangs.
            let _ = thread.join();
        }
    }

    #[cfg(test)]
    pub fn fixture(
        account: AccountId,
        done: Receiver<Done>,
        syncing: bool,
        fetching: HashSet<MessageKey>,
    ) -> Self {
        let (jobs, _) = tokio::sync::mpsc::unbounded_channel();
        Self {
            account,
            jobs,
            done,
            syncing,
            fetching: fetching.into_iter().map(|key| (key, 0)).collect(),
            open: tokio::sync::watch::channel(None).0,
            view: tokio::sync::watch::channel(0).0,
            last_sync: None,
            dead: false,
            shutdown: tokio::sync::watch::channel(false).0,
            stopped: mpsc::channel().1,
            thread: None,
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
        self.join_remaining();
    }
}

fn shutdown_deadline() -> Instant {
    #[cfg(test)]
    if let Some(deadline) = tests::DROP_DEADLINE.with(std::cell::Cell::get) {
        return deadline;
    }
    Instant::now() + SHUTDOWN_WAIT
}

async fn until_stopped(stopping: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *stopping.borrow_and_update() {
            return;
        }
        if stopping.changed().await.is_err() {
            return;
        }
    }
}

async fn download(
    remote: &dyn Remote,
    mut open: tokio::sync::watch::Receiver<Option<MessageKey>>,
    mut view: tokio::sync::watch::Receiver<u64>,
    key: MessageKey,
    epoch: u64,
) -> Done {
    let other_opened = async {
        loop {
            if *view.borrow_and_update() != epoch {
                break;
            }
            if open
                .borrow_and_update()
                .as_ref()
                .is_some_and(|wanted| wanted != &key)
            {
                break;
            }
            match first(view.changed(), open.changed()).await {
                First::Left(Err(_)) | First::Right(Err(_)) => break,
                _ => {}
            }
        }
    };
    match first(other_opened, remote.fetch(&key.0, &key.1)).await {
        First::Left(()) => Done::Skipped(key, epoch),
        First::Right(result) => Done::Fetched(key, result, epoch),
    }
}

enum First<A, B> {
    Left(A),
    Right(B),
}

async fn first<A: Future, B: Future>(left: A, right: B) -> First<A::Output, B::Output> {
    let mut left = pin!(left);
    let mut right = pin!(right);
    std::future::poll_fn(|context| {
        if let Poll::Ready(output) = left.as_mut().poll(context) {
            return Poll::Ready(First::Left(output));
        }
        if let Poll::Ready(output) = right.as_mut().poll(context) {
            return Poll::Ready(First::Right(output));
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::Pending;
    use std::sync::mpsc::Sender;
    use std::sync::{Arc, Mutex};
    use tersa_application::mailbox::MessageId;
    /// Records the order work finishes in; syncs wait for the test.
    struct Recorder {
        log: Sender<String>,
        release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl Remote for Recorder {
        fn fetch<'a>(&'a self, account: &'a AccountId, id: &'a MessageId) -> Pending<'a, Vec<u8>> {
            Box::pin(async move {
                let _ = self
                    .log
                    .send(format!("fetch {} {}", account.as_str(), id.as_str()));
                Ok(Vec::new())
            })
        }

        fn sync<'a>(&'a self, _account: &'a AccountId) -> Pending<'a, ()> {
            let release = self.release.lock().expect("lock").take();
            Box::pin(async move {
                if let Some(release) = release {
                    let _ = release.await;
                }
                let _ = self.log.send("sync".to_owned());
                Err("offline".to_owned())
            })
        }
    }

    fn id(text: &str) -> MessageId {
        MessageId::new(text).expect("id")
    }

    fn account(text: &str) -> AccountId {
        AccountId::new(text).expect("account")
    }

    fn key(account_text: &str, id_text: &str) -> MessageKey {
        (account(account_text), id(id_text))
    }

    #[test]
    fn downloads_finish_while_a_sync_is_still_running() {
        let (log, entries) = mpsc::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let mut worker = Worker::start(
            account("acct_a"),
            Box::new(Recorder {
                log,
                release: Mutex::new(Some(released)),
            }),
        )
        .expect("worker");
        let next = || {
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("work finishes")
        };
        assert!(worker.sync_at(Instant::now(), SystemTime::now()));
        assert!(
            worker.sync_at(Instant::now(), SystemTime::now()),
            "a second request joins the running sync"
        );
        worker.set_open(Some(&key("acct_a", "a")));
        assert!(worker.fetch(&key("acct_a", "a")));
        assert!(worker.fetch(&key("acct_a", "a")), "a repeat is merged");
        assert_eq!(next(), "fetch acct_a a");
        worker.set_open(Some(&key("acct_a", "b")));
        assert!(worker.fetch(&key("acct_a", "b")));
        assert_eq!(next(), "fetch acct_a b");
        release.send(()).expect("release");
        assert_eq!(next(), "sync");
        let mut fetched = 0;
        let mut synced = 0;
        for _ in 0..3 {
            match worker.done.recv_timeout(Duration::from_secs(5)) {
                Ok(Done::Fetched(_, Ok(_), _)) => fetched += 1,
                Ok(Done::Synced(_, Err(error))) if error == "offline" => synced += 1,
                _ => panic!("unexpected result"),
            }
        }
        assert_eq!((fetched, synced), (2, 1));
        assert!(
            entries.recv_timeout(Duration::from_millis(100)).is_err(),
            "nothing ran twice"
        );
        // The sync finished; the five-minute clock now decides.
        worker.syncing = false;
        assert!(
            !worker.sync_due_at(Instant::now(), SystemTime::now()),
            "a sync was just asked for"
        );
        worker.last_sync = worker
            .last_sync
            .map(|(monotonic, wall)| (monotonic, wall - SYNC_EVERY));
        assert!(
            worker.sync_due_at(Instant::now(), SystemTime::now()),
            "five minutes later another one is due"
        );
    }

    #[test]
    fn downloads_for_messages_no_longer_open_are_skipped() {
        let (log, entries) = mpsc::channel();
        let mut worker = Worker::start(
            account("acct_a"),
            Box::new(Recorder {
                log,
                release: Mutex::new(None),
            }),
        )
        .expect("worker");
        worker.set_open(Some(&key("acct_a", "now")));
        for stale in ["s1", "s2", "s3", "s4", "s5", "s6"] {
            assert!(worker.fetch(&key("acct_a", stale)));
        }
        assert!(worker.fetch(&key("acct_a", "now")));
        assert_eq!(
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("work finishes"),
            "fetch acct_a now"
        );
        let mut skipped = 0;
        for _ in 0..7 {
            match worker.done.recv_timeout(Duration::from_secs(5)) {
                Ok(Done::Skipped(_, _)) => skipped += 1,
                Ok(Done::Fetched(key, Ok(_), _)) => assert_eq!(key.1.as_str(), "now"),
                _ => panic!("unexpected result"),
            }
        }
        assert_eq!(skipped, 6);
        assert!(
            entries.recv_timeout(Duration::from_millis(100)).is_err(),
            "stale messages were never downloaded"
        );
    }

    /// Downloads of ids starting with "slow" wait until the test opens the
    /// gate.
    struct Gated {
        log: Sender<String>,
        gate: Arc<tokio::sync::Semaphore>,
    }

    impl Remote for Gated {
        fn fetch<'a>(&'a self, _account: &'a AccountId, id: &'a MessageId) -> Pending<'a, Vec<u8>> {
            Box::pin(async move {
                let _ = self.log.send(format!("start {}", id.as_str()));
                if id.as_str().starts_with("slow") {
                    let _ = self.gate.acquire().await;
                }
                let _ = self.log.send(format!("fetch {}", id.as_str()));
                Ok(Vec::new())
            })
        }

        fn sync<'a>(&'a self, _account: &'a AccountId) -> Pending<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn opening_another_message_stops_a_running_download() {
        let (log, entries) = mpsc::channel();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut worker = Worker::start(
            account("acct_a"),
            Box::new(Gated {
                log,
                gate: Arc::clone(&gate),
            }),
        )
        .expect("worker");
        let next = || {
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("work starts")
        };
        worker.set_open(Some(&key("acct_a", "slow")));
        assert!(worker.fetch(&key("acct_a", "slow")));
        assert_eq!(next(), "start slow");
        worker.set_open(Some(&key("acct_a", "now")));
        assert!(worker.fetch(&key("acct_a", "now")));
        assert_eq!(next(), "start now");
        assert_eq!(next(), "fetch now", "it did not wait for the slow one");
        let mut results = Vec::new();
        for _ in 0..2 {
            match worker.done.recv_timeout(Duration::from_secs(5)) {
                Ok(Done::Skipped(key, _)) => results.push(format!("skipped {}", key.1.as_str())),
                Ok(Done::Fetched(key, Ok(_), _)) => {
                    results.push(format!("fetched {}", key.1.as_str()));
                }
                _ => panic!("unexpected result"),
            }
        }
        results.sort();
        assert_eq!(results, ["fetched now", "skipped slow"]);
        gate.add_permits(1);
        assert!(
            entries.recv_timeout(Duration::from_millis(100)).is_err(),
            "the stopped download never finished"
        );
    }

    #[test]
    fn going_back_to_the_list_keeps_a_download_running() {
        let (log, entries) = mpsc::channel();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut worker = Worker::start(
            account("acct_a"),
            Box::new(Gated {
                log,
                gate: Arc::clone(&gate),
            }),
        )
        .expect("worker");
        worker.set_open(Some(&key("acct_a", "slow")));
        assert!(worker.fetch(&key("acct_a", "slow")));
        assert_eq!(
            entries.recv_timeout(Duration::from_secs(5)).expect("start"),
            "start slow"
        );
        worker.set_open(None);
        gate.add_permits(1);
        assert!(matches!(
            worker.done.recv_timeout(Duration::from_secs(5)),
            Ok(Done::Fetched(key, Ok(_), _)) if key.1.as_str() == "slow"
        ));
    }

    #[test]
    fn opening_the_same_id_in_another_account_cancels_the_old_download() {
        let (log, entries) = mpsc::channel();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut workers = Workers::start(vec![
            (
                account("acct_a"),
                Box::new(Gated {
                    log: log.clone(),
                    gate: Arc::clone(&gate),
                }),
            ),
            (
                account("acct_b"),
                Box::new(Gated {
                    log,
                    gate: Arc::clone(&gate),
                }),
            ),
        ])
        .expect("workers");
        let old = key("acct_a", "slow");
        let current = key("acct_b", "slow");
        assert!(workers.fetch(&old));
        assert_eq!(
            entries.recv_timeout(Duration::from_secs(5)).expect("start"),
            "start slow"
        );
        assert!(workers.fetch(&current));
        // Returning to the list cannot erase the previous cancellation.
        workers.set_open(None);
        assert_eq!(
            entries.recv_timeout(Duration::from_secs(5)).expect("start"),
            "start slow"
        );
        assert!(
            matches!(workers.accounts[0].done.recv_timeout(Duration::from_secs(5)), Ok(Done::Skipped(key, _)) if key == old)
        );
        gate.add_permits(1);
        assert!(
            matches!(workers.accounts[1].done.recv_timeout(Duration::from_secs(5)), Ok(Done::Fetched(key, Ok(_), _)) if key == current)
        );
        assert_eq!(
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("finish"),
            "fetch slow"
        );
    }

    #[test]
    fn downloads_of_the_same_id_in_two_accounts_route_without_fallback() {
        let (log, entries) = mpsc::channel();
        let mut workers = Workers::start(vec![
            (
                account("acct_a"),
                Box::new(Recorder {
                    log: log.clone(),
                    release: Mutex::new(None),
                }),
            ),
            (
                account("acct_b"),
                Box::new(Recorder {
                    log,
                    release: Mutex::new(None),
                }),
            ),
        ])
        .expect("workers");
        for (index, account_name) in ["acct_a", "acct_b"].into_iter().enumerate() {
            let wanted = key(account_name, "m");
            assert!(workers.fetch(&wanted));
            assert!(
                matches!(workers.accounts[index].done.recv_timeout(Duration::from_secs(5)), Ok(Done::Fetched(key, Ok(_), _)) if key == wanted)
            );
            assert_eq!(
                entries.recv_timeout(Duration::from_secs(5)).expect("route"),
                format!("fetch {account_name} m")
            );
        }
        assert!(!workers.fetch(&key("acct_unknown", "m")));
        assert!(!workers.accounts[0].fetch(&key("acct_b", "m")));
    }
    #[test]
    fn a_sync_is_due_after_a_sleep_the_monotonic_clock_missed() {
        let (log, _entries) = mpsc::channel();
        let mut worker = Worker::start(
            account("acct_a"),
            Box::new(Recorder {
                log,
                release: Mutex::new(None),
            }),
        )
        .expect("worker");
        let before_sleep = SystemTime::now() - SYNC_EVERY - Duration::from_secs(1);
        worker.last_sync = Some((Instant::now(), before_sleep));
        assert!(worker.sync_due_at(Instant::now(), SystemTime::now()));
        worker.last_sync = Some((Instant::now(), SystemTime::now()));
        assert!(!worker.sync_due_at(Instant::now(), SystemTime::now()));
    }

    // Test-thread-only seams exercise the real Drop route without waiting 30s.
    // The observer fires only when a still-owned handle reaches the join path.
    std::thread_local! {
        pub(super) static DROP_DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
        pub(super) static JOIN_OBSERVER: std::cell::RefCell<Option<Sender<AccountId>>> = const { std::cell::RefCell::new(None) };
    }

    const TEST_WAIT: Duration = Duration::from_secs(5);

    enum Gate {
        Ready(Result<(), String>),
        Network(tokio::sync::oneshot::Receiver<Result<(), String>>),
        Store(mpsc::Receiver<Result<(), String>>),
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Event {
        Started(AccountId),
        Fetch(MessageKey),
        FutureDropped(AccountId),
        OwnerDropped(AccountId),
    }

    struct Active {
        account: AccountId,
        events: Sender<Event>,
        count: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for Active {
        fn drop(&mut self) {
            self.count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            let _ = self.events.send(Event::FutureDropped(self.account.clone()));
        }
    }

    struct Controlled {
        account: AccountId,
        gate: Mutex<Option<Gate>>,
        events: Sender<Event>,
        active: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Controlled {
        fn remote(name: &str, gate: Gate, events: Sender<Event>) -> Box<dyn Remote> {
            Box::new(Self {
                account: account(name),
                gate: Mutex::new(Some(gate)),
                events,
                active: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            })
        }
    }
    impl Drop for Controlled {
        fn drop(&mut self) {
            let _ = self.events.send(Event::OwnerDropped(self.account.clone()));
        }
    }
    impl Remote for Controlled {
        fn fetch<'a>(&'a self, account: &'a AccountId, id: &'a MessageId) -> Pending<'a, Vec<u8>> {
            Box::pin(async move {
                assert_eq!(account, &self.account);
                let _ = self
                    .events
                    .send(Event::Fetch((account.clone(), id.clone())));
                Ok(format!("{}/{}", account.as_str(), id.as_str()).into_bytes())
            })
        }
        fn sync<'a>(&'a self, account: &'a AccountId) -> Pending<'a, ()> {
            Box::pin(async move {
                assert_eq!(account, &self.account);
                assert_eq!(
                    self.active
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    0,
                    "overlapping cycle for one account"
                );
                let _active = Active {
                    account: account.clone(),
                    events: self.events.clone(),
                    count: Arc::clone(&self.active),
                };
                let gate = self.gate.lock().expect("gate").take();
                let _ = self.events.send(Event::Started(account.clone()));
                match gate {
                    Some(Gate::Network(gate)) => gate.await.expect("network gate"),
                    Some(Gate::Store(gate)) => gate.recv_timeout(TEST_WAIT).expect("store gate"),
                    Some(Gate::Ready(result)) => result,
                    None => Ok(()),
                }
            })
        }
    }

    fn wait_started(events: &Receiver<Event>, expected: &AccountId) {
        let deadline = Instant::now() + TEST_WAIT;
        loop {
            let event = events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("worker starts");
            if event == Event::Started(expected.clone()) {
                return;
            }
        }
    }

    #[test]
    fn a_blocked_store_account_does_not_block_peer_sync_or_download() {
        let (events, observed) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut workers = Workers::start(vec![
            (
                account("acct_a"),
                Controlled::remote("acct_a", Gate::Store(gate), events.clone()),
            ),
            (
                account("acct_b"),
                Controlled::remote("acct_b", Gate::Ready(Ok(())), events),
            ),
        ])
        .expect("workers");
        let start = (Instant::now(), SystemTime::now());
        assert!(workers.accounts[0].sync_at(start.0, start.1));
        wait_started(&observed, &account("acct_a"));
        assert!(workers.accounts[1].sync_at(start.0, start.1));
        assert!(
            matches!(workers.accounts[1].done.recv_timeout(TEST_WAIT), Ok(Done::Synced(id, Ok(()))) if id == account("acct_b"))
        );
        let wanted = key("acct_b", "same");
        assert!(workers.fetch(&wanted));
        assert!(
            matches!(workers.accounts[1].done.recv_timeout(TEST_WAIT), Ok(Done::Fetched(key, Ok(raw), _)) if key == wanted && raw == b"acct_b/same")
        );
        assert!(matches!(
            workers.accounts[0].done.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(workers.accounts[0].sync_at(
            start.0 + Duration::from_secs(60),
            start.1 + Duration::from_secs(60)
        ));
        assert_eq!(
            workers.accounts[0].last_sync,
            Some(start),
            "coalescing does not move the deadline"
        );
        release
            .send(Err("authorization required".to_owned()))
            .expect("release A");
        assert!(
            matches!(workers.accounts[0].done.recv_timeout(TEST_WAIT), Ok(Done::Synced(id, Err(error))) if id == account("acct_a") && error == "authorization required")
        );
    }

    #[test]
    fn account_deadlines_manual_coalescing_and_no_overlapping_cycles() {
        let (events, observed) = mpsc::channel();
        let (release_a, a) = tokio::sync::oneshot::channel();
        let (release_b, b) = tokio::sync::oneshot::channel();
        let mut workers = Workers::start(vec![
            (
                account("acct_a"),
                Controlled::remote("acct_a", Gate::Network(a), events.clone()),
            ),
            (
                account("acct_b"),
                Controlled::remote("acct_b", Gate::Network(b), events),
            ),
        ])
        .expect("workers");
        let mono = Instant::now();
        let wall = UNIX_EPOCH + Duration::from_secs(10_000);
        assert!(workers.accounts[0].sync_due_at(mono, wall));
        assert!(workers.accounts[0].sync_at(mono, wall));
        wait_started(&observed, &account("acct_a"));
        assert!(workers.accounts[1].sync_at(
            mono + Duration::from_secs(60),
            wall + Duration::from_secs(60)
        ));
        wait_started(&observed, &account("acct_b"));
        for _ in 0..8 {
            assert!(workers.accounts[0].sync_at(
                mono + Duration::from_secs(120),
                wall + Duration::from_secs(120)
            ));
        }
        assert_eq!(workers.accounts[0].next_sync_millis(), Some(10_300_000));
        assert_eq!(workers.accounts[1].next_sync_millis(), Some(10_360_000));
        assert!(
            !workers.accounts[0].sync_due_at(mono + SYNC_EVERY, wall + SYNC_EVERY),
            "running cycles never overlap"
        );
        release_a.send(Ok(())).expect("release A");
        assert!(matches!(
            workers.accounts[0].done.recv_timeout(TEST_WAIT),
            Ok(Done::Synced(_, Ok(())))
        ));
        workers.accounts[0].syncing = false; // Apply the real completion as the UI does.
        assert!(
            !workers.accounts[0].sync_due_at(
                mono + SYNC_EVERY
                    .checked_sub(Duration::from_nanos(1))
                    .expect("positive period"),
                wall
            )
        );
        assert!(workers.accounts[0].sync_due_at(mono + SYNC_EVERY, wall));
        assert!(!workers.accounts[1].sync_due_at(mono + SYNC_EVERY, wall + SYNC_EVERY));
        assert!(workers.accounts[0].sync_at(mono + SYNC_EVERY, wall + SYNC_EVERY));
        assert!(matches!(
            workers.accounts[0].done.recv_timeout(TEST_WAIT),
            Ok(Done::Synced(_, Ok(())))
        ));
        release_b.send(Ok(())).expect("release B");
        assert!(matches!(
            workers.accounts[1].done.recv_timeout(TEST_WAIT),
            Ok(Done::Synced(_, Ok(())))
        ));
    }

    #[test]
    fn five_owned_workers_cancel_futures_and_join_before_shutdown_returns() {
        let (events, observed) = mpsc::channel();
        let mut releases = Vec::new();
        let remotes = (0..5)
            .map(|index| {
                let name = format!("acct_{index}");
                let (release, gate) = tokio::sync::oneshot::channel();
                releases.push(release);
                (
                    account(&name),
                    Controlled::remote(&name, Gate::Network(gate), events.clone()),
                )
            })
            .collect();
        let mut workers = Workers::start(remotes).expect("five workers");
        for worker in &mut workers.accounts {
            assert!(worker.sync_at(Instant::now(), SystemTime::now()));
            wait_started(&observed, &worker.account);
        }
        assert!(workers.shutdown_until(Instant::now() + TEST_WAIT));
        assert!(
            workers
                .accounts
                .iter()
                .all(|worker| worker.thread.is_none())
        );
        let events: Vec<_> = observed.try_iter().collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::FutureDropped(_)))
                .count(),
            5
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::OwnerDropped(_)))
                .count(),
            5
        );
        assert!(
            workers
                .accounts
                .iter_mut()
                .all(|worker| !worker.sync_at(Instant::now(), SystemTime::now()))
        );
        drop(releases);
    }

    #[test]
    fn shutdown_signals_other_accounts_before_waiting_for_a_blocked_store() {
        let (events, observed) = mpsc::channel();
        let (release_a, gate_a) = mpsc::channel();
        let (_release_b, gate_b) = tokio::sync::oneshot::channel();
        let mut workers = Workers::start(vec![
            (
                account("acct_a"),
                Controlled::remote("acct_a", Gate::Store(gate_a), events.clone()),
            ),
            (
                account("acct_b"),
                Controlled::remote("acct_b", Gate::Network(gate_b), events),
            ),
        ])
        .expect("workers");
        for worker in &mut workers.accounts {
            assert!(worker.sync_at(Instant::now(), SystemTime::now()));
            wait_started(&observed, &worker.account);
        }
        // A cannot receive this queued fetch while its store call is blocked.
        assert!(workers.fetch(&key("acct_a", "queued")));
        let joining = std::thread::spawn(move || {
            let joined = workers.shutdown_until(Instant::now() + TEST_WAIT);
            (
                joined,
                workers
                    .accounts
                    .iter()
                    .all(|worker| worker.thread.is_none()),
            )
        });
        let deadline = Instant::now() + TEST_WAIT;
        loop {
            let event = observed
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("B cancels before A is released");
            assert!(
                !matches!(event, Event::Fetch(_)),
                "no queued work starts on shutdown"
            );
            if event == Event::FutureDropped(account("acct_b")) {
                break;
            }
        }
        release_a.send(Ok(())).expect("finish store call");
        assert_eq!(joining.join().expect("join shutdown"), (true, true));
        assert!(
            observed
                .try_iter()
                .all(|event| !matches!(event, Event::Fetch(_)))
        );
    }

    #[test]
    fn shutdown_grace_and_fetch_admission_are_bounded() {
        let (events, observed) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut workers = Workers::start(vec![(
            account("acct_a"),
            Controlled::remote("acct_a", Gate::Store(gate), events),
        )])
        .expect("worker");
        assert!(workers.accounts[0].sync_at(Instant::now(), SystemTime::now()));
        wait_started(&observed, &account("acct_a"));
        for index in 0..MAX_FETCHES {
            assert!(workers.fetch(&key("acct_a", &format!("m{index}"))));
        }
        assert!(!workers.fetch(&key("acct_a", "overflow")));
        assert_eq!(workers.accounts[0].fetching.len(), MAX_FETCHES);
        assert!(
            !workers.shutdown_until(Instant::now()),
            "expired budget returns without waiting for the blocked store"
        );
        release.send(Ok(())).expect("finish store call");
        assert!(workers.shutdown_until(Instant::now() + TEST_WAIT));
        assert!(
            observed
                .try_iter()
                .all(|event| !matches!(event, Event::Fetch(_)))
        );
    }

    #[test]
    fn duplicate_and_sixth_workers_are_rejected() {
        for names in [
            vec!["acct_a", "acct_a"],
            vec!["acct_a", "acct_b", "acct_c", "acct_d", "acct_e", "acct_f"],
        ] {
            let (events, observed) = mpsc::channel();
            let remotes = names
                .iter()
                .map(|name| {
                    (
                        account(name),
                        Controlled::remote(name, Gate::Ready(Ok(())), events.clone()),
                    )
                })
                .collect();
            assert!(Workers::start(remotes).is_err());
            assert!(
                observed
                    .try_iter()
                    .all(|event| matches!(event, Event::OwnerDropped(_)))
            );
        }
    }

    #[test]
    fn shutdown_retains_the_existing_detached_dns_lookup_contract() {
        struct Lookup {
            gate: Mutex<Option<mpsc::Receiver<()>>>,
            started: Sender<()>,
            finished: Sender<()>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl Drop for Lookup {
            fn drop(&mut self) {
                self.dropped
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        impl Remote for Lookup {
            fn fetch<'a>(&'a self, _: &'a AccountId, _: &'a MessageId) -> Pending<'a, Vec<u8>> {
                Box::pin(std::future::pending())
            }
            fn sync<'a>(&'a self, _: &'a AccountId) -> Pending<'a, ()> {
                let gate = self
                    .gate
                    .lock()
                    .expect("lookup gate")
                    .take()
                    .expect("one lookup");
                let started = self.started.clone();
                let finished = self.finished.clone();
                Box::pin(async move {
                    let lookup = tokio::task::spawn_blocking(move || {
                        let _ = started.send(());
                        gate.recv_timeout(TEST_WAIT).expect("lookup release");
                        let _ = finished.send(());
                    });
                    let _ = lookup.await;
                    Ok(())
                })
            }
        }
        let (release, gate) = mpsc::channel();
        let (started, start) = mpsc::channel();
        let (finished, finish) = mpsc::channel();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut workers = Workers::start(vec![(
            account("acct_a"),
            Box::new(Lookup {
                gate: Mutex::new(Some(gate)),
                started,
                finished,
                dropped: Arc::clone(&dropped),
            }),
        )])
        .expect("worker");
        assert!(workers.accounts[0].sync_at(Instant::now(), SystemTime::now()));
        start
            .recv_timeout(TEST_WAIT)
            .expect("actual lookup thread started");
        assert!(workers.shutdown_until(Instant::now() + TEST_WAIT));
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "store/remote owner is gone even while the store-free lookup remains"
        );
        release.send(()).expect("release lookup");
        finish
            .recv_timeout(TEST_WAIT)
            .expect("lookup cleans up after release");
    }

    fn assert_drop_retains_native_owner_and_lock(single_worker: bool) {
        use tersa_sync_runtime::InstallationLock;
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!(
            "tersa-join-after-grace-{}-{single_worker}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let directory = Directory(root);
        let lock = InstallationLock::acquire(&directory.0).expect("installation lock");
        let (events, observed) = mpsc::channel();
        let (release_native, native_gate) = mpsc::channel();
        let (_release_network, network_gate) = tokio::sync::oneshot::channel();
        let mut remotes = vec![(
            account("acct_a"),
            Controlled::remote("acct_a", Gate::Store(native_gate), events.clone()),
        )];
        if !single_worker {
            remotes.push((
                account("acct_b"),
                Controlled::remote("acct_b", Gate::Network(network_gate), events),
            ));
        }
        let mut workers = Workers::start(remotes).expect("workers");
        for worker in &mut workers.accounts {
            assert!(worker.sync_at(Instant::now(), SystemTime::now()));
            wait_started(&observed, &worker.account);
        }
        assert!(workers.fetch(&key("acct_a", "queued")));
        let (joining, join_entered) = mpsc::channel();
        let (finished, finish) = mpsc::channel();
        let finalizer = std::thread::spawn(move || {
            // Same owner ordering as commands::tui: worker finalization returns
            // before the surrounding installation lock is allowed to drop.
            let held_lock = lock;
            DROP_DEADLINE.with(|deadline| deadline.set(Some(Instant::now())));
            JOIN_OBSERVER.with(|observer| *observer.borrow_mut() = Some(joining));
            if single_worker {
                // Standalone Worker::drop must obey the same no-detach policy.
                drop(workers.accounts.pop().expect("single worker"));
            }
            drop(workers); // Actual production Drop, not shutdown_until alone.
            drop(held_lock);
            finished.send(()).expect("finalization returns");
        });
        assert_eq!(
            join_entered
                .recv_timeout(TEST_WAIT)
                .expect("normal join after grace"),
            account("acct_a")
        );
        assert!(
            InstallationLock::acquire(&directory.0).is_err(),
            "lock stays held while the native owner is active"
        );
        assert!(
            matches!(finish.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "Drop cannot return before native owner cleanup"
        );
        let mut before_release = Vec::new();
        if !single_worker {
            let deadline = Instant::now() + TEST_WAIT;
            loop {
                let event = observed
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .expect("peer cancelled before native join finishes");
                let peer_cancelled = event == Event::FutureDropped(account("acct_b"));
                before_release.push(event);
                if peer_cancelled {
                    break;
                }
            }
        }
        before_release.extend(observed.try_iter());
        assert!(!before_release.contains(&Event::OwnerDropped(account("acct_a"))));
        assert!(!before_release.contains(&Event::FutureDropped(account("acct_a"))));
        release_native.send(Ok(())).expect("finish native call");
        finish
            .recv_timeout(TEST_WAIT)
            .expect("Drop joins and returns normally");
        finalizer.join().expect("join finalizer");
        let after_release: Vec<_> = observed.try_iter().collect();
        assert!(after_release.contains(&Event::FutureDropped(account("acct_a"))));
        assert!(after_release.contains(&Event::OwnerDropped(account("acct_a"))));
        assert!(
            before_release
                .iter()
                .chain(&after_release)
                .all(|event| !matches!(event, Event::Fetch(_))),
            "queued work never starts after stop"
        );
        let reopened =
            InstallationLock::acquire(&directory.0).expect("lock releases after owner join");
        drop(reopened);
    }

    #[test]
    fn actual_group_drop_joins_native_owners_after_expired_grace() {
        assert_drop_retains_native_owner_and_lock(false);
    }

    #[test]
    fn actual_single_worker_drop_keeps_owner_and_lock_until_join() {
        assert_drop_retains_native_owner_and_lock(true);
    }

    #[test]
    fn view_change_cancels_a_pending_fetch_before_a_late_release() {
        let (log, entries) = mpsc::channel();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut workers = Workers::start(vec![(
            account("acct_a"),
            Box::new(Gated {
                log,
                gate: Arc::clone(&gate),
            }),
        )])
        .expect("worker");
        let wanted = key("acct_a", "slow");
        assert!(workers.fetch(&wanted));
        assert_eq!(
            entries.recv_timeout(TEST_WAIT).expect("fetch starts"),
            "start slow"
        );
        workers.change_view(1);
        assert!(
            matches!(workers.accounts[0].done.recv_timeout(TEST_WAIT), Ok(Done::Skipped(key, 0)) if key == wanted)
        );
        assert!(workers.accounts[0].finish_fetch(&wanted, 0));
        gate.add_permits(1);
        assert!(
            matches!(entries.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "dropped old-view future cannot complete on late release"
        );
    }
}
