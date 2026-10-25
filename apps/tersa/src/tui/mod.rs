// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The full-screen interface (ADR 0031, T2).
//!
//! State and key handling live in [`app`] and drawing in [`view`]; this module
//! only owns the terminal and the event loop, so the rest is testable with
//! ratatui's test backend.

mod app;
mod view;
mod wrap;

use std::collections::HashSet;
use std::io::IsTerminal;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use tersa_application::mailbox::MessageId;
use tersa_presentation::terminal::SafeText;

pub use app::Row;
use app::{App, Request, SyncState};

/// Where the interface reads cached mail from.
pub trait MailSource {
    /// The cached rows, newest first.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn rows(&self) -> Result<Vec<Row>, ()>;

    /// The cached raw message `id`; `Ok(None)` when only the envelope is
    /// cached.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn message(&self, id: &MessageId) -> Result<Option<Vec<u8>>, ()>;
}

/// Work that finishes later, on the network thread.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// Talks to Gmail on the network thread, so the interface stays responsive
/// while the network is slow. Downloads and syncs may run at the same time.
pub trait Remote: Send + 'static {
    /// Downloads, caches, and returns the raw message `id`; fails with a
    /// short reason for the reader.
    fn fetch<'a>(&'a self, id: &'a MessageId) -> Pending<'a, Vec<u8>>;

    /// Syncs recent mail into the cache; fails with a short reason for the
    /// reader.
    fn sync(&self) -> Pending<'_, ()>;
}

/// How often the loop checks for finished work while idle.
const TICK: Duration = Duration::from_millis(100);

/// How often the account syncs on its own.
const SYNC_EVERY: Duration = Duration::from_secs(5 * 60);

/// How often an idle screen is redrawn anyway, so relative dates stay true.
const REDRAW_EVERY: Duration = Duration::from_secs(30);

/// Set by the panic hook. ratatui's hook restores the terminal on a panic in
/// any thread, so the interface must not keep drawing after one.
static PANICKED: AtomicBool = AtomicBool::new(false);

/// Checks that standard input and output are a terminal. Callers run it
/// before unlocking anything, so `tersa > out.txt` fails without asking for a
/// passphrase.
///
/// # Errors
///
/// Returns a message when either is not a terminal.
pub fn require_terminal() -> Result<(), String> {
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        Ok(())
    } else {
        Err("the interface needs a terminal; `tersa inbox` prints plain output".to_owned())
    }
}

/// Runs the interface until the user quits.
///
/// # Errors
///
/// Returns a message when standard input or output is not a terminal, the
/// cache cannot be read, or the terminal fails.
pub fn run(
    account: SafeText,
    source: &dyn MailSource,
    remote: Option<Box<dyn Remote>>,
) -> Result<(), String> {
    require_terminal()?;
    let rows = source
        .rows()
        .map_err(|()| "could not read the local mailbox".to_owned())?;
    let mut app = App::new(account, rows);
    let worker = remote.map(Worker::start);
    // Installs a panic hook that restores the terminal before reporting.
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            // Raw mode may be on even though the alternate screen failed.
            ratatui::restore();
            return Err(terminal_error(error));
        }
    };
    let restore_terminal = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICKED.store(true, Ordering::SeqCst);
        restore_terminal(info);
    }));
    let result = event_loop(&mut terminal, &mut app, source, worker);
    ratatui::restore();
    result
}

/// One piece of network work.
enum Job {
    Fetch(MessageId),
    Sync,
}

/// A finished piece of network work.
enum Done {
    Fetched(MessageId, Result<Vec<u8>, String>),
    /// The message was no longer open when its turn came, so it was not
    /// downloaded.
    Skipped(MessageId),
    Synced(Result<(), String>),
}

/// The network thread's channels. Each job runs as its own task on one
/// single-threaded runtime, so a download never waits for a sync. Dropping
/// this ends the thread and cancels unfinished jobs; the process does not
/// wait for it.
struct Worker {
    jobs: tokio::sync::mpsc::UnboundedSender<Job>,
    done: Receiver<Done>,
    fetching: HashSet<MessageId>,
    /// The open message. Opening another one stops the download of the
    /// previous one, queued or running, so at most one download runs and
    /// one large message is held in memory at a time.
    open: tokio::sync::watch::Sender<Option<MessageId>>,
    syncing: bool,
    /// When the last sync started, on both clocks: the monotonic clock stops
    /// while the machine sleeps, the wall clock does not.
    last_sync: Option<(Instant, SystemTime)>,
}

/// Downloads `id` unless another message is opened first: then it stops,
/// whether it is still queued or already running. Going back to the list
/// does not stop it, so the message is cached when the reader returns.
async fn download(
    remote: &dyn Remote,
    mut open: tokio::sync::watch::Receiver<Option<MessageId>>,
    id: MessageId,
) -> Done {
    let other_opened = async {
        loop {
            if open
                .borrow_and_update()
                .as_ref()
                .is_some_and(|open| open != &id)
            {
                break;
            }
            // A dropped sender means the interface is gone; stop too.
            if open.changed().await.is_err() {
                break;
            }
        }
    };
    // Checked first, so a download queued for a message the reader already
    // left never starts.
    match first(other_opened, remote.fetch(&id)).await {
        First::Left(()) => Done::Skipped(id),
        First::Right(result) => Done::Fetched(id, result),
    }
}

/// Which of two futures finished first.
enum First<A, B> {
    Left(A),
    Right(B),
}

/// Runs both futures and returns the first output, dropping the other. On a
/// tie the left one wins.
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

impl Worker {
    fn start(remote: Box<dyn Remote>) -> Self {
        let (jobs, mut incoming) = tokio::sync::mpsc::unbounded_channel::<Job>();
        let (outgoing, done) = mpsc::channel();
        let (open, wanted) = tokio::sync::watch::channel(None::<MessageId>);
        std::thread::spawn(move || {
            let Ok(executor) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                // Ending the thread disconnects the channels; the interface
                // then fails the queued work.
                return;
            };
            let remote: Rc<dyn Remote> = Rc::from(remote);
            tokio::task::LocalSet::new().block_on(&executor, async move {
                while let Some(job) = incoming.recv().await {
                    let remote = Rc::clone(&remote);
                    let outgoing = outgoing.clone();
                    let wanted = wanted.clone();
                    tokio::task::spawn_local(async move {
                        let finished = match job {
                            Job::Fetch(id) => download(&*remote, wanted, id).await,
                            Job::Sync => Done::Synced(remote.sync().await),
                        };
                        let _ = outgoing.send(finished);
                    });
                }
            });
        });
        Self {
            jobs,
            done,
            fetching: HashSet::new(),
            open,
            syncing: false,
            last_sync: None,
        }
    }

    /// Records which message is open, so downloads of others stop.
    fn set_open(&self, id: Option<&MessageId>) {
        self.open.send_if_modified(|open| {
            let changed = open.as_ref() != id;
            if changed {
                *open = id.cloned();
            }
            changed
        });
    }

    /// Asks for message `id`; returns false when the thread is gone.
    fn fetch(&mut self, id: &MessageId) -> bool {
        if self.fetching.contains(id) {
            return true;
        }
        let sent = self.jobs.send(Job::Fetch(id.clone())).is_ok();
        if sent {
            self.fetching.insert(id.clone());
        }
        sent
    }

    /// Asks for a sync unless one is running; returns false when the thread
    /// is gone.
    fn sync(&mut self) -> bool {
        self.last_sync = Some((Instant::now(), SystemTime::now()));
        if self.syncing {
            return true;
        }
        self.syncing = self.jobs.send(Job::Sync).is_ok();
        self.syncing
    }

    fn sync_due(&self) -> bool {
        !self.syncing
            && self.last_sync.is_none_or(|(monotonic, wall)| {
                monotonic.elapsed() >= SYNC_EVERY
                    || wall.elapsed().is_ok_and(|elapsed| elapsed >= SYNC_EVERY)
            })
    }
}

const WORKER_GONE: &str = "the network worker stopped";

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    source: &dyn MailSource,
    mut worker: Option<Worker>,
) -> Result<(), String> {
    let mut dirty = true;
    let mut drawn = Instant::now();
    loop {
        if PANICKED.load(Ordering::SeqCst) {
            return Err("tersa stopped after an internal error".to_owned());
        }
        let now = now_millis();
        if let Some(worker) = &mut worker {
            dirty |= finish_work(worker, app, source, now);
            if worker.sync_due() {
                start_sync(worker, app, now);
                dirty = true;
            }
            worker.set_open(app.open_id());
        }
        if dirty || drawn.elapsed() >= REDRAW_EVERY {
            if std::mem::take(&mut app.repaint) {
                // Repaint every cell when the screen changes, so any drift
                // between the terminal and ratatui's model cannot linger.
                terminal.clear().map_err(terminal_error)?;
            }
            terminal
                .draw(|frame| view::draw(frame, app, now))
                .map_err(terminal_error)?;
            dirty = false;
            drawn = Instant::now();
        }
        if app.quit {
            return Ok(());
        }
        if !event::poll(TICK).map_err(terminal_error)? {
            continue;
        }
        let key = match event::read().map_err(terminal_error)? {
            Event::Key(key) if key.kind == KeyEventKind::Press => key,
            Event::Resize(..) => {
                dirty = true;
                continue;
            }
            _ => continue,
        };
        dirty = true;
        match app.key(key) {
            Some(Request::OpenMessage(id)) => {
                let raw = source.message(&id);
                let missing = matches!(raw, Ok(None));
                app.show_message(id.clone(), raw);
                if let Some(worker) = &mut worker
                    && missing
                {
                    worker.set_open(Some(&id));
                    if worker.fetch(&id) {
                        app.downloading(&id);
                    } else {
                        app.downloaded(id, Err(WORKER_GONE.to_owned()));
                    }
                }
            }
            Some(Request::Reformat(id, preference)) => match source.message(&id) {
                Ok(Some(raw)) => app.reformat(&id, &raw, preference),
                _ => app.status = Some("The message could not be read again.".to_owned()),
            },
            Some(Request::Sync) => match &mut worker {
                Some(worker) => start_sync(worker, app, now),
                None => {
                    app.status = Some(
                        "Syncing needs the Google OAuth client; see `tersa doctor`.".to_owned(),
                    );
                }
            },
            None => {}
        }
    }
}

fn start_sync(worker: &mut Worker, app: &mut App, now: i64) {
    if worker.sync() {
        app.sync = SyncState::Running;
    } else {
        app.synced(Err(WORKER_GONE.to_owned()), now);
    }
}

/// Applies finished downloads and syncs; returns whether anything changed.
fn finish_work(worker: &mut Worker, app: &mut App, source: &dyn MailSource, now: i64) -> bool {
    let mut changed = false;
    loop {
        let done = match worker.done.try_recv() {
            Ok(done) => done,
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                // The network thread is gone: fail what it will never finish.
                changed |= fail_pending(worker, app, now);
                break;
            }
        };
        changed = true;
        match done {
            Done::Fetched(id, result) => {
                worker.fetching.remove(&id);
                app.downloaded(id, result);
            }
            Done::Skipped(id) => {
                worker.fetching.remove(&id);
                // Reopened while its skipped job was finishing: ask again.
                if app.open_id() == Some(&id) && !worker.fetch(&id) {
                    app.downloaded(id, Err(WORKER_GONE.to_owned()));
                }
            }
            Done::Synced(result) => {
                worker.syncing = false;
                let reloaded = result.and_then(|()| {
                    source
                        .rows()
                        .map_err(|()| "could not read the local mailbox".to_owned())
                });
                match reloaded {
                    Ok(rows) => {
                        app.reload(rows);
                        app.synced(Ok(()), now);
                    }
                    Err(error) => app.synced(Err(error), now),
                }
            }
        }
    }
    changed
}

/// Fails the sync and downloads a stopped worker still owed; returns whether
/// there were any.
fn fail_pending(worker: &mut Worker, app: &mut App, now: i64) -> bool {
    let mut changed = false;
    if std::mem::take(&mut worker.syncing) {
        app.synced(Err(WORKER_GONE.to_owned()), now);
        changed = true;
    }
    for id in std::mem::take(&mut worker.fetching) {
        app.downloaded(id, Err(WORKER_GONE.to_owned()));
        changed = true;
    }
    changed
}

#[allow(clippy::needless_pass_by_value, reason = "used as a map_err adapter")]
fn terminal_error(error: std::io::Error) -> String {
    format!("the terminal failed: {error}")
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::mpsc::{self, Sender};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    use tersa_application::mailbox::MessageId;
    use tersa_presentation::terminal::SafeText;

    use super::app::{Body, Screen};
    use super::{
        App, Done, MailSource, Pending, Remote, Row, SYNC_EVERY, SyncState, WORKER_GONE, Worker,
        finish_work,
    };

    /// Records the order work finishes in; syncs wait for the test.
    struct Recorder {
        log: Sender<String>,
        release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl Remote for Recorder {
        fn fetch<'a>(&'a self, id: &'a MessageId) -> Pending<'a, Vec<u8>> {
            Box::pin(async move {
                let _ = self.log.send(format!("fetch {}", id.as_str()));
                Ok(Vec::new())
            })
        }

        fn sync(&self) -> Pending<'_, ()> {
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

    #[test]
    fn downloads_finish_while_a_sync_is_still_running() {
        let (log, entries) = mpsc::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let mut worker = Worker::start(Box::new(Recorder {
            log,
            release: Mutex::new(Some(released)),
        }));
        let next = || {
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("work finishes")
        };
        assert!(worker.sync());
        assert!(worker.sync(), "a second request joins the running sync");
        worker.set_open(Some(&id("a")));
        assert!(worker.fetch(&id("a")));
        assert!(worker.fetch(&id("a")), "a repeat is merged");
        assert_eq!(next(), "fetch a");
        worker.set_open(Some(&id("b")));
        assert!(worker.fetch(&id("b")));
        assert_eq!(next(), "fetch b");
        release.send(()).expect("release");
        assert_eq!(next(), "sync");
        let mut fetched = 0;
        let mut synced = 0;
        for _ in 0..3 {
            match worker.done.recv_timeout(Duration::from_secs(5)) {
                Ok(Done::Fetched(_, Ok(_))) => fetched += 1,
                Ok(Done::Synced(Err(error))) if error == "offline" => synced += 1,
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
        assert!(!worker.sync_due(), "a sync was just asked for");
        worker.last_sync = worker
            .last_sync
            .map(|(monotonic, wall)| (monotonic - SYNC_EVERY, wall));
        assert!(worker.sync_due(), "five minutes later another one is due");
    }

    #[test]
    fn downloads_for_messages_no_longer_open_are_skipped() {
        let (log, entries) = mpsc::channel();
        let mut worker = Worker::start(Box::new(Recorder {
            log,
            release: Mutex::new(None),
        }));
        worker.set_open(Some(&id("now")));
        for stale in ["s1", "s2", "s3", "s4", "s5", "s6"] {
            assert!(worker.fetch(&id(stale)));
        }
        assert!(worker.fetch(&id("now")));
        assert_eq!(
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("work finishes"),
            "fetch now"
        );
        let mut skipped = 0;
        for _ in 0..7 {
            match worker.done.recv_timeout(Duration::from_secs(5)) {
                Ok(Done::Skipped(_)) => skipped += 1,
                Ok(Done::Fetched(id, Ok(_))) => assert_eq!(id.as_str(), "now"),
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
        fn fetch<'a>(&'a self, id: &'a MessageId) -> Pending<'a, Vec<u8>> {
            Box::pin(async move {
                let _ = self.log.send(format!("start {}", id.as_str()));
                if id.as_str().starts_with("slow") {
                    let _ = self.gate.acquire().await;
                }
                let _ = self.log.send(format!("fetch {}", id.as_str()));
                Ok(Vec::new())
            })
        }

        fn sync(&self) -> Pending<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn opening_another_message_stops_a_running_download() {
        let (log, entries) = mpsc::channel();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut worker = Worker::start(Box::new(Gated {
            log,
            gate: Arc::clone(&gate),
        }));
        let next = || {
            entries
                .recv_timeout(Duration::from_secs(5))
                .expect("work starts")
        };
        worker.set_open(Some(&id("slow")));
        assert!(worker.fetch(&id("slow")));
        assert_eq!(next(), "start slow");
        worker.set_open(Some(&id("now")));
        assert!(worker.fetch(&id("now")));
        assert_eq!(next(), "start now");
        assert_eq!(next(), "fetch now", "it did not wait for the slow one");
        let mut results = Vec::new();
        for _ in 0..2 {
            match worker.done.recv_timeout(Duration::from_secs(5)) {
                Ok(Done::Skipped(id)) => results.push(format!("skipped {}", id.as_str())),
                Ok(Done::Fetched(id, Ok(_))) => results.push(format!("fetched {}", id.as_str())),
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
        let mut worker = Worker::start(Box::new(Gated {
            log,
            gate: Arc::clone(&gate),
        }));
        worker.set_open(Some(&id("slow")));
        assert!(worker.fetch(&id("slow")));
        assert_eq!(
            entries.recv_timeout(Duration::from_secs(5)).expect("start"),
            "start slow"
        );
        worker.set_open(None);
        gate.add_permits(1);
        assert!(matches!(
            worker.done.recv_timeout(Duration::from_secs(5)),
            Ok(Done::Fetched(id, Ok(_))) if id.as_str() == "slow"
        ));
    }

    struct Empty;

    impl MailSource for Empty {
        fn rows(&self) -> Result<Vec<Row>, ()> {
            Ok(Vec::new())
        }

        fn message(&self, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }
    }

    #[test]
    fn a_stopped_worker_fails_the_work_it_owed() {
        let (jobs, _) = tokio::sync::mpsc::unbounded_channel();
        let (_, done) = mpsc::channel();
        let mut worker = Worker {
            jobs,
            done,
            fetching: HashSet::from([id("a")]),
            open: tokio::sync::watch::channel(Some(id("a"))).0,
            syncing: true,
            last_sync: Some((Instant::now(), SystemTime::now())),
        };
        let mut app = App::new(SafeText::single_line("me@example.com"), Vec::new());
        app.show_message(id("a"), Ok(None));
        app.downloading(&id("a"));
        assert!(finish_work(&mut worker, &mut app, &Empty, 0));
        assert!(matches!(&app.sync, SyncState::Failed(error) if error == WORKER_GONE));
        assert!(
            matches!(&app.screen, Screen::Message(view)
                if matches!(&view.body, Body::DownloadFailed(error) if error == WORKER_GONE)),
            "the open message says why it will not arrive"
        );
        assert!(!worker.syncing && worker.fetching.is_empty());
        assert!(
            !finish_work(&mut worker, &mut app, &Empty, 0),
            "reported once"
        );
        assert!(!worker.sync(), "a new sync reports the stopped worker");
    }

    #[test]
    fn a_sync_is_due_after_a_sleep_the_monotonic_clock_missed() {
        let (log, _entries) = mpsc::channel();
        let mut worker = Worker::start(Box::new(Recorder {
            log,
            release: Mutex::new(None),
        }));
        let before_sleep = SystemTime::now() - SYNC_EVERY - Duration::from_secs(1);
        worker.last_sync = Some((Instant::now(), before_sleep));
        assert!(worker.sync_due());
        worker.last_sync = Some((Instant::now(), SystemTime::now()));
        assert!(!worker.sync_due());
    }
}
