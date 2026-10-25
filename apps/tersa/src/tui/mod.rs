// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The full-screen interface (ADR 0031, T2).
//!
//! State and key handling live in [`app`] and drawing in [`view`]; this module
//! only owns the terminal and the event loop, so the rest is testable with
//! ratatui's test backend.

mod app;
#[cfg(test)]
mod perf;
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
use tersa_application::mailbox::{MessageId, StoreLimit};
use tersa_presentation::terminal::SafeText;

pub use app::Row;
use app::{App, Request, SyncState};

/// Where the interface reads cached mail from.
pub trait MailSource {
    /// Up to `limit` cached rows after `after`, newest first, or from the
    /// newest when `after` is `None`.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn page(&self, after: Option<&Row>, limit: u16) -> Result<Vec<Row>, ()>;

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

/// Rows read before the first frame.
const FIRST_PAGE: u16 = 100;

/// Rows read per page afterwards, one page per pass while no key waits.
const PAGE: u16 = 500;

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
    let (rows, more) = read_page(source, None, FIRST_PAGE)
        .map_err(|()| "could not read the local mailbox".to_owned())?;
    let mut app = App::new(account, rows);
    app.more_rows = more;
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
        if app.more_rows {
            dirty |= load_page(app, source);
        }
        // While pages remain, only look for a key that is already waiting.
        let wait = if app.more_rows { Duration::ZERO } else { TICK };
        if !event::poll(wait).map_err(terminal_error)? {
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
                // Read again as many rows as were loaded, so the selection
                // and the list stay where they were; later pages follow.
                let loaded = u16::try_from(app.rows.len())
                    .unwrap_or(u16::MAX)
                    .clamp(FIRST_PAGE, StoreLimit::MAX);
                let reloaded = result.and_then(|()| {
                    read_page(source, None, loaded)
                        .map_err(|()| "could not read the local mailbox".to_owned())
                });
                match reloaded {
                    Ok((rows, more)) => {
                        app.reload(rows, more);
                        app.synced(Ok(()), now);
                    }
                    Err(error) => app.synced(Err(error), now),
                }
            }
        }
    }
    changed
}

/// Reads the page after the last loaded row; returns whether it changed the
/// list.
fn load_page(app: &mut App, source: &dyn MailSource) -> bool {
    match read_page(source, app.rows.last(), PAGE) {
        Ok((rows, more)) => {
            app.more_rows = more;
            app.append(rows);
        }
        // The top bar says so; a status line would vanish at the next key.
        Err(()) => app.older_rows_failed(),
    }
    true
}

/// Reads up to `limit` rows after `after`, and whether older rows follow. It
/// asks for one row more than it keeps, so a page that ends the cache is not
/// taken for an unfinished one.
fn read_page(
    source: &dyn MailSource,
    after: Option<&Row>,
    limit: u16,
) -> Result<(Vec<Row>, bool), ()> {
    // A read is capped; at the cap a full page counts as unfinished.
    let probe = limit.saturating_add(1).min(StoreLimit::MAX);
    let mut rows = source.page(after, probe)?;
    let kept = usize::from(limit);
    let more = rows.len() > kept || (probe == limit && rows.len() == kept);
    rows.truncate(kept);
    Ok((rows, more))
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
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::{
        App, Done, FIRST_PAGE, MailSource, Pending, Remote, Row, SYNC_EVERY, SyncState,
        WORKER_GONE, Worker, finish_work, load_page, read_page,
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
            .map(|(monotonic, wall)| (monotonic, wall - SYNC_EVERY));
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
        fn page(&self, _after: Option<&Row>, _limit: u16) -> Result<Vec<Row>, ()> {
            Ok(Vec::new())
        }

        fn message(&self, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }
    }

    /// A cache of `total` rows, newest first, that counts its reads.
    struct Pages {
        rows: Vec<Row>,
        reads: std::cell::Cell<usize>,
    }

    impl Pages {
        fn new(total: usize) -> Self {
            let rows = (0..total)
                .map(|index| {
                    let envelope = tersa_application::mailbox::MessageEnvelope::new(
                        id(&format!("m{index:05}")),
                        tersa_application::mailbox::ThreadId::new("t").expect("thread"),
                        tersa_application::mailbox::HeaderText::new("Ann <ann@example.com>")
                            .expect("from"),
                        tersa_application::mailbox::HeaderText::new(if index % 2 == 0 {
                            "even"
                        } else {
                            "odd"
                        })
                        .expect("subject"),
                        tersa_application::mailbox::HeaderText::new("preview").expect("preview"),
                        tersa_application::mailbox::UnixTimestampMillis::new(
                            1_000_000 - i64::try_from(index).expect("small"),
                        )
                        .expect("time"),
                        false,
                    );
                    Row::from_envelope(&envelope)
                })
                .collect();
            Self {
                rows,
                reads: std::cell::Cell::new(0),
            }
        }
    }

    impl MailSource for Pages {
        fn page(&self, after: Option<&Row>, limit: u16) -> Result<Vec<Row>, ()> {
            self.reads.set(self.reads.get() + 1);
            let start = after.map_or(0, |after| {
                self.rows
                    .iter()
                    .position(|row| row.id == after.id)
                    .map_or(self.rows.len(), |position| position + 1)
            });
            Ok(self.rows[start..]
                .iter()
                .take(usize::from(limit))
                .cloned()
                .collect())
        }

        fn message(&self, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }
    }

    #[test]
    fn older_rows_load_a_page_at_a_time_and_join_the_search() {
        let source = Pages::new(1_234);
        let first = source.page(None, FIRST_PAGE).expect("page");
        let mut app = App::new(SafeText::single_line("acct"), first);
        app.more_rows = true;
        // Searching before the older rows arrive still covers them later.
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "odd".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(
            app.status.as_deref(),
            Some("50+ matches; esc shows every message")
        );
        while app.more_rows {
            assert!(load_page(&mut app, &source));
        }
        assert_eq!(source.reads.get(), 1 + 3, "100, then 500, 500 and 134");
        assert_eq!(app.rows.len(), 1_234);
        let ids: Vec<&str> = app.rows.iter().map(|row| row.id.as_str()).collect();
        let expected: Vec<String> = (0..1_234).map(|index| format!("m{index:05}")).collect();
        assert_eq!(ids, expected, "every row once, in order");
        assert_eq!(app.shown.len(), 617, "the search covers every page");
        assert_eq!(
            app.status.as_deref(),
            Some("617 matches; esc shows every message"),
            "the count follows the pages"
        );
    }

    #[test]
    fn a_page_that_ends_the_cache_is_not_taken_for_an_unfinished_one() {
        let source = Pages::new(100);
        let (rows, more) = read_page(&source, None, FIRST_PAGE).expect("page");
        assert_eq!(rows.len(), 100);
        assert!(!more, "exactly one first page");

        let source = Pages::new(600);
        let (rows, more) = read_page(&source, None, FIRST_PAGE).expect("page");
        let mut app = App::new(SafeText::single_line("acct"), rows);
        app.more_rows = more;
        while app.more_rows {
            load_page(&mut app, &source);
        }
        assert_eq!(app.rows.len(), 600);
        assert_eq!(source.reads.get(), 2, "no empty read after a full page");
    }

    #[test]
    fn a_failed_older_page_outlasts_the_next_key() {
        struct OlderFail(Pages);
        impl MailSource for OlderFail {
            fn page(&self, after: Option<&Row>, limit: u16) -> Result<Vec<Row>, ()> {
                if after.is_some() {
                    return Err(());
                }
                self.0.page(after, limit)
            }

            fn message(&self, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
                Ok(None)
            }
        }
        let source = OlderFail(Pages::new(1_234));
        let (rows, more) = read_page(&source, None, FIRST_PAGE).expect("page");
        let mut app = App::new(SafeText::single_line("acct"), rows);
        app.more_rows = more;
        load_page(&mut app, &source);
        app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert!(!app.more_rows, "loading stops");
        assert!(app.older_unreadable, "a key press does not clear it");
    }

    fn finished_sync(app: &mut App, source: &dyn MailSource) {
        let (jobs, _) = tokio::sync::mpsc::unbounded_channel();
        let (done_sender, done) = mpsc::channel();
        let mut worker = Worker {
            jobs,
            done,
            fetching: HashSet::new(),
            open: tokio::sync::watch::channel(None).0,
            syncing: true,
            last_sync: Some((Instant::now(), SystemTime::now())),
        };
        done_sender.send(Done::Synced(Ok(()))).expect("send");
        assert!(finish_work(&mut worker, app, source, 0));
    }

    fn selected_id(app: &App) -> Option<&str> {
        app.shown_row(app.selected).map(|row| row.id.as_str())
    }

    #[test]
    fn a_sync_reloads_as_many_rows_as_were_loaded() {
        let source = Pages::new(1_234);
        let mut app = App::new(
            SafeText::single_line("acct"),
            source.page(None, 600).expect("page"),
        );
        app.more_rows = true;
        for _ in 0..300 {
            app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        finished_sync(&mut app, &source);
        assert_eq!(app.rows.len(), 600);
        assert!(app.more_rows);
        assert_eq!(selected_id(&app), Some("m00300"));
    }

    #[test]
    fn a_selection_pushed_past_the_reload_comes_back_with_its_page() {
        let mut source = Pages::new(1_234);
        let mut app = App::new(
            SafeText::single_line("acct"),
            source.page(None, 600).expect("page"),
        );
        app.more_rows = true;
        for _ in 0..599 {
            app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        assert_eq!(selected_id(&app), Some("m00599"));
        // The sync stored one newer message, so 600 rows end one row earlier.
        source
            .rows
            .insert(0, Row::sample("new", "Zed", "Fresh", true));
        finished_sync(&mut app, &source);
        assert_eq!(app.rows.len(), 600);
        load_page(&mut app, &source);
        assert_eq!(selected_id(&app), Some("m00599"));
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
