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
mod worker;
mod wrap;

use std::io::IsTerminal;
use std::os::fd::AsFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use tersa_application::mailbox::{AccountId, MessageId};
use tersa_application::unified_mailbox::{
    MAX_PAGE_SIZE, UnavailableAccount, UnifiedMailboxContinuation, UnifiedMailboxDocument,
};
use tersa_presentation::terminal::SafeText;

use app::{App, Request};
pub use app::{MessageKey, Row, ViewScope, account_tag_label};
use worker::{Done, Worker, Workers};

/// Where the interface reads cached mail from.
pub trait MailSource {
    /// One application query page, using its opaque continuation unchanged.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` for an invalid query contract or a locked result.
    fn page(
        &self,
        scope: &ViewScope,
        continuation: Option<&UnifiedMailboxContinuation>,
        limit: u16,
    ) -> Result<MailPage, ()>;

    /// The cached raw message `id` of `account`; `Ok(None)` when only the
    /// envelope is cached.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn message(&self, account: &AccountId, id: &MessageId) -> Result<Option<Vec<u8>>, ()>;

    /// Every account the source reads, in registry order, each with its
    /// stored Gmail address or its id. Read again after every finished sync.
    fn account_labels(&self) -> Vec<(AccountId, SafeText)>;
}

/// Sanitized rows with the application's account-scoped pagination state.
#[derive(Default)]
pub struct MailPage {
    pub rows: Vec<Row>,
    pub continuation: Option<UnifiedMailboxContinuation>,
    pub unavailable_accounts: Vec<UnavailableAccount>,
}

impl From<UnifiedMailboxDocument> for MailPage {
    fn from(document: UnifiedMailboxDocument) -> Self {
        Self {
            rows: document
                .rows
                .into_iter()
                .map(|row| Row::from_envelope(&row.envelope, &row.account_id))
                .collect(),
            continuation: document.continuation,
            unavailable_accounts: document.unavailable_accounts,
        }
    }
}

/// Initializes display state without terminal or network I/O.
pub(crate) fn initial_app(source: &dyn MailSource) -> Result<App, ()> {
    let page = read_page(source, &ViewScope::All, None, FIRST_PAGE)?;
    let mut app = App::new(source.account_labels(), Vec::new());
    set_progress(&mut app, &page);
    app.status = unreadable_status(page.unavailable_accounts.len());
    app.append(page.rows);
    Ok(app)
}

fn set_progress(app: &mut App, page: &MailPage) {
    app.continuation.clone_from(&page.continuation);
    app.more_rows = page.continuation.is_some();
    if !page.unavailable_accounts.is_empty() {
        let available = |account: &AccountId| {
            !page
                .unavailable_accounts
                .iter()
                .any(|entry| &entry.account_id == account)
        };
        // A later failure must not leave that account's old metadata or body
        // visible, particularly after an identity fence rejects the store.
        if app.rows.iter().any(|row| !available(&row.account)) {
            let rows = app
                .rows
                .iter()
                .filter(|row| available(&row.account))
                .cloned()
                .collect();
            app.reload(rows, app.more_rows);
        }
        if app.open_key().is_some_and(|key| !available(&key.0)) {
            app.screen = app::Screen::Inbox;
            app.repaint = true;
        }
    }
    app.unavailable_accounts
        .clone_from(&page.unavailable_accounts);
}

/// Work that finishes later, on the network thread.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// Talks to Gmail on the network thread, so the interface stays responsive
/// while the network is slow. Downloads and syncs may run at the same time.
pub trait Remote: Send + 'static {
    /// Downloads, caches, and returns the raw message `id` of `account`;
    /// fails with a short reason for the reader.
    fn fetch<'a>(&'a self, account: &'a AccountId, id: &'a MessageId) -> Pending<'a, Vec<u8>>;

    /// Syncs only this account through its identity gate.
    fn sync<'a>(&'a self, account: &'a AccountId) -> Pending<'a, ()>;
}

/// How often the loop checks for finished work while idle.
const TICK: Duration = Duration::from_millis(100);

/// Rows read before the first frame.
const FIRST_PAGE: u16 = 100;

/// Rows read per page afterwards, one page per pass while no key waits.
const PAGE: u16 = MAX_PAGE_SIZE;

/// How often the account syncs on its own.
pub(super) const SYNC_EVERY: Duration = Duration::from_secs(5 * 60);

/// How often an idle screen is redrawn anyway, so relative dates stay true.
const REDRAW_EVERY: Duration = Duration::from_secs(30);

/// Set by the panic hook. ratatui's hook restores the terminal on a panic in
/// any thread, so the interface must not keep drawing after one.
static PANICKED: AtomicBool = AtomicBool::new(false);

/// Checks that standard input and output are a terminal. Callers run it
/// before unlocking anything, so `tersa > out.txt` fails without asking for a
/// passphrase. Standard input is checked the way crossterm checks it, so
/// crossterm reads the input [`wait_for_input`] watches.
///
/// # Errors
///
/// Returns a message when either is not a terminal.
pub fn require_terminal() -> Result<(), String> {
    if rustix::termios::isatty(std::io::stdin()) && std::io::stdout().is_terminal() {
        Ok(())
    } else {
        Err("the interface needs a terminal; `tersa inbox` prints plain output".to_owned())
    }
}

/// The status line for accounts whose store could not be opened; `None`
/// when every account opened. It says how many without naming any.
fn unreadable_status(unreadable: usize) -> Option<String> {
    (unreadable > 0).then(|| match unreadable {
        1 => "1 account could not be read; its mail is not shown".to_owned(),
        count => format!("{count} accounts could not be read; their mail is not shown"),
    })
}

/// Runs the interface until the user quits.
///
/// # Errors
///
/// Returns a message when standard input or output is not a terminal, the
/// cache cannot be read, or the terminal fails.
pub fn run(
    source: &dyn MailSource,
    remotes: Vec<(AccountId, Box<dyn Remote>)>,
) -> Result<(), String> {
    require_terminal()?;
    let mut app =
        initial_app(source).map_err(|()| "could not read the local mailbox".to_owned())?;
    let mut worker = Workers::start(remotes)?;
    // Installs a panic hook that restores the terminal before reporting.
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            // Raw mode may be on even though the alternate screen failed.
            silence_closed_stderr();
            ratatui::restore();
            return Err(terminal_error(error));
        }
    };
    let restore_terminal = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICKED.store(true, Ordering::SeqCst);
        restore_terminal(info);
    }));
    let result = event_loop(&mut terminal, &mut app, source, &mut worker);
    silence_closed_stderr();
    ratatui::restore();
    // Stops the network thread once the terminal is back to normal.
    drop(worker);
    result
}

const WORKER_GONE: &str = "the network worker stopped";
const FETCH_NOT_QUEUED: &str = "the download could not be queued";

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    source: &dyn MailSource,
    worker: &mut Workers,
) -> Result<(), String> {
    let mut dirty = true;
    let mut drawn = Instant::now();
    loop {
        if PANICKED.load(Ordering::SeqCst) {
            return Err("tersa stopped after an internal error".to_owned());
        }
        let now = now_millis();
        dirty |= finish_work(worker, app, source, now);
        if worker.accounts.iter().any(|worker| worker.dead) {
            return Err(WORKER_GONE.to_owned());
        }
        dirty |= start_sync(worker, app, now, true);
        worker.set_open(app.open_key());
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
        match wait_for_input(wait).map_err(terminal_error)? {
            Input::Waiting => {}
            Input::None => continue,
            // Nobody is left to read the screen: quit as `q` would.
            Input::Closed => return Ok(()),
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
            Some(Request::OpenMessage(key)) => {
                let raw = source.message(&key.0, &key.1);
                let missing = matches!(raw, Ok(None));
                app.show_message(key.clone(), raw);
                if missing && !worker.is_empty() {
                    worker.set_open(Some(&key));
                    if worker.fetch(&key) {
                        app.downloading(&key);
                    } else {
                        app.downloaded(key, Err(FETCH_NOT_QUEUED.to_owned()));
                    }
                }
            }
            Some(Request::Reformat(key, preference)) => match source.message(&key.0, &key.1) {
                Ok(Some(raw)) => app.reformat(&key, &raw, preference),
                _ => app.status = Some("The message could not be read again.".to_owned()),
            },
            Some(Request::ChangeScope(scope)) => {
                if change_view(app, source, worker, scope).is_err() {
                    app.status = Some("That account view is unavailable.".to_owned());
                }
            }
            Some(Request::Sync) => {
                if worker.is_empty() {
                    app.status = Some("Syncing needs a readable account and the Google OAuth client; see `tersa doctor`.".to_owned());
                } else {
                    start_sync(worker, app, now, false);
                }
            }
            None => {}
        }
    }
}

/// Discards all prior view state before querying the exact new source set.
fn change_view(
    app: &mut App,
    source: &dyn MailSource,
    workers: &mut Workers,
    scope: ViewScope,
) -> Result<bool, ()> {
    if !app.set_scope(scope)? {
        return Ok(false);
    }
    workers.change_view(app.view_epoch);
    if let Ok(page) = read_page(source, &app.scope, None, FIRST_PAGE) {
        set_progress(app, &page);
        app.append(page.rows);
    } else {
        app.rows_failed();
        app.status = Some("The selected mailbox view could not be read.".to_owned());
    }
    Ok(true)
}

/// Schedules each ready account independently, coalescing an active cycle.
fn start_sync(workers: &mut Workers, app: &mut App, now: i64, due_only: bool) -> bool {
    let monotonic = Instant::now();
    let wall = SystemTime::now();
    let mut changed = false;
    let mut eligible = false;
    for worker in &mut workers.accounts {
        if !due_only && !app.scope.contains(&worker.account) {
            continue;
        }
        eligible = true;
        if due_only && !worker.sync_due_at(monotonic, wall) {
            continue;
        }
        if worker.sync_at(monotonic, wall) {
            changed |= app.sync_started(&worker.account, worker.next_sync_millis());
        } else {
            changed |= fail_pending(worker, app, now);
        }
    }
    if !due_only && !eligible {
        app.status = Some("This account is unavailable for syncing.".to_owned());
        changed = true;
    }
    changed
}

/// Applies account-keyed completions and reloads the unified query once per
/// batch, starting fresh even after a failed sync may have stored metadata.
fn finish_work(workers: &mut Workers, app: &mut App, source: &dyn MailSource, now: i64) -> bool {
    let mut changed = false;
    let mut reload = false;
    for worker in &mut workers.accounts {
        loop {
            let done = match worker.done.try_recv() {
                Ok(done) => done,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    reload |= worker.syncing && app.scope.contains(&worker.account);
                    changed |= fail_pending(worker, app, now);
                    break;
                }
            };
            changed = true;
            match done {
                Done::Fetched(key, result, epoch) if key.0 == worker.account => {
                    if !worker.finish_fetch(&key, epoch) {
                        continue;
                    }
                    if epoch == app.view_epoch {
                        app.downloaded(key, result);
                    } else {
                        resume_open_message(worker, app, source, &key);
                    }
                }
                Done::Skipped(key, epoch) if key.0 == worker.account => {
                    if worker.finish_fetch(&key, epoch) {
                        resume_open_message(worker, app, source, &key);
                    }
                }
                Done::Synced(account, result) if account == worker.account => {
                    worker.syncing = false;
                    app.synced(&account, result, now, worker.next_sync_millis());
                    app.set_accounts(source.account_labels());
                    reload |= app.scope.contains(&account);
                }
                _ => {} // A completion from any other account is never applied.
            }
        }
    }
    if reload {
        let loaded = app.rows.len().max(usize::from(FIRST_PAGE));
        if let Ok(page) = read_scoped_rows(source, &app.scope, loaded) {
            set_progress(app, &page);
            app.reload(page.rows, app.more_rows);
            while app.selection_pending() && app.more_rows {
                load_page(app, source);
            }
        } else {
            // Query availability and network sync results are separate states.
            app.rows_failed();
            app.status = Some("The local mailbox could not be read again.".to_owned());
        }
    }
    changed
}

/// A reopened current message may have coalesced with an old-view fetch.
/// Ignore the old result, then satisfy the CURRENT request via a fresh cache
/// read or its own generation-tagged download, with exact account routing.
fn resume_open_message(
    worker: &mut Worker,
    app: &mut App,
    source: &dyn MailSource,
    key: &MessageKey,
) {
    if app.open_key() != Some(key) || !app.scope.contains(&key.0) {
        return;
    }
    match source.message(&key.0, &key.1) {
        Ok(None) if worker.fetch(key) => app.downloading(key),
        Ok(None) => app.downloaded(key.clone(), Err(FETCH_NOT_QUEUED.to_owned())),
        raw => app.show_message(key.clone(), raw),
    }
}

/// Reads the page that follows the loaded rows; returns whether it changed
/// the list.
fn load_page(app: &mut App, source: &dyn MailSource) -> bool {
    match read_page(source, &app.scope, app.continuation.as_ref(), PAGE) {
        Ok(page) => {
            set_progress(app, &page);
            app.append(page.rows);
        }
        // The top bar says so; a status line would vanish at the next key.
        Err(()) => app.rows_failed(),
    }
    true
}

/// Reads exactly one application page; only the application probes for more.
fn read_page(
    source: &dyn MailSource,
    scope: &ViewScope,
    continuation: Option<&UnifiedMailboxContinuation>,
    limit: u16,
) -> Result<MailPage, ()> {
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(());
    }
    source.page(scope, continuation, limit)
}

/// Restarts from a fresh query and reads up to a GLOBAL row count in bounded
/// pages after sync, never passing a loaded row count to an account reader.
#[cfg(test)]
pub(crate) fn read_rows(source: &dyn MailSource, limit: usize) -> Result<MailPage, ()> {
    read_scoped_rows(source, &ViewScope::All, limit)
}

fn read_scoped_rows(
    source: &dyn MailSource,
    scope: &ViewScope,
    limit: usize,
) -> Result<MailPage, ()> {
    if limit == 0 {
        return Err(());
    }
    let mut page = read_page(
        source,
        scope,
        None,
        u16::try_from(limit.min(usize::from(PAGE))).map_err(|_error| ())?,
    )?;
    while page.rows.len() < limit && page.continuation.is_some() {
        let size =
            u16::try_from((limit - page.rows.len()).min(usize::from(PAGE))).map_err(|_error| ())?;
        let next = read_page(source, scope, page.continuation.as_ref(), size)?;
        page.rows.extend(next.rows);
        page.continuation = next.continuation;
        page.unavailable_accounts = next.unavailable_accounts;
        page.rows.retain(|row| {
            !page
                .unavailable_accounts
                .iter()
                .any(|entry| entry.account_id == row.account)
        });
    }
    Ok(page)
}

/// Fails the sync and downloads a stopped worker still owed; returns whether
/// there were any.
fn fail_pending(worker: &mut Worker, app: &mut App, now: i64) -> bool {
    if worker.dead {
        return false;
    }
    worker.dead = true;
    worker.syncing = false;
    app.synced(&worker.account, Err(WORKER_GONE.to_owned()), now, None);
    for (key, epoch) in std::mem::take(&mut worker.fetching) {
        if epoch == app.view_epoch {
            app.downloaded(key, Err(WORKER_GONE.to_owned()));
        }
    }
    true
}

/// What the terminal has for the event loop.
enum Input {
    /// A key or a resize is waiting.
    Waiting,
    /// Nothing arrived in time.
    None,
    /// The terminal is gone.
    Closed,
}

/// Waits up to `wait` for a key or a resize.
///
/// crossterm reads a terminal that has gone away again and again, at full
/// speed, when no hangup signal ends the process (crossterm-rs/crossterm#793),
/// so the wait happens here and crossterm runs only while standard input,
/// which it reads because [`require_terminal`] passed, is still open.
fn wait_for_input(wait: Duration) -> std::io::Result<Input> {
    // The first pass returns events crossterm parsed from an earlier read.
    for timeout in [Duration::ZERO, wait] {
        if !terminal_open(std::io::stdin(), timeout)? {
            return Ok(Input::Closed);
        }
        if event::poll(Duration::ZERO)? {
            return Ok(Input::Waiting);
        }
    }
    Ok(Input::None)
}

/// Waits up to `timeout` for `input` to become readable; returns false when
/// the terminal behind it has gone away.
fn terminal_open(input: impl AsFd, timeout: Duration) -> std::io::Result<bool> {
    let mut fds = [PollFd::new(&input, PollFlags::IN)];
    let mut timeout = Timespec::try_from(timeout).map_err(std::io::Error::other)?;
    loop {
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(_) => break,
            // A signal, such as a resize, which crossterm reports once a
            // second look shows the terminal still open.
            Err(Errno::INTR) => timeout = Timespec::default(),
            Err(error) => return Err(error.into()),
        }
    }
    let revents = fds[0].revents();
    if revents.contains(PollFlags::HUP) {
        return Ok(false);
    }
    if revents.intersects(PollFlags::ERR | PollFlags::NVAL) {
        return Err(std::io::Error::other("the terminal cannot be polled"));
    }
    Ok(true)
}

/// Sends standard error nowhere once it is a terminal that has gone away.
/// ratatui reports there that it could not restore the terminal, and a failed
/// `eprintln!` would abort before the network thread stops.
fn silence_closed_stderr() {
    if let Ok(false) = terminal_open(std::io::stderr(), Duration::ZERO)
        && let Ok(null) = std::fs::File::options().write(true).open("/dev/null")
    {
        let _ = rustix::stdio::dup2_stderr(&null);
    }
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
    use std::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime};

    use tersa_application::mailbox::{AccountId, MessageId};
    use tersa_application::unified_mailbox::UnavailableAccount;
    use tersa_presentation::terminal::SafeText;

    use super::app::{Body, Screen, SyncState};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::{
        App, Done, FIRST_PAGE, MailPage, MailSource, MessageKey, Row, UnifiedMailboxContinuation,
        ViewScope, WORKER_GONE, Worker, Workers, change_view, finish_work, initial_app, load_page,
        read_page, read_rows, read_scoped_rows, set_progress, start_sync, terminal_open,
        unreadable_status, view,
    };

    fn id(text: &str) -> MessageId {
        MessageId::new(text).expect("id")
    }

    fn account(text: &str) -> AccountId {
        AccountId::new(text).expect("account")
    }

    fn key(account_text: &str, id_text: &str) -> MessageKey {
        (account(account_text), id(id_text))
    }

    /// The interface over one account with the given labels.
    fn labeled(labels: &[&str]) -> Vec<(AccountId, SafeText)> {
        labels
            .iter()
            .map(|label| (account(label), SafeText::single_line(label)))
            .collect()
    }

    struct Empty;

    impl MailSource for Empty {
        fn page(
            &self,
            _scope: &ViewScope,
            _continuation: Option<&UnifiedMailboxContinuation>,
            _limit: u16,
        ) -> Result<MailPage, ()> {
            Ok(MailPage::default())
        }

        fn message(&self, _account: &AccountId, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }

        fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
            vec![(account("acct"), SafeText::single_line("acct"))]
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
                    Row::from_envelope(&envelope, &account("acct"))
                })
                .collect();
            Self {
                rows,
                reads: std::cell::Cell::new(0),
            }
        }
    }

    struct PageReader(Vec<tersa_application::mailbox::MessageEnvelope>);
    impl tersa_application::mailbox::MailboxReader for PageReader {
        fn list_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: tersa_application::mailbox::StoreLimit,
        ) -> tersa_application::mailbox::BoxFuture<
            'a,
            Result<
                Vec<tersa_application::mailbox::MessageEnvelope>,
                tersa_application::mailbox::MailboxStoreError,
            >,
        > {
            panic!("no fallback")
        }
        fn thread_envelopes<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a tersa_application::mailbox::ThreadId,
            _: tersa_application::mailbox::StoreLimit,
        ) -> tersa_application::mailbox::BoxFuture<
            'a,
            Result<
                Vec<tersa_application::mailbox::MessageEnvelope>,
                tersa_application::mailbox::MailboxStoreError,
            >,
        > {
            panic!("no thread reads")
        }
        fn get_message<'a>(
            &'a self,
            _: &'a AccountId,
            _: &'a MessageId,
        ) -> tersa_application::mailbox::BoxFuture<
            'a,
            Result<
                Option<tersa_application::mailbox::Message>,
                tersa_application::mailbox::MailboxStoreError,
            >,
        > {
            panic!("no body reads")
        }
        fn list_envelopes_after<'a>(
            &'a self,
            _: &'a AccountId,
            after: Option<&'a tersa_application::mailbox::EnvelopeCursor>,
            limit: tersa_application::mailbox::StoreLimit,
        ) -> tersa_application::mailbox::BoxFuture<
            'a,
            Result<
                Vec<tersa_application::mailbox::MessageEnvelope>,
                tersa_application::mailbox::MailboxStoreError,
            >,
        > {
            assert!(limit.get() <= 201);
            Box::pin(async move {
                Ok(self
                    .0
                    .iter()
                    .filter(|row| after.is_none_or(|cursor| cursor.precedes(row)))
                    .take(usize::from(limit.get()))
                    .cloned()
                    .collect())
            })
        }
    }

    fn app_loaded(source: &dyn MailSource, count: usize) -> App {
        let page = read_rows(source, count).expect("rows");
        let mut app = App::new(source.account_labels(), Vec::new());
        set_progress(&mut app, &page);
        app.append(page.rows);
        app
    }

    fn fresh_row(index: usize) -> Row {
        let mut row = Row::sample("acct", &format!("new{index:05}"), "Zed", "Fresh", true);
        row.received_at_millis = 2_000_000 - i64::try_from(index).expect("small");
        row
    }

    impl MailSource for Pages {
        fn page(
            &self,
            scope: &ViewScope,
            continuation: Option<&UnifiedMailboxContinuation>,
            limit: u16,
        ) -> Result<MailPage, ()> {
            assert!(
                limit <= 200,
                "every test path, including reload, is bounded"
            );
            self.reads.set(self.reads.get() + 1);
            let reader = PageReader(
                self.rows
                    .iter()
                    .map(|row| {
                        tersa_application::mailbox::MessageEnvelope::new(
                            row.id.clone(),
                            tersa_application::mailbox::ThreadId::new("t").expect("thread"),
                            tersa_application::mailbox::HeaderText::new(row.sender.as_str())
                                .expect("sender"),
                            tersa_application::mailbox::HeaderText::new(row.subject.as_str())
                                .expect("subject"),
                            tersa_application::mailbox::HeaderText::new(row.preview.as_str())
                                .expect("preview"),
                            tersa_application::mailbox::UnixTimestampMillis::new(
                                row.received_at_millis,
                            )
                            .expect("time"),
                            row.unread,
                        )
                    })
                    .collect(),
            );
            let sources = [
                tersa_application::unified_mailbox::UnifiedMailboxSource::Ready {
                    account_id: account("acct"),
                    reader: &reader,
                },
            ];
            let sources: Vec<_> = sources
                .into_iter()
                .filter(|source| scope.contains(source.account_id()))
                .collect();
            let result = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime")
                .block_on(
                    tersa_application::unified_mailbox::UnifiedMailboxQuery.execute(
                        &sources,
                        limit,
                        continuation,
                        false,
                    ),
                )
                .map_err(|_error| ())?;
            match result {
                tersa_application::unified_mailbox::UnifiedMailboxResult::Available(document) => {
                    Ok(document.into())
                }
                tersa_application::unified_mailbox::UnifiedMailboxResult::Locked => Err(()),
            }
        }

        fn message(&self, _account: &AccountId, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }

        fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
            vec![(account("acct"), SafeText::single_line("acct"))]
        }
    }

    #[test]
    fn older_rows_load_a_page_at_a_time_and_join_the_search() {
        let source = Pages::new(1_234);
        let mut app = initial_app(&source).expect("app");
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
        assert_eq!(
            source.reads.get(),
            1 + 6,
            "100, then five 200-row pages and 134"
        );
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
        let page = read_page(&source, &ViewScope::All, None, FIRST_PAGE).expect("page");
        assert_eq!(page.rows.len(), 100);
        assert!(page.continuation.is_none(), "exactly one first page");

        let source = Pages::new(600);
        let mut app = initial_app(&source).expect("app");
        while app.more_rows {
            load_page(&mut app, &source);
        }
        assert_eq!(app.rows.len(), 600);
        assert_eq!(
            source.reads.get(),
            4,
            "100, 200, 200, 100; no empty final read"
        );
    }

    #[test]
    fn a_failed_older_page_outlasts_the_next_key() {
        struct OlderFail(Pages);
        impl MailSource for OlderFail {
            fn page(
                &self,
                scope: &ViewScope,
                continuation: Option<&UnifiedMailboxContinuation>,
                limit: u16,
            ) -> Result<MailPage, ()> {
                if continuation.is_some() {
                    return Err(());
                }
                self.0.page(scope, continuation, limit)
            }

            fn message(
                &self,
                _account: &AccountId,
                _id: &MessageId,
            ) -> Result<Option<Vec<u8>>, ()> {
                Ok(None)
            }

            fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
                vec![(account("acct"), SafeText::single_line("acct"))]
            }
        }
        let source = OlderFail(Pages::new(1_234));
        let mut app = initial_app(&source).expect("app");
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "odd".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        load_page(&mut app, &source);
        assert!(!app.more_rows, "loading stops");
        assert_eq!(
            app.status.as_deref(),
            Some("50+ matches; esc shows every message"),
            "older mail was never searched"
        );
        app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert!(app.rows_unreadable, "a key press does not clear it");
    }

    #[test]
    fn a_failed_reload_after_a_sync_stops_paging() {
        struct FailAfterSync(Pages, std::cell::Cell<bool>);
        impl MailSource for FailAfterSync {
            fn page(
                &self,
                scope: &ViewScope,
                continuation: Option<&UnifiedMailboxContinuation>,
                limit: u16,
            ) -> Result<MailPage, ()> {
                if self.1.get() {
                    return Err(());
                }
                self.0.page(scope, continuation, limit)
            }

            fn message(
                &self,
                _account: &AccountId,
                _id: &MessageId,
            ) -> Result<Option<Vec<u8>>, ()> {
                Ok(None)
            }

            fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
                vec![(account("acct"), SafeText::single_line("acct"))]
            }
        }
        let source = FailAfterSync(Pages::new(1_234), std::cell::Cell::new(false));
        let mut app = initial_app(&source).expect("app");
        source.1.set(true);
        finished_sync(&mut app, &source, Ok(()));
        assert!(
            !app.more_rows,
            "rows loaded before the sync are no cursor for after it"
        );
        assert!(app.rows_unreadable);
        assert!(matches!(app.sync[0].state, SyncState::Synced(_)));
    }

    fn finished_sync(app: &mut App, source: &dyn MailSource, result: Result<(), String>) {
        let (done_sender, done) = mpsc::channel();
        let account = app.accounts[0].0.clone();
        let mut workers = Workers {
            accounts: vec![Worker::fixture(account.clone(), done, true, HashSet::new())],
        };
        done_sender
            .send(Done::Synced(account, result))
            .expect("send");
        assert!(finish_work(&mut workers, app, source, 0));
    }

    /// The screen as text lines, so a test can read what was drawn.
    fn drawn(app: &mut App) -> Vec<String> {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| view::draw(frame, app, 1_761_000_000_000))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        (0..24)
            .map(|y| {
                (0..80)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect::<String>()
            })
            .collect()
    }

    fn selected_id(app: &App) -> Option<&str> {
        app.shown_row(app.selected).map(|row| row.id.as_str())
    }

    #[test]
    fn a_selection_the_sync_removed_stops_the_catch_up() {
        let mut source = Pages::new(1_234);
        let mut app = app_loaded(&source, 600);
        app.more_rows = true;
        for _ in 0..599 {
            app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        let newer: Vec<Row> = (0..600).map(fresh_row).collect();
        source.rows.retain(|row| row.id.as_str() != "m00599");
        source.rows.splice(0..0, newer);
        finished_sync(&mut app, &source, Ok(()));
        assert!(!app.selection_pending(), "the listing passed where it was");
        // Reload restores 600 rows. Three bounded catch-up pages pass the
        // deleted selection, without draining the rest of the cache.
        assert_eq!(
            app.rows.len(),
            600 + 200 + 200 + 200,
            "the catch-up stops there, short of the 1,833 cached"
        );
        assert!(app.more_rows, "the rest loads in the background");
    }

    #[test]
    fn a_failed_sync_still_reads_the_list_again() {
        let mut source = Pages::new(50);
        let mut app = initial_app(&source).expect("app");
        // Envelopes stored before a later step of the sync failed.
        source.rows.insert(0, fresh_row(0));
        finished_sync(&mut app, &source, Err("bodies failed".to_owned()));
        assert_eq!(app.rows.len(), 51);
        assert_eq!(app.rows[0].id.as_str(), "new00000");
        assert!(matches!(app.sync[0].state, SyncState::Failed(_)));
    }

    /// A cache whose stored Gmail address appears and disappears between
    /// syncs, like a store that gains it on the start-up sync and loses it on
    /// an identity mismatch. The label is the stored address when there is
    /// one, otherwise the account id.
    struct Labeled(Pages, std::cell::RefCell<Option<SafeText>>);

    impl MailSource for Labeled {
        fn page(
            &self,
            scope: &ViewScope,
            continuation: Option<&UnifiedMailboxContinuation>,
            limit: u16,
        ) -> Result<MailPage, ()> {
            self.0.page(scope, continuation, limit)
        }

        fn message(&self, _account: &AccountId, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }

        fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
            let stored = self.1.borrow().clone();
            vec![(
                account("acct_1234"),
                stored.unwrap_or_else(|| SafeText::single_line("acct_1234")),
            )]
        }
    }

    /// Two accounts whose labels change between reads, like stores that gain
    /// their Gmail addresses on a start-up sync.
    struct Relabeled(Vec<Row>, std::cell::RefCell<Vec<(AccountId, SafeText)>>);

    impl MailSource for Relabeled {
        fn page(
            &self,
            scope: &ViewScope,
            _continuation: Option<&UnifiedMailboxContinuation>,
            _limit: u16,
        ) -> Result<MailPage, ()> {
            Ok(MailPage {
                rows: self
                    .0
                    .iter()
                    .filter(|row| scope.contains(&row.account))
                    .cloned()
                    .collect(),
                ..MailPage::default()
            })
        }

        fn message(&self, _account: &AccountId, _id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }

        fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
            self.1.borrow().clone()
        }
    }

    #[test]
    fn every_finished_sync_picks_up_the_top_bar_label() {
        let source = Labeled(Pages::new(2), std::cell::RefCell::new(None));
        let mut app = initial_app(&source).expect("app");
        finished_sync(&mut app, &source, Ok(()));
        assert_eq!(
            app.accounts[0].1.as_str(),
            "acct_1234",
            "no stored label yet keeps the id"
        );
        // The start-up sync stored the account's Gmail address; the next
        // finished sync shows it on the bar.
        *source.1.borrow_mut() = Some(SafeText::single_line("me@example.com"));
        finished_sync(&mut app, &source, Ok(()));
        assert_eq!(app.accounts[0].1.as_str(), "me@example.com");
        // An identity mismatch clears the address, and its sync may fail
        // after the clear; the bar must not keep the replaced identity's
        // address, so the failed sync reads the store again and falls back
        // to the id.
        *source.1.borrow_mut() = None;
        finished_sync(&mut app, &source, Err("offline".to_owned()));
        assert_eq!(app.accounts[0].1.as_str(), "acct_1234");
    }

    #[test]
    fn a_finished_sync_refreshes_the_open_message_header() {
        let source = Relabeled(
            vec![
                Row::sample("acct_a", "a", "Ann", "Lunch", false),
                Row::sample("acct_b", "b", "Bob", "Report", false),
            ],
            std::cell::RefCell::new(labeled(&["acct_a", "acct_b"])),
        );
        let mut app = initial_app(&source).expect("app");
        app.show_message(key("acct_a", "a"), Ok(None));
        assert!(
            drawn(&mut app).join("\n").contains("Account: acct_a"),
            "the header is cached with the label it was drawn with"
        );
        // The start-up sync stores the account's Gmail address.
        *source.1.borrow_mut() = vec![
            (account("acct_a"), SafeText::single_line("ann@example.com")),
            (account("acct_b"), SafeText::single_line("acct_b")),
        ];
        finished_sync(&mut app, &source, Ok(()));
        let text = drawn(&mut app).join("\n");
        assert!(text.contains("Account: ann@example.com"), "{text:?}");
    }

    #[test]
    fn a_sync_reloads_as_many_rows_as_were_loaded() {
        let source = Pages::new(1_234);
        let mut app = app_loaded(&source, 600);
        app.more_rows = true;
        for _ in 0..300 {
            app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        finished_sync(&mut app, &source, Ok(()));
        assert_eq!(app.rows.len(), 600);
        assert!(app.more_rows);
        assert_eq!(selected_id(&app), Some("m00300"));
    }

    #[test]
    fn a_selection_pushed_past_the_reload_comes_back_with_its_page() {
        let mut source = Pages::new(1_234);
        let mut app = app_loaded(&source, 600);
        app.more_rows = true;
        for _ in 0..599 {
            app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        assert_eq!(selected_id(&app), Some("m00599"));
        // The sync stored more newer messages than one page holds, so the
        // 600 rows read again end before the selected one.
        let newer: Vec<Row> = (0..600).map(fresh_row).collect();
        source.rows.splice(0..0, newer);
        finished_sync(&mut app, &source, Ok(()));
        assert_eq!(
            selected_id(&app),
            Some("m00599"),
            "back before the next frame"
        );
    }

    #[test]
    fn a_later_unavailable_document_removes_old_account_rows_and_open_body() {
        struct BecomesUnavailable(Pages, std::cell::Cell<bool>);
        impl MailSource for BecomesUnavailable {
            fn page(
                &self,
                scope: &ViewScope,
                continuation: Option<&UnifiedMailboxContinuation>,
                limit: u16,
            ) -> Result<MailPage, ()> {
                if self.1.get() {
                    Ok(MailPage { unavailable_accounts: vec![UnavailableAccount { account_id: account("acct"), state: tersa_application::unified_mailbox::UnavailableAccountState::StoreUnavailable }], ..MailPage::default() })
                } else {
                    self.0.page(scope, continuation, limit)
                }
            }
            fn message(&self, account: &AccountId, id: &MessageId) -> Result<Option<Vec<u8>>, ()> {
                self.0.message(account, id)
            }
            fn account_labels(&self) -> Vec<(AccountId, SafeText)> {
                self.0.account_labels()
            }
        }
        let source = BecomesUnavailable(Pages::new(300), std::cell::Cell::new(false));
        let mut app = initial_app(&source).expect("first page");
        app.show_message(
            key("acct", "m00000"),
            Ok(Some(b"Subject: old\r\n\r\nold body".to_vec())),
        );
        source.1.set(true);
        load_page(&mut app, &source);
        assert!(
            app.rows.is_empty(),
            "an unavailable account contributes no stale rows"
        );
        assert!(
            app.open_key().is_none(),
            "its old body is no longer displayed"
        );
        assert!(app.repaint);
        assert!(app.continuation.is_none());
        assert_eq!(app.unavailable_accounts.len(), 1);
    }

    #[test]
    fn all_unavailable_accounts_render_a_document_instead_of_exiting() {
        let source = crate::commands::StoreSource {
            stores: vec![(account("acct_a"), None), (account("acct_b"), None)],
            executor: tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime"),
            requests: std::cell::RefCell::default(),
        };
        let mut app = initial_app(&source).expect("all-unavailable UI admission");
        assert!(app.rows.is_empty());
        assert_eq!(app.accounts.len(), 2);
        assert_eq!(app.unavailable_accounts.len(), 2);
        assert!(app.continuation.is_none());
        assert!(app.unavailable_accounts.iter().all(|entry| entry.state
            == tersa_application::unified_mailbox::UnavailableAccountState::StoreUnavailable));
        app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        let screen = drawn(&mut app).join("\n");
        assert!(screen.contains("2 accounts unavailable"), "{screen}");
        assert!(screen.contains("their mail is not shown"), "{screen}");
        assert!(
            !screen.contains("No cached mail yet"),
            "unavailability is not an empty cache"
        );
    }

    fn sql_envelope(name: &str, at: i64) -> tersa_application::mailbox::MessageEnvelope {
        use tersa_application::mailbox::{
            HeaderText, MessageEnvelope, ThreadId, UnixTimestampMillis,
        };
        MessageEnvelope::new(
            id(name),
            ThreadId::new("t").expect("thread"),
            HeaderText::new("Ann").expect("sender"),
            HeaderText::new("Subject").expect("subject"),
            HeaderText::new("Preview").expect("preview"),
            UnixTimestampMillis::new(at).expect("time"),
            false,
        )
    }

    #[test]
    fn sqlcipher_sync_reload_restarts_bounded_pages_and_keeps_the_exact_duplicate_id_selection() {
        use tersa_application::mailbox::MailboxStore;
        use tersa_store_sqlcipher::{DatabaseKey, SqlCipherMailboxStore};
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(std::env::temp_dir().join(format!(
                "tersa-bounded-reload-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir_all(&directory.0).expect("directory");
        let executor = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut stores = Vec::new();
        for name in ["acct_a", "acct_b"] {
            let account = account(name);
            let store = SqlCipherMailboxStore::open(
                account.clone(),
                directory.0.join(format!("{name}.sqlite3")),
                DatabaseKey::new([9; 32]),
            )
            .expect("store");
            let rows: Vec<_> = (0..400)
                .map(|index| sql_envelope(&format!("same{index:03}"), 1_000_000 - index))
                .collect();
            executor
                .block_on(store.upsert_envelopes(&account, &rows))
                .expect("seed");
            stores.push((account, Some(store)));
        }
        let source = crate::commands::StoreSource {
            stores,
            executor,
            requests: std::cell::RefCell::default(),
        };
        let mut app = app_loaded(&source, 600);
        for _ in 0..599 {
            app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        let selected = app
            .shown_row(app.selected)
            .expect("selection")
            .message_key();
        assert_eq!(selected, key("acct_b", "same299"));
        app.show_message(selected.clone(), Ok(None));
        let newer: Vec<_> = (0..50)
            .map(|index| sql_envelope(&format!("new{index:03}"), 2_000_000 - index))
            .collect();
        source
            .executor
            .block_on(
                source.stores[0]
                    .1
                    .as_ref()
                    .expect("store")
                    .upsert_envelopes(&account("acct_a"), &newer),
            )
            .expect("sync metadata");
        source.requests.borrow_mut().clear();
        finished_sync(&mut app, &source, Ok(()));
        assert_eq!(app.open_key(), Some(&selected));
        assert_eq!(
            app.shown_row(app.selected)
                .expect("restored selection")
                .message_key(),
            selected
        );
        assert_eq!(
            app.rows.len(),
            800,
            "600 restored plus one bounded selection catch-up page"
        );
        assert_eq!(*source.requests.borrow(), [200, 200, 200, 200]);
        while app.more_rows {
            load_page(&mut app, &source);
        }
        assert_eq!(app.rows.len(), 850);
        let keys: HashSet<_> = app.rows.iter().map(Row::message_key).collect();
        assert_eq!(
            keys.len(),
            850,
            "same Gmail IDs in two accounts remain distinct"
        );
        assert!(source.requests.borrow().iter().all(|size| *size <= 200));
    }

    /// A pseudo-terminal: the side tersa reads, and the side the terminal
    /// emulator holds.
    fn pty() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        use rustix::fs::{Mode, OFlags};
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let emulator = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
        grantpt(&emulator).expect("grantpt");
        unlockpt(&emulator).expect("unlockpt");
        let name = ptsname(&emulator, Vec::new()).expect("ptsname");
        let input = rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )
        .expect("open the terminal");
        (input, emulator)
    }

    struct PendingRemote {
        account: AccountId,
        started: mpsc::Sender<AccountId>,
        dropped: mpsc::Sender<AccountId>,
    }
    impl Drop for PendingRemote {
        fn drop(&mut self) {
            let _ = self.dropped.send(self.account.clone());
        }
    }
    impl super::Remote for PendingRemote {
        fn fetch<'a>(&'a self, _: &'a AccountId, _: &'a MessageId) -> super::Pending<'a, Vec<u8>> {
            Box::pin(std::future::pending())
        }
        fn sync<'a>(&'a self, account: &'a AccountId) -> super::Pending<'a, ()> {
            Box::pin(async move {
                assert_eq!(account, &self.account);
                let _ = self.started.send(account.clone());
                std::future::pending().await
            })
        }
    }

    #[test]
    fn terminal_loss_drops_and_joins_every_account_worker() {
        let (input, emulator) = pty();
        let (started, starts) = mpsc::channel();
        let (dropped, drops) = mpsc::channel();
        {
            let remotes = ["acct_a", "acct_b"]
                .iter()
                .map(|name| {
                    (
                        account(name),
                        Box::new(PendingRemote {
                            account: account(name),
                            started: started.clone(),
                            dropped: dropped.clone(),
                        }) as Box<dyn super::Remote>,
                    )
                })
                .collect();
            let mut workers = Workers::start(remotes).expect("workers");
            for worker in &mut workers.accounts {
                assert!(worker.sync_at(Instant::now(), SystemTime::now()));
                assert_eq!(
                    starts
                        .recv_timeout(Duration::from_secs(5))
                        .expect("sync started"),
                    worker.account
                );
            }
            drop(emulator);
            assert!(!terminal_open(&input, Duration::from_secs(5)).expect("terminal loss"));
            // event_loop returns on Input::Closed; the same owned group drop
            // cancels and joins before the enclosing session can return.
        }
        let owners: HashSet<_> = drops.try_iter().collect();
        assert_eq!(
            owners,
            HashSet::from([account("acct_a"), account("acct_b")])
        );
    }

    #[test]
    fn a_worker_failure_joins_the_other_owned_workers_on_session_exit() {
        let (started, starts) = mpsc::channel();
        let (dropped, drops) = mpsc::channel();
        let mut workers = Workers::start(vec![(
            account("acct_b"),
            Box::new(PendingRemote {
                account: account("acct_b"),
                started,
                dropped,
            }),
        )])
        .expect("worker");
        assert!(workers.accounts[0].sync_at(Instant::now(), SystemTime::now()));
        assert_eq!(
            starts
                .recv_timeout(Duration::from_secs(5))
                .expect("sync started"),
            account("acct_b")
        );
        let (_, done) = mpsc::channel();
        workers.accounts.insert(
            0,
            Worker::fixture(account("acct_a"), done, true, HashSet::new()),
        );
        let mut app = App::new(labeled(&["acct_a", "acct_b"]), Vec::new());
        assert!(finish_work(&mut workers, &mut app, &Empty, 0));
        assert!(
            workers.accounts.iter().any(|worker| worker.dead),
            "event_loop takes the fatal worker-exit path"
        );
        drop(workers);
        assert_eq!(
            drops
                .try_recv()
                .expect("other owner dropped before session exit"),
            account("acct_b")
        );
    }

    #[test]
    fn sync_errors_are_account_local_and_completions_restart_one_fresh_query() {
        let source = Relabeled(
            vec![
                Row::sample("acct_a", "same", "Ann", "Cached A", false),
                Row::sample("acct_b", "same", "Bob", "Cached B", false),
            ],
            std::cell::RefCell::new(labeled(&["acct_a", "acct_b"])),
        );
        let mut app = initial_app(&source).expect("cached inbox");
        let (a, a_done) = mpsc::channel();
        let (b, b_done) = mpsc::channel();
        let mut workers = Workers {
            accounts: vec![
                Worker::fixture(account("acct_a"), a_done, true, HashSet::new()),
                Worker::fixture(account("acct_b"), b_done, true, HashSet::new()),
            ],
        };
        // A mismatched event cannot update B through A's worker.
        a.send(Done::Synced(
            account("acct_b"),
            Err("wrong route".to_owned()),
        ))
        .expect("send");
        assert!(finish_work(&mut workers, &mut app, &source, 41));
        assert!(workers.accounts[0].syncing);
        assert_eq!(app.sync[1].state, SyncState::Idle);
        b.send(Done::Synced(account("acct_b"), Ok(())))
            .expect("B success");
        a.send(Done::Synced(
            account("acct_a"),
            Err("authorization required".to_owned()),
        ))
        .expect("A failure");
        assert!(finish_work(&mut workers, &mut app, &source, 42));
        assert!(matches!(app.sync[0].state, SyncState::Failed(_)));
        assert_eq!(app.sync[1].state, SyncState::Synced(42));
        assert_eq!(app.sync[1].last_success, Some(42));
        assert_eq!(
            app.rows.len(),
            2,
            "remote auth failure does not suppress local cache"
        );
        assert!(app.unavailable_accounts.is_empty());
        assert!(
            !app.sync_started(&account("acct_unknown"), None),
            "no first-account fallback"
        );
    }

    #[test]
    fn a_closed_terminal_is_seen_at_once() {
        let (input, emulator) = pty();
        // An idle terminal is waited for, not reported at once.
        let start = Instant::now();
        assert!(terminal_open(&input, Duration::from_millis(50)).expect("poll"));
        assert!(start.elapsed() >= Duration::from_millis(40));

        drop(emulator);
        let start = Instant::now();
        assert!(!terminal_open(&input, Duration::from_secs(10)).expect("poll"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_stopped_worker_fails_the_work_it_owed() {
        let (_, done) = mpsc::channel();
        let mut worker = Workers {
            accounts: vec![Worker::fixture(
                account("acct_a"),
                done,
                true,
                HashSet::from([key("acct_a", "a")]),
            )],
        };
        let mut app = App::new(labeled(&["acct_a"]), Vec::new());
        app.show_message(key("acct_a", "a"), Ok(None));
        app.downloading(&key("acct_a", "a"));
        assert!(finish_work(&mut worker, &mut app, &Empty, 0));
        assert!(
            matches!(&app.sync[0].state, SyncState::Failed(error) if error.as_str() == WORKER_GONE)
        );
        assert!(
            matches!(&app.screen, Screen::Message(view)
                if matches!(&view.body, Body::DownloadFailed(error) if error == WORKER_GONE)),
            "the open message says why it will not arrive"
        );
        assert!(!worker.accounts[0].syncing && worker.accounts[0].fetching.is_empty());
        assert!(
            !finish_work(&mut worker, &mut app, &Empty, 0),
            "reported once"
        );
        assert!(
            !worker.accounts[0].sync_at(Instant::now(), SystemTime::now()),
            "a stopped worker is not retried"
        );
    }

    #[test]
    fn unreadable_accounts_are_reported_without_identity() {
        assert_eq!(unreadable_status(0), None);
        assert_eq!(
            unreadable_status(1).as_deref(),
            Some("1 account could not be read; its mail is not shown")
        );
        assert_eq!(
            unreadable_status(2).as_deref(),
            Some("2 accounts could not be read; their mail is not shown")
        );
    }

    struct ViewDirectory(std::path::PathBuf);
    impl Drop for ViewDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct ViewFixture {
        source: crate::commands::StoreSource,
        _directory: ViewDirectory,
    }
    fn view_fixture() -> ViewFixture {
        use tersa_application::mailbox::{
            HeaderText, MailboxStore, MessageEnvelope, ThreadId, UnixTimestampMillis,
        };
        use tersa_store_sqlcipher::{DatabaseKey, SqlCipherMailboxStore};
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "tersa-view-{}-{serial}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("directory");
        let directory = ViewDirectory(root);
        let executor = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut stores = Vec::new();
        for (name, subject) in [("acct_a", "alpha"), ("acct_b", "beta")] {
            let account = account(name);
            let store = SqlCipherMailboxStore::open(
                account.clone(),
                directory.0.join(format!("{name}.sqlite3")),
                DatabaseKey::new([9; 32]),
            )
            .expect("store");
            let rows: Vec<_> = (0..225)
                .map(|index| {
                    MessageEnvelope::new(
                        id(&format!("same{index:03}")),
                        ThreadId::new("t").expect("thread"),
                        HeaderText::new("Sender").expect("sender"),
                        HeaderText::new(subject).expect("subject"),
                        HeaderText::new("preview").expect("preview"),
                        UnixTimestampMillis::new(10_000 - index).expect("time"),
                        false,
                    )
                })
                .collect();
            executor
                .block_on(store.upsert_envelopes(&account, &rows))
                .expect("seed");
            stores.push((account, Some(store)));
        }
        stores.push((account("acct_unavailable"), None));
        ViewFixture {
            source: crate::commands::StoreSource {
                stores,
                executor,
                requests: std::cell::RefCell::default(),
            },
            _directory: directory,
        }
    }

    #[test]
    fn real_scoped_queries_cycle_fresh_continuations_and_clear_old_view_state() {
        let fixture = view_fixture();
        let source = &fixture.source;
        let mut workers = Workers::start(Vec::new()).expect("offline workers");
        let mut app = initial_app(source).expect("All");
        let all_cursor = app.continuation.clone();
        assert_eq!(app.rows.len(), 100);
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "beta".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.show_message(
            key("acct_b", "same000"),
            Ok(Some(b"Subject: old\r\n\r\nold body".to_vec())),
        );
        assert!(
            change_view(
                &mut app,
                source,
                &mut workers,
                ViewScope::Account(account("acct_a"))
            )
            .expect("A")
        );
        assert_eq!(app.search.query, "");
        assert_eq!(app.selected, 0);
        assert!(app.open_key().is_none());
        assert_eq!(app.rows.len(), 100);
        assert!(app.rows.iter().all(|row| row.account == account("acct_a")));
        assert!(
            source.page(&app.scope, all_cursor.as_ref(), 37).is_err(),
            "the old account set cannot resume in A"
        );
        let next = source
            .page(&app.scope, app.continuation.as_ref(), 37)
            .expect("variable A page");
        assert_eq!(next.rows[0].id.as_str(), "same100");
        assert_eq!(next.rows.len(), 37);
        let cursor = app.continuation.clone();
        let epoch = app.view_epoch;
        let calls = source.requests.borrow().len();
        assert!(
            !change_view(
                &mut app,
                source,
                &mut workers,
                ViewScope::Account(account("acct_a"))
            )
            .expect("no-op")
        );
        assert_eq!(source.requests.borrow().len(), calls);
        assert_eq!(app.continuation, cursor);
        assert_eq!(app.view_epoch, epoch);
        assert!(
            change_view(
                &mut app,
                source,
                &mut workers,
                ViewScope::Account(account("acct_b"))
            )
            .expect("B")
        );
        assert_eq!(app.rows[0].message_key(), key("acct_b", "same000"));
        assert!(app.rows.iter().all(|row| row.account == account("acct_b")));
        assert!(change_view(&mut app, source, &mut workers, ViewScope::All).expect("All again"));
        assert_eq!(app.rows[0].message_key(), key("acct_a", "same000"));
        assert_eq!(app.rows[1].message_key(), key("acct_b", "same000"));
        assert_eq!(app.rows.len(), 100);
        assert_eq!(app.view_epoch, 3);
        assert!(source.requests.borrow().iter().all(|size| *size <= 200));
    }

    #[test]
    fn search_and_unavailable_views_are_scoped_and_unknown_accounts_never_fall_back() {
        let fixture = view_fixture();
        let source = &fixture.source;
        let mut workers = Workers::start(Vec::new()).expect("offline");
        let mut app = initial_app(source).expect("All");
        change_view(
            &mut app,
            source,
            &mut workers,
            ViewScope::Account(account("acct_a")),
        )
        .expect("A");
        while app.more_rows {
            load_page(&mut app, source);
        }
        assert_eq!(app.rows.len(), 225);
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "beta".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            app.shown.is_empty(),
            "B's cached beta rows are outside A's search"
        );
        let all = read_scoped_rows(source, &ViewScope::All, 450).expect("All rows");
        assert_eq!(
            all.rows
                .iter()
                .filter(|row| row.subject.as_str() == "beta")
                .count(),
            225
        );
        let unknown = ViewScope::Account(account("acct_unknown"));
        let before = source.requests.borrow().len();
        assert_eq!(
            change_view(&mut app, source, &mut workers, unknown.clone()),
            Err(())
        );
        assert_eq!(source.requests.borrow().len(), before);
        assert_eq!(app.scope, ViewScope::Account(account("acct_a")));
        assert!(source.page(&unknown, None, 100).is_err());
        change_view(
            &mut app,
            source,
            &mut workers,
            ViewScope::Account(account("acct_unavailable")),
        )
        .expect("registered unavailable");
        assert_eq!(app.search.query, "");
        assert!(app.rows.is_empty());
        assert!(app.continuation.is_none());
        assert_eq!(app.unavailable_accounts.len(), 1);
        assert_eq!(
            app.unavailable_accounts[0].account_id,
            account("acct_unavailable")
        );
        assert!(
            drawn(&mut app)
                .join("\n")
                .contains("their mail is not shown")
        );
    }

    #[test]
    fn old_view_completion_cannot_overwrite_the_same_message_reopened_in_a_new_view() {
        struct Replies(std::sync::atomic::AtomicUsize);
        impl super::Remote for Replies {
            fn fetch<'a>(
                &'a self,
                _: &'a AccountId,
                _: &'a MessageId,
            ) -> super::Pending<'a, Vec<u8>> {
                Box::pin(async move {
                    let index = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(if index == 0 {
                        b"Subject: old\r\n\r\nold body".to_vec()
                    } else {
                        b"Subject: new\r\n\r\nnew body".to_vec()
                    })
                })
            }
            fn sync<'a>(&'a self, _: &'a AccountId) -> super::Pending<'a, ()> {
                Box::pin(std::future::pending())
            }
        }
        let source = Relabeled(
            vec![
                Row::sample("acct_a", "same", "Ann", "A", false),
                Row::sample("acct_b", "same", "Bob", "B", false),
            ],
            std::cell::RefCell::new(labeled(&["acct_a", "acct_b"])),
        );
        let mut app = initial_app(&source).expect("All");
        let mut workers = Workers::start(vec![(
            account("acct_a"),
            Box::new(Replies(std::sync::atomic::AtomicUsize::new(0))),
        )])
        .expect("worker");
        let (inject, incoming) = mpsc::channel();
        let actual = std::mem::replace(&mut workers.accounts[0].done, incoming);
        let wanted = key("acct_a", "same");
        app.show_message(wanted.clone(), Ok(None));
        assert!(workers.fetch(&wanted));
        app.downloading(&wanted);
        let old = actual
            .recv_timeout(Duration::from_secs(5))
            .expect("old result queued");
        change_view(
            &mut app,
            &source,
            &mut workers,
            ViewScope::Account(account("acct_a")),
        )
        .expect("new A view");
        assert!(app.open_key().is_none());
        app.show_message(wanted.clone(), Ok(None));
        assert!(workers.fetch(&wanted));
        app.downloading(&wanted);
        inject.send(old).expect("late old view result");
        assert!(finish_work(&mut workers, &mut app, &source, 0));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::Downloading)),
            "old body must not be shown"
        );
        let current = actual
            .recv_timeout(Duration::from_secs(5))
            .expect("fresh generation fetch");
        inject
            .send(Done::Fetched(
                wanted.clone(),
                Ok(b"Subject: stale\r\n\r\nstale".to_vec()),
                0,
            ))
            .expect("stale duplicate");
        finish_work(&mut workers, &mut app, &source, 0);
        assert_eq!(
            workers.accounts[0].fetching.get(&wanted),
            Some(&app.view_epoch),
            "old result cannot settle the new request"
        );
        inject.send(current).expect("current result");
        finish_work(&mut workers, &mut app, &source, 0);
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(&view.body, Body::Rendered(body) if body.body.as_str() == "new body"))
        );
    }

    #[test]
    fn manual_sync_uses_the_view_but_automatic_sync_still_starts_other_accounts() {
        let (started, starts) = mpsc::channel();
        let (dropped, _drops) = mpsc::channel();
        let remotes = ["acct_a", "acct_b"]
            .iter()
            .map(|name| {
                (
                    account(name),
                    Box::new(PendingRemote {
                        account: account(name),
                        started: started.clone(),
                        dropped: dropped.clone(),
                    }) as Box<dyn super::Remote>,
                )
            })
            .collect();
        let mut workers = Workers::start(remotes).expect("workers");
        let source = Relabeled(
            Vec::new(),
            std::cell::RefCell::new(labeled(&["acct_a", "acct_b", "acct_unavailable"])),
        );
        let mut app = initial_app(&source).expect("All");
        change_view(
            &mut app,
            &source,
            &mut workers,
            ViewScope::Account(account("acct_a")),
        )
        .expect("A");
        assert!(start_sync(&mut workers, &mut app, 0, false));
        assert_eq!(
            starts
                .recv_timeout(Duration::from_secs(5))
                .expect("A starts"),
            account("acct_a")
        );
        assert!(!workers.accounts[1].syncing);
        assert!(start_sync(&mut workers, &mut app, 0, true));
        assert_eq!(
            starts
                .recv_timeout(Duration::from_secs(5))
                .expect("B auto starts"),
            account("acct_b")
        );
        change_view(
            &mut app,
            &source,
            &mut workers,
            ViewScope::Account(account("acct_unavailable")),
        )
        .expect("unavailable");
        assert!(
            !app.syncing(),
            "peers' running state is not this view's state"
        );
        assert!(start_sync(&mut workers, &mut app, 0, false));
        assert!(
            app.status
                .as_deref()
                .expect("status")
                .contains("unavailable")
        );
        assert!(
            workers.accounts.iter().all(|worker| worker.syncing),
            "view changes do not cancel sync"
        );
        change_view(&mut app, &source, &mut workers, ViewScope::All).expect("All");
        assert!(
            !start_sync(&mut workers, &mut app, 0, false),
            "manual All coalesces already-running peers"
        );
    }

    #[test]
    fn unrelated_sync_updates_status_without_replacing_selected_rows_body_or_cursor() {
        use tersa_application::mailbox::{AccountEmail, MailboxStore};
        let fixture = view_fixture();
        let source = &fixture.source;
        let (a, a_done) = mpsc::channel();
        let (b, b_done) = mpsc::channel();
        let mut workers = Workers {
            accounts: vec![
                Worker::fixture(account("acct_a"), a_done, true, HashSet::new()),
                Worker::fixture(account("acct_b"), b_done, true, HashSet::new()),
            ],
        };
        let mut app = initial_app(source).expect("All");
        change_view(
            &mut app,
            source,
            &mut workers,
            ViewScope::Account(account("acct_a")),
        )
        .expect("A");
        let wanted = key("acct_a", "same000");
        app.show_message(
            wanted.clone(),
            Ok(Some(b"Subject: current\r\n\r\ncurrent body".to_vec())),
        );
        drawn(&mut app);
        let old_layout = match &app.screen {
            Screen::Message(view) => view.layout.clone(),
            Screen::Inbox => panic!("message"),
        };
        let old_rows: Vec<_> = app.rows.iter().map(Row::message_key).collect();
        let old_cursor = app.continuation.clone();
        source.stores[1]
            .1
            .as_ref()
            .expect("B store")
            .store_email_address(
                &account("acct_b"),
                &AccountEmail::new("bob@example.com").expect("address"),
            )
            .expect("B profile");
        source.requests.borrow_mut().clear();
        b.send(Done::Synced(
            account("acct_b"),
            Err("authorization required for B".to_owned()),
        ))
        .expect("B completes");
        assert!(finish_work(&mut workers, &mut app, source, 42));
        assert!(
            source.requests.borrow().is_empty(),
            "no query or cursor from B is used in A"
        );
        assert_eq!(
            app.rows.iter().map(Row::message_key).collect::<Vec<_>>(),
            old_rows
        );
        assert_eq!(app.continuation, old_cursor);
        assert_eq!(app.open_key(), Some(&wanted));
        assert!(
            matches!(&app.screen, Screen::Message(view) if view.layout == old_layout && matches!(&view.body, Body::Rendered(body) if body.body.as_str() == "current body"))
        );
        assert_eq!(
            app.account_label(&account("acct_b")),
            "bob@example.com",
            "unrelated label metadata may refresh"
        );
        assert!(
            !drawn(&mut app)
                .join("\n")
                .contains("authorization required for B")
        );
        source
            .executor
            .block_on(
                source.stores[0]
                    .1
                    .as_ref()
                    .expect("A store")
                    .upsert_envelopes(&account("acct_a"), &[sql_envelope("fresh", 20_000)]),
            )
            .expect("A sync metadata");
        a.send(Done::Synced(account("acct_a"), Ok(())))
            .expect("A completes");
        finish_work(&mut workers, &mut app, source, 43);
        assert_eq!(*source.requests.borrow(), [100]);
        assert_eq!(app.rows[0].message_key(), key("acct_a", "fresh"));
        assert!(app.rows.iter().all(|row| row.account == account("acct_a")));
        assert_ne!(app.continuation, old_cursor);
        assert_eq!(app.open_key(), Some(&wanted));
        assert_eq!(app.sync[0].state, SyncState::Synced(43));
        assert!(matches!(app.sync[1].state, SyncState::Failed(_)));
    }
}
