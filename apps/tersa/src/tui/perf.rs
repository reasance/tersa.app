// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The ADR 0031 performance budgets, measured on a full cache: an encrypted
//! store holding 10,000 envelopes (the most a cache can keep; the default
//! sync policy keeps 100) and 25 bodies. A second case reads five accounts'
//! caches of 2,000 envelopes each, whose timestamps interleave, as one
//! merged list. First frames request 100 global rows (per-account probes 101);
//! later pages and reloads request at most 200 (per-account probes at most 201).
//!
//! These tests are ignored by default and kept out of CI, which is for
//! correctness. Run them on a release build:
//!
//! ```text
//! cargo test --release -p tersa perf -- --ignored --nocapture --test-threads=1
//! ```
//!
//! What they measure, and what they leave out:
//!
//! - The first frame is timed five times in process, from opening the
//!   store and starting account workers to a draw into ratatui's test backend. Process start, the keyring
//!   read and writing to a real terminal come on top of it. The budgets
//!   are checked against the slowest run, the first frame's and the
//!   top-50 query's alike.
//! - The idle resident size is that of this test binary in a fresh process
//!   that loads the cache and starts one or five production workers with
//!   controlled pending futures. No live network is included. It links the test
//!   harness as well, so the product binary is no larger.
//! - The budget on the stripped release binary is not checked here: it is
//!   the size of `target/release/tersa`, which the release profile strips.

#![expect(clippy::unwrap_used, reason = "a benchmark fixture that must build")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tersa_application::mailbox::{
    AccountEmail, AccountId, HeaderText, MailboxReader, MailboxStore, Message, MessageContent,
    MessageEnvelope, MessageId, StoreLimit, ThreadId, UnixTimestampMillis,
};
use tersa_store_sqlcipher::{DatabaseKey, IntegrityScan, SqlCipherMailboxStore};

use super::{PAGE, load_page, view};
use crate::commands::StoreSource;

/// ADR 0031 budgets.
const FIRST_FRAME: Duration = Duration::from_millis(100);
const TOP_50: Duration = Duration::from_millis(20);
const IDLE_RSS_MIB: f64 = 50.0;

const MESSAGES: usize = 10_000;
const BODIES: usize = 25;

/// The multi-account case: this many caches of [`ACCOUNT_MESSAGES`]
/// envelopes each, whose timestamps interleave, in one merged list.
const ACCOUNTS: usize = 5;
const ACCOUNT_MESSAGES: usize = 2_000;

/// A temporary directory removed when dropped.
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}

impl Fixture {
    /// Builds the full cache once per test.
    fn build() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "tersa-perf-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("mail.sqlite3");
        let store = open(&path, IntegrityScan::Full);
        let envelopes: Vec<MessageEnvelope> = (0..MESSAGES).map(envelope).collect();
        block_on(store.upsert_envelopes(&account(), &envelopes)).unwrap();
        for envelope in envelopes.iter().take(BODIES) {
            let body = format!(
                "Subject: {}\r\nContent-Type: text/html\r\n\r\n{}",
                envelope.subject().as_str(),
                "<p>A paragraph of a newsletter, with <a href=\"https://example.com/x\">a link</a>.</p>"
                    .repeat(600)
            );
            let content = MessageContent::new(body.into_bytes()).unwrap();
            block_on(store.put_message(&account(), &Message::new(envelope.clone(), content)))
                .unwrap();
        }
        Self { directory, path }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn account() -> AccountId {
    AccountId::new("acct_perf").unwrap()
}

fn open(path: &std::path::Path, scan: IntegrityScan) -> SqlCipherMailboxStore {
    SqlCipherMailboxStore::open_with_scan(account(), path, DatabaseKey::new([7; 32]), scan).unwrap()
}

/// Envelope `index`, newest first, with Gmail-like field sizes.
fn envelope(index: usize) -> MessageEnvelope {
    MessageEnvelope::new(
        MessageId::new(format!("19a{index:013x}")).unwrap(),
        ThreadId::new(format!("19b{:013x}", index / 3)).unwrap(),
        HeaderText::new(format!(
            "Sender Number {index} <sender{index}@newsletter.example>"
        ))
        .unwrap(),
        HeaderText::new(format!(
            "Weekly update {index}: what changed, what is next, and three links"
        ))
        .unwrap(),
        HeaderText::new(format!(
            "Hello reader, this is the preview of message {index}. It runs about as long as \
             Gmail's previews do, with a few clauses, a date, and a sign-off at the end. {}",
            "More words follow. ".repeat(4)
        ))
        .unwrap(),
        UnixTimestampMillis::new(1_761_000_000_000 - i64::try_from(index).unwrap() * 60_000)
            .unwrap(),
        index.is_multiple_of(7),
    )
}

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

fn source(store: SqlCipherMailboxStore) -> StoreSource {
    StoreSource {
        stores: vec![(account(), Some(store))],
        requests: std::cell::RefCell::default(),
        executor: tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    }
}

fn multi_account(number: usize) -> AccountId {
    AccountId::new(format!("acct_perf_{number}")).unwrap()
}

/// The multi-account fixture: one cache per account, each holding its share
/// of the envelopes so the merged list interleaves them, and one stored
/// Gmail address for its label.
struct AccountsFixture {
    directory: PathBuf,
    paths: Vec<PathBuf>,
}

impl AccountsFixture {
    /// Builds the caches once per test.
    fn build() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "tersa-perf-multi-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let mut paths = Vec::new();
        for number in 0..ACCOUNTS {
            let account = multi_account(number);
            let path = directory.join(format!("mail{number}.sqlite3"));
            let store = SqlCipherMailboxStore::open_with_scan(
                account.clone(),
                &path,
                DatabaseKey::new([7; 32]),
                IntegrityScan::Full,
            )
            .unwrap();
            // Every account holds every `ACCOUNTS`-th envelope, so the
            // timestamps of the caches interleave in the merged order.
            let envelopes: Vec<MessageEnvelope> = (0..ACCOUNT_MESSAGES)
                .map(|index| envelope(index * ACCOUNTS + number))
                .collect();
            block_on(store.upsert_envelopes(&account, &envelopes)).unwrap();
            store
                .store_email_address(
                    &account,
                    &AccountEmail::new(format!("reader{number}@newsletter.example")).unwrap(),
                )
                .unwrap();
            paths.push(path);
        }
        Self { directory, paths }
    }

    /// One store per account, opened like the interface opens them.
    fn open_store(&self, number: usize) -> SqlCipherMailboxStore {
        SqlCipherMailboxStore::open_with_scan(
            multi_account(number),
            &self.paths[number],
            DatabaseKey::new([7; 32]),
            IntegrityScan::Skip,
        )
        .unwrap()
    }

    /// The source over every cache, as `tersa` builds it.
    fn source(&self) -> StoreSource {
        StoreSource {
            stores: (0..ACCOUNTS)
                .map(|number| (multi_account(number), Some(self.open_store(number))))
                .collect(),
            requests: std::cell::RefCell::default(),
            executor: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        }
    }
}

impl Drop for AccountsFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Starts the production worker machinery with controlled, pending network
/// futures. No provider, credentials, DNS or real socket is involved.
fn idle_workers(app: &mut super::app::App, wait_for_start: bool) -> super::worker::Workers {
    struct Idle(std::sync::mpsc::Sender<()>);
    impl super::Remote for Idle {
        fn fetch<'a>(&'a self, _: &'a AccountId, _: &'a MessageId) -> super::Pending<'a, Vec<u8>> {
            Box::pin(std::future::pending())
        }
        fn sync<'a>(&'a self, _: &'a AccountId) -> super::Pending<'a, ()> {
            Box::pin(async move {
                let _ = self.0.send(());
                std::future::pending().await
            })
        }
    }
    let (started, starts) = std::sync::mpsc::channel();
    let remotes = app
        .accounts
        .iter()
        .map(|(account, _)| {
            (
                account.clone(),
                Box::new(Idle(started.clone())) as Box<dyn super::Remote>,
            )
        })
        .collect();
    let mut workers = super::worker::Workers::start(remotes).unwrap();
    super::start_sync(&mut workers, app, 1_761_000_000_000, false);
    if wait_for_start {
        for _ in &app.accounts {
            starts.recv_timeout(Duration::from_secs(5)).unwrap();
        }
    }
    workers
}

fn idle_rss(path: &std::path::Path, multi: bool) -> f64 {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.args([
        "--exact",
        "tui::perf::perf_idle_rss_child",
        "--ignored",
        "--nocapture",
    ]);
    child.env_remove(if multi {
        CHILD_DATABASE
    } else {
        CHILD_ACCOUNTS
    });
    child.env(
        if multi {
            CHILD_ACCOUNTS
        } else {
            CHILD_DATABASE
        },
        path,
    );
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "RSS child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8_lossy(&output.stdout);
    printed
        .lines()
        .find_map(|line| line.strip_prefix("RSS_MIB="))
        .unwrap_or_else(|| panic!("child printed no RSS: {printed}"))
        .parse()
        .unwrap()
}

fn rss_mib() -> f64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let kib: f64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap();
    kib / 1024.0
}

/// The fastest and the slowest of `runs` timings of `work`, and the value
/// of the last run. Budgets are checked against the slowest.
fn timed<T>(runs: usize, mut work: impl FnMut() -> T) -> (Duration, Duration, T) {
    let mut fastest = Duration::MAX;
    let mut slowest = Duration::ZERO;
    let mut last = None;
    for _ in 0..runs {
        let start = Instant::now();
        let value = work();
        let elapsed = start.elapsed();
        fastest = fastest.min(elapsed);
        slowest = slowest.max(elapsed);
        last = Some(value);
    }
    (fastest, slowest, last.unwrap())
}

fn report(name: &str, measured: Duration) {
    println!("{name}: {measured:.2?}");
}

/// Prints the fastest and slowest runs and checks the slowest.
fn report_budget(name: &str, fastest: Duration, slowest: Duration, budget: Duration) {
    println!("{name}: {fastest:.2?} fastest, {slowest:.2?} slowest (budget {budget:?})");
    check(slowest, budget, name);
}

/// Budgets hold only for optimized builds; a debug run just prints.
fn check(measured: Duration, budget: Duration, name: &str) {
    if !cfg!(debug_assertions) {
        assert!(measured < budget, "{name}: {measured:?} over {budget:?}");
    }
}

#[test]
#[ignore = "performance: run on a release build, see the module documentation"]
fn perf_full_cache_budgets() {
    let fixture = Fixture::build();

    let (full_open, _, _) = timed(3, || open(&fixture.path, IntegrityScan::Full));
    let (open_time, _, store) = timed(5, || open(&fixture.path, IntegrityScan::Skip));
    report("open with the integrity scan", full_open);
    report("open without it", open_time);

    let limit = StoreLimit::new(50).unwrap();
    let (top_50, top_50_slowest, rows) = timed(20, || {
        block_on(store.list_envelopes_after(&account(), None, limit)).unwrap()
    });
    assert_eq!(rows.len(), 50);
    report_budget("top-50 query", top_50, top_50_slowest, TOP_50);

    let warm = source(store);
    let (first_frame, first_frame_slowest, (mut app, _workers)) = timed(5, || {
        let fresh = source(open(&fixture.path, IntegrityScan::Skip));
        let mut app = super::initial_app(&fresh).unwrap();
        let workers = idle_workers(&mut app, false);
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal
            .draw(|frame| view::draw(frame, &mut app, 1_761_000_000_000))
            .unwrap();
        (app, workers)
    });
    report_budget(
        "first frame (open, worker start, global 100, per-account probe 101, draw)",
        first_frame,
        first_frame_slowest,
        FIRST_FRAME,
    );

    let mut slowest_page = Duration::ZERO;
    let loading = Instant::now();
    while app.more_rows {
        let start = Instant::now();
        load_page(&mut app, &warm);
        slowest_page = slowest_page.max(start.elapsed());
    }
    assert_eq!(app.rows.len(), MESSAGES);
    report("load the other 9,900 rows", loading.elapsed());
    report(&format!("slowest page of {PAGE}"), slowest_page);

    let (reload, _, reloaded) = timed(3, || super::read_rows(&warm, MESSAGES).unwrap());
    assert_eq!(reloaded.rows.len(), MESSAGES);
    assert!(warm.requests.borrow().iter().all(|size| *size <= 200));
    println!("global pages <=200; per-account query probes <=201; reload uses bounded pages");
    report("reload all rows after a sync", reload);

    let (search, _, ()) = timed(5, || {
        app.key(ratatui::crossterm::event::KeyEvent::new(
            ratatui::crossterm::event::KeyCode::Char('/'),
            ratatui::crossterm::event::KeyModifiers::NONE,
        ));
        for character in "update 99".chars() {
            app.key(ratatui::crossterm::event::KeyEvent::new(
                ratatui::crossterm::event::KeyCode::Char(character),
                ratatui::crossterm::event::KeyModifiers::NONE,
            ));
        }
        app.key(ratatui::crossterm::event::KeyEvent::new(
            ratatui::crossterm::event::KeyCode::Esc,
            ratatui::crossterm::event::KeyModifiers::NONE,
        ));
    });
    report("type a 9-character search over 10,000 rows", search);

    drop(reloaded);

    // The fixture and the timings above allocated a lot in this process, so
    // the resident size is measured in a fresh one that does only what the
    // interface does: open the store, load every row, draw.
    let rss = idle_rss(&fixture.path, false);
    println!(
        "idle RSS with one worker and 10,000 rows loaded: {rss:.1} MiB (budget {IDLE_RSS_MIB} MiB)"
    );
    if !cfg!(debug_assertions) {
        assert!(rss < IDLE_RSS_MIB, "RSS {rss:.1} MiB");
    }
}

#[test]
#[ignore = "performance: run on a release build, see the module documentation"]
fn perf_five_account_budgets() {
    let fixture = AccountsFixture::build();

    // The merged first frame opens every store, reads one page from each,
    // and draws, against the same budget as one account.
    let (first_frame, first_frame_slowest, (mut app, mut workers)) = timed(5, || {
        let fresh = fixture.source();
        let mut app = super::initial_app(&fresh).unwrap();
        let workers = idle_workers(&mut app, false);
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal
            .draw(|frame| view::draw(frame, &mut app, 1_761_000_000_000))
            .unwrap();
        (app, workers)
    });
    report_budget(
        &format!(
            "first frame, {ACCOUNTS} accounts (open, worker start, global 100, per-account probe 101, draw)"
        ),
        first_frame,
        first_frame_slowest,
        FIRST_FRAME,
    );

    let warm = fixture.source();
    let mut slowest_page = Duration::ZERO;
    while app.more_rows {
        let start = Instant::now();
        load_page(&mut app, &warm);
        slowest_page = slowest_page.max(start.elapsed());
    }
    assert_eq!(app.rows.len(), ACCOUNTS * ACCOUNT_MESSAGES);
    assert!(warm.requests.borrow().iter().all(|size| *size <= 200));
    let (reload, _, reloaded) = timed(3, || {
        super::read_rows(&warm, ACCOUNTS * ACCOUNT_MESSAGES).unwrap()
    });
    assert_eq!(reloaded.rows.len(), ACCOUNTS * ACCOUNT_MESSAGES);
    report(
        "reload five-account total 10,000 rows in global pages <=200 (probes <=201)",
        reload,
    );
    report(
        &format!("slowest page of {PAGE} across {ACCOUNTS} accounts"),
        slowest_page,
    );
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut slowest_switch = Duration::ZERO;
    for _ in 0..5 {
        for scope in [
            super::ViewScope::Account(multi_account(0)),
            super::ViewScope::Account(multi_account(1)),
            super::ViewScope::All,
        ] {
            let start = Instant::now();
            super::change_view(&mut app, &warm, &mut workers, scope).unwrap();
            terminal
                .draw(|frame| view::draw(frame, &mut app, 1_761_000_000_000))
                .unwrap();
            slowest_switch = slowest_switch.max(start.elapsed());
        }
    }
    report(
        "slowest All/account view change (fresh global 100 / probes <=101, draw)",
        slowest_switch,
    );
    check(slowest_switch, FIRST_FRAME, "view-change first frame");
    let rss = idle_rss(&fixture.directory, true);
    println!(
        "idle RSS with five workers and total 10,000 rows: {rss:.1} MiB (budget {IDLE_RSS_MIB} MiB)"
    );
    if !cfg!(debug_assertions) {
        assert!(rss < IDLE_RSS_MIB, "five-worker RSS {rss:.1} MiB");
    }
}

/// Where [`perf_full_cache_budgets`] tells its child process the fixture is.
const CHILD_DATABASE: &str = "TERSA_PERF_DATABASE";
/// Five-account fixture path, opened without taking ownership of its cleanup.
const CHILD_ACCOUNTS: &str = "TERSA_PERF_ACCOUNTS";

#[test]
#[ignore = "performance: started by perf_full_cache_budgets"]
fn perf_idle_rss_child() {
    let source = if let Some(directory) = std::env::var_os(CHILD_ACCOUNTS) {
        let directory = PathBuf::from(directory);
        StoreSource {
            stores: (0..ACCOUNTS)
                .map(|number| {
                    (
                        multi_account(number),
                        Some(
                            SqlCipherMailboxStore::open_with_scan(
                                multi_account(number),
                                directory.join(format!("mail{number}.sqlite3")),
                                DatabaseKey::new([7; 32]),
                                IntegrityScan::Skip,
                            )
                            .unwrap(),
                        ),
                    )
                })
                .collect(),
            requests: std::cell::RefCell::default(),
            executor: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        }
    } else if let Some(path) = std::env::var_os(CHILD_DATABASE) {
        source(open(std::path::Path::new(&path), IntegrityScan::Skip))
    } else {
        println!("perf_idle_rss_child measures only when a parent starts it");
        return;
    };
    let mut app = super::initial_app(&source).unwrap();
    let _workers = idle_workers(&mut app, true);
    while app.more_rows {
        load_page(&mut app, &source);
    }
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    terminal
        .draw(|frame| view::draw(frame, &mut app, 1_761_000_000_000))
        .unwrap();
    assert_eq!(app.rows.len(), MESSAGES);
    println!("RSS_MIB={:.1}", rss_mib());
}
