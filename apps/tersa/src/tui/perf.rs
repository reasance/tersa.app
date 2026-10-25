// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The ADR 0031 performance budgets, measured on a full cache: an encrypted
//! store holding 10,000 envelopes (the most a cache can keep; the default
//! sync policy keeps 100) and 25 bodies.
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
//! - The first frame is the fastest of five runs in process, from opening the
//!   store to a draw into ratatui's test backend. Process start, the keyring
//!   read and writing to a real terminal come on top of it.
//! - The idle resident size is that of this test binary in a fresh process
//!   that does what the interface does. The test binary links the test
//!   harness as well, so the product binary is no larger.
//! - The budget on the stripped release binary is not checked here: it is
//!   the size of `target/release/tersa`, which the release profile strips.

#![expect(clippy::unwrap_used, reason = "a benchmark fixture that must build")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tersa_application::mailbox::{
    AccountId, HeaderText, MailboxReader, MailboxStore, Message, MessageContent, MessageEnvelope,
    MessageId, StoreLimit, ThreadId, UnixTimestampMillis,
};
use tersa_presentation::terminal::SafeText;
use tersa_store_sqlcipher::{DatabaseKey, IntegrityScan, SqlCipherMailboxStore};

use super::app::App;
use super::{FIRST_PAGE, PAGE, load_page, read_page, view};
use crate::commands::StoreSource;

/// ADR 0031 budgets.
const FIRST_FRAME: Duration = Duration::from_millis(100);
const TOP_50: Duration = Duration::from_millis(20);
const IDLE_RSS_MIB: f64 = 50.0;

const MESSAGES: usize = 10_000;
const BODIES: usize = 25;

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

fn source(store: SqlCipherMailboxStore) -> StoreSource<SqlCipherMailboxStore> {
    StoreSource {
        store,
        account: account(),
        executor: tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    }
}

fn rss_mib() -> f64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    let kib: f64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap();
    kib / 1024.0
}

/// The best of `runs` timings of `work`, which is what a warm process sees.
fn best<T>(runs: usize, mut work: impl FnMut() -> T) -> (Duration, T) {
    let mut fastest = Duration::MAX;
    let mut last = None;
    for _ in 0..runs {
        let start = Instant::now();
        let value = work();
        fastest = fastest.min(start.elapsed());
        last = Some(value);
    }
    (fastest, last.unwrap())
}

fn report(name: &str, measured: Duration, budget: Option<Duration>) {
    match budget {
        Some(budget) => println!("{name}: {measured:.2?} (budget {budget:?})"),
        None => println!("{name}: {measured:.2?}"),
    }
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

    let (full_open, _) = best(3, || open(&fixture.path, IntegrityScan::Full));
    let (open_time, store) = best(5, || open(&fixture.path, IntegrityScan::Skip));
    report("open with the integrity scan", full_open, None);
    report("open without it", open_time, None);

    let limit = StoreLimit::new(50).unwrap();
    let (top_50, rows) = best(20, || {
        block_on(store.list_envelopes_after(&account(), None, limit)).unwrap()
    });
    assert_eq!(rows.len(), 50);
    report("top-50 query", top_50, Some(TOP_50));
    check(top_50, TOP_50, "top-50 query");

    let warm = source(store);
    let (first_frame, mut app) = best(5, || {
        let fresh = source(open(&fixture.path, IntegrityScan::Skip));
        let (rows, more) = read_page(&fresh, None, FIRST_PAGE).unwrap();
        let mut app = App::new(SafeText::single_line("acct_perf"), rows);
        app.more_rows = more;
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal
            .draw(|frame| view::draw(frame, &mut app, 1_761_000_000_000))
            .unwrap();
        app
    });
    report(
        "first frame (open, first page, draw)",
        first_frame,
        Some(FIRST_FRAME),
    );
    check(first_frame, FIRST_FRAME, "first frame");

    let mut slowest_page = Duration::ZERO;
    let loading = Instant::now();
    while app.more_rows {
        let start = Instant::now();
        load_page(&mut app, &warm);
        slowest_page = slowest_page.max(start.elapsed());
    }
    assert_eq!(app.rows.len(), MESSAGES);
    report("load the other 9,900 rows", loading.elapsed(), None);
    report(&format!("slowest page of {PAGE}"), slowest_page, None);

    let loaded = u16::try_from(MESSAGES).unwrap();
    let (reload, (rows, _more)) = best(3, || read_page(&warm, None, loaded).unwrap());
    assert_eq!(rows.len(), MESSAGES);
    report("reload all rows after a sync", reload, None);

    let (search, ()) = best(5, || {
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
    report("type a 9-character search over 10,000 rows", search, None);

    drop(rows);

    // The fixture and the timings above allocated a lot in this process, so
    // the resident size is measured in a fresh one that does only what the
    // interface does: open the store, load every row, draw.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tui::perf::perf_idle_rss_child",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_DATABASE, &fixture.path)
        .output()
        .unwrap();
    let printed = String::from_utf8_lossy(&output.stdout);
    let rss: f64 = printed
        .lines()
        .find_map(|line| line.strip_prefix("RSS_MIB="))
        .unwrap_or_else(|| panic!("the child printed no RSS: {printed}"))
        .parse()
        .unwrap();
    println!("idle RSS with 10,000 rows loaded: {rss:.1} MiB (budget {IDLE_RSS_MIB} MiB)");
    if !cfg!(debug_assertions) {
        assert!(rss < IDLE_RSS_MIB, "RSS {rss:.1} MiB");
    }
}

/// Where [`perf_full_cache_budgets`] tells its child process the fixture is.
const CHILD_DATABASE: &str = "TERSA_PERF_DATABASE";

#[test]
#[ignore = "performance: started by perf_full_cache_budgets"]
fn perf_idle_rss_child() {
    let Some(path) = std::env::var_os(CHILD_DATABASE) else {
        println!("perf_idle_rss_child measures only when perf_full_cache_budgets starts it");
        return;
    };
    let source = source(open(std::path::Path::new(&path), IntegrityScan::Skip));
    let (rows, more) = read_page(&source, None, FIRST_PAGE).unwrap();
    let mut app = App::new(SafeText::single_line("acct_perf"), rows);
    app.more_rows = more;
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
