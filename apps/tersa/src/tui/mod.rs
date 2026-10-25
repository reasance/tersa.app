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
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use tersa_presentation::terminal::SafeText;

pub use app::Row;
use app::{App, Request};

/// Where the interface reads cached mail from.
pub trait MailSource {
    /// The cached raw message for the row at `index`; `Ok(None)` when only
    /// the envelope is cached.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the local store cannot be read.
    fn message(&self, index: usize) -> Result<Option<Vec<u8>>, ()>;
}

/// Downloads full messages; runs on its own thread so the interface stays
/// responsive while the network is slow.
pub trait Fetcher: Send + 'static {
    /// Downloads, caches, and returns the raw message for the row at `index`.
    ///
    /// # Errors
    ///
    /// Returns a short reason for the reader.
    fn fetch(&mut self, index: usize) -> Result<Vec<u8>, String>;
}

/// How often the loop checks for finished downloads while idle.
const TICK: Duration = Duration::from_millis(100);

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
/// Returns a message when standard input or output is not a terminal, or the
/// terminal fails.
pub fn run(
    account: SafeText,
    rows: Vec<Row>,
    source: &dyn MailSource,
    fetcher: Option<Box<dyn Fetcher>>,
) -> Result<(), String> {
    require_terminal()?;
    let mut app = App::new(account, rows);
    let downloads = fetcher.map(Downloads::start);
    // Installs a panic hook that restores the terminal before reporting.
    let mut terminal = ratatui::try_init().map_err(terminal_error)?;
    let result = event_loop(&mut terminal, &mut app, source, downloads);
    ratatui::restore();
    result
}

/// The download thread's channels. Dropping it ends the thread after its
/// current download; the process does not wait for it.
struct Downloads {
    requests: Sender<usize>,
    results: Receiver<(usize, Result<Vec<u8>, String>)>,
    in_flight: HashSet<usize>,
}

impl Downloads {
    fn start(mut fetcher: Box<dyn Fetcher>) -> Self {
        let (requests, incoming) = mpsc::channel::<usize>();
        let (outgoing, results) = mpsc::channel();
        std::thread::spawn(move || {
            for index in incoming {
                let result = fetcher.fetch(index);
                if outgoing.send((index, result)).is_err() {
                    break;
                }
            }
        });
        Self {
            requests,
            results,
            in_flight: HashSet::new(),
        }
    }

    /// Asks for `index`; returns false when the thread is gone.
    fn request(&mut self, index: usize) -> bool {
        if self.in_flight.contains(&index) {
            return true;
        }
        let sent = self.requests.send(index).is_ok();
        if sent {
            self.in_flight.insert(index);
        }
        sent
    }
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    source: &dyn MailSource,
    mut downloads: Option<Downloads>,
) -> Result<(), String> {
    loop {
        if let Some(downloads) = &mut downloads {
            while let Ok((index, result)) = downloads.results.try_recv() {
                downloads.in_flight.remove(&index);
                app.downloaded(index, result);
            }
        }
        let now = now_millis();
        if std::mem::take(&mut app.repaint) {
            // Repaint every cell when the screen changes, so any drift
            // between the terminal and ratatui's model cannot linger.
            terminal.clear().map_err(terminal_error)?;
        }
        terminal
            .draw(|frame| view::draw(frame, app, now))
            .map_err(terminal_error)?;
        if app.quit {
            return Ok(());
        }
        if !event::poll(TICK).map_err(terminal_error)? {
            continue;
        }
        if let Event::Key(key) = event::read().map_err(terminal_error)? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if let Some(Request::OpenMessage(index)) = app.key(key) {
                let raw = source.message(index);
                let missing = matches!(raw, Ok(None));
                app.show_message(index, raw);
                if missing
                    && downloads
                        .as_mut()
                        .is_some_and(|downloads| downloads.request(index))
                {
                    app.downloading(index);
                }
            }
        }
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
