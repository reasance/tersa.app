// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Interface state and key handling, free of terminal I/O so it can be tested.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tersa_application::mailbox::MessageEnvelope;
use tersa_presentation::html::decode_entities;
use tersa_presentation::message::{BodyFormat, BodyPreference, RenderedMessage, render_message};
use tersa_presentation::terminal::SafeText;

/// One inbox row, already sanitized.
#[derive(Clone, Debug)]
pub struct Row {
    pub sender: SafeText,
    pub subject: SafeText,
    pub preview: SafeText,
    pub received_at_millis: i64,
    pub unread: bool,
}

impl Row {
    pub fn from_envelope(envelope: &MessageEnvelope) -> Self {
        Self {
            sender: SafeText::single_line(sender_name(envelope.from().as_str())),
            subject: SafeText::single_line(envelope.subject().as_str()),
            // Gmail's previews arrive HTML-escaped (`&#39;`, `&amp;`).
            preview: SafeText::single_line(&decode_entities(envelope.preview().as_str())),
            received_at_millis: envelope.received_at().as_millis(),
            unread: envelope.is_unread(),
        }
    }
}

/// The display name from a `Name <address>` header, or the address.
///
/// A display name that itself contains `@`, or a character that looks like
/// it, could pose as another address, as in `"security@bank.example"
/// <attacker@evil.example>`, so the real address is shown instead.
fn sender_name(from: &str) -> &str {
    let from = from.trim();
    match from.rsplit_once('<') {
        Some((name, address)) => {
            let name = name.trim().trim_matches('"').trim();
            let address = address.trim_end_matches('>').trim();
            // `@`, the fullwidth `＠`, and the small `﹫`.
            if name.is_empty() || name.contains(['@', '\u{ff20}', '\u{fe6b}']) {
                address
            } else {
                name
            }
        }
        None => from,
    }
}

/// What the message pane shows.
#[derive(Debug)]
pub enum Body {
    /// The full cached message.
    Rendered(Box<RenderedMessage>),
    /// Only the envelope is cached, and no download is possible.
    NotCached,
    /// The full message is being downloaded.
    Downloading,
    /// Downloading the full message failed, with a message for the reader.
    DownloadFailed(String),
    /// Reading the cached message failed.
    Failed,
}

/// An open message and its scroll position.
#[derive(Debug)]
pub struct MessageView {
    pub index: usize,
    pub body: Body,
    /// Raw bytes kept so the format can be switched without another read.
    raw: Option<Vec<u8>>,
    pub preference: BodyPreference,
    pub scroll: usize,
    /// Wrapped lines for the last width drawn, rebuilt when the width changes.
    pub layout: Option<(u16, Vec<super::view::StyledLine>)>,
}

/// The screen in front.
#[derive(Debug)]
pub enum Screen {
    Inbox,
    Message(MessageView),
}

/// Work the interface needs from the outside world.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    /// Load the cached message for the row at this index.
    OpenMessage(usize),
}

/// The whole interface state.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools, reason = "independent interface flags")]
pub struct App {
    pub account: SafeText,
    pub rows: Vec<Row>,
    pub selected: usize,
    /// The first row drawn in the list, kept stable while moving.
    pub list_offset: usize,
    pub screen: Screen,
    pub help: bool,
    pub status: Option<String>,
    pub quit: bool,
    /// Rows or lines that fit on screen, recorded by the last draw.
    pub page: usize,
    pending_g: bool,
    pub preference: BodyPreference,
    /// Set when the screen changes, so the next draw repaints every cell.
    pub repaint: bool,
}

impl App {
    pub fn new(account: SafeText, rows: Vec<Row>) -> Self {
        Self {
            account,
            rows,
            selected: 0,
            list_offset: 0,
            screen: Screen::Inbox,
            help: false,
            status: None,
            quit: false,
            page: 10,
            pending_g: false,
            // Converted HTML reads better than many newsletters' plain parts,
            // and its links are numbered rather than inlined.
            preference: BodyPreference::Html,
            repaint: false,
        }
    }

    /// Handles one key press and returns any work the caller must do.
    pub fn key(&mut self, key: KeyEvent) -> Option<Request> {
        self.status = None;
        if self.help {
            self.help = false;
            return None;
        }
        let pending_g = std::mem::take(&mut self.pending_g);
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if control && matches!(key.code, KeyCode::Char('c')) {
            self.quit = true;
            return None;
        }
        if key.code == KeyCode::Char('?') {
            self.help = true;
            return None;
        }
        let half = (self.page / 2).max(1);
        let motion = match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some(Motion::By(1)),
            KeyCode::Char('k') | KeyCode::Up => Some(Motion::By(-1)),
            KeyCode::Char('d') if control => Some(Motion::By(signed(half))),
            KeyCode::Char('u') if control => Some(Motion::By(-signed(half))),
            KeyCode::PageDown | KeyCode::Char(' ') => Some(Motion::By(signed(self.page.max(1)))),
            KeyCode::PageUp | KeyCode::Char('b') => Some(Motion::By(-signed(self.page.max(1)))),
            KeyCode::Char('g') if pending_g => Some(Motion::Top),
            KeyCode::Home => Some(Motion::Top),
            KeyCode::Char('G') | KeyCode::End => Some(Motion::Bottom),
            KeyCode::Char('g') => {
                self.pending_g = true;
                return None;
            }
            _ => None,
        };
        match &mut self.screen {
            Screen::Inbox => {
                if let Some(motion) = motion {
                    self.selected = motion.apply(self.selected, self.rows.len());
                    return None;
                }
                match key.code {
                    KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right
                        if !self.rows.is_empty() =>
                    {
                        Some(Request::OpenMessage(self.selected))
                    }
                    KeyCode::Char('q') | KeyCode::Esc => {
                        self.quit = true;
                        None
                    }
                    _ => None,
                }
            }
            Screen::Message(view) => {
                if let Some(motion) = motion {
                    let lines = view.layout.as_ref().map_or(0, |(_, lines)| lines.len());
                    let last = lines.saturating_sub(self.page.max(1)) + 1;
                    view.scroll = motion.apply(view.scroll, last);
                    return None;
                }
                match key.code {
                    KeyCode::Char('q' | 'h') | KeyCode::Esc | KeyCode::Left => {
                        self.screen = Screen::Inbox;
                        self.repaint = true;
                        None
                    }
                    KeyCode::Char('n') if view.index + 1 < self.rows.len() => {
                        self.selected = view.index + 1;
                        Some(Request::OpenMessage(self.selected))
                    }
                    KeyCode::Char('p') if view.index > 0 => {
                        self.selected = view.index - 1;
                        Some(Request::OpenMessage(self.selected))
                    }
                    KeyCode::Char('H') => {
                        self.toggle_format();
                        None
                    }
                    _ => None,
                }
            }
        }
    }

    /// Shows the message at `index` with its cached raw bytes, if any.
    pub fn show_message(&mut self, index: usize, raw: Result<Option<Vec<u8>>, ()>) {
        let (body, raw) = match raw {
            Ok(Some(raw)) => (
                Body::Rendered(Box::new(render_message(&raw, self.preference))),
                Some(raw),
            ),
            Ok(None) => (Body::NotCached, None),
            Err(()) => (Body::Failed, None),
        };
        self.selected = index;
        self.repaint = true;
        self.screen = Screen::Message(MessageView {
            index,
            body,
            raw,
            preference: self.preference,
            scroll: 0,
            layout: None,
        });
    }

    /// Marks the open message as downloading.
    pub fn downloading(&mut self, index: usize) {
        if let Screen::Message(view) = &mut self.screen
            && view.index == index
        {
            view.body = Body::Downloading;
            view.layout = None;
            self.repaint = true;
        }
    }

    /// Takes a finished download. It is shown only if that message is still
    /// open; it is cached either way.
    pub fn downloaded(&mut self, index: usize, result: Result<Vec<u8>, String>) {
        let open = matches!(&self.screen, Screen::Message(view) if view.index == index);
        if !open {
            return;
        }
        match result {
            Ok(raw) => self.show_message(index, Ok(Some(raw))),
            Err(error) => {
                if let Screen::Message(view) = &mut self.screen {
                    view.body = Body::DownloadFailed(error);
                    view.layout = None;
                    self.repaint = true;
                }
            }
        }
    }

    fn toggle_format(&mut self) {
        let Screen::Message(view) = &mut self.screen else {
            return;
        };
        let Body::Rendered(rendered) = &view.body else {
            return;
        };
        if !rendered.has_alternative {
            self.status = Some("This message has only one format.".to_owned());
            return;
        }
        let next = match rendered.format {
            Some(BodyFormat::Html) => BodyPreference::Plain,
            _ => BodyPreference::Html,
        };
        if let Some(raw) = &view.raw {
            view.body = Body::Rendered(Box::new(render_message(raw, next)));
            view.preference = next;
            view.scroll = 0;
            view.layout = None;
            self.preference = next;
            self.repaint = true;
        }
    }
}

#[derive(Clone, Copy)]
enum Motion {
    By(isize),
    Top,
    Bottom,
}

impl Motion {
    /// Moves `position` within `0..len`.
    fn apply(self, position: usize, len: usize) -> usize {
        let last = len.saturating_sub(1);
        match self {
            Self::Top => 0,
            Self::Bottom => last,
            Self::By(delta) => position.saturating_add_signed(delta).min(last),
        }
    }
}

fn signed(value: usize) -> isize {
    isize::try_from(value).unwrap_or(isize::MAX)
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use tersa_presentation::terminal::SafeText;

    use super::{App, Body, Request, Row, Screen, sender_name};

    fn row(subject: &str) -> Row {
        Row {
            sender: SafeText::single_line("Sender"),
            subject: SafeText::single_line(subject),
            preview: SafeText::single_line("preview"),
            received_at_millis: 0,
            unread: true,
        }
    }

    fn press(app: &mut App, code: KeyCode) -> Option<Request> {
        app.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn app(rows: usize) -> App {
        App::new(
            SafeText::single_line("acct"),
            (0..rows).map(|index| row(&format!("s{index}"))).collect(),
        )
    }

    #[test]
    fn previews_are_unescaped_then_sanitized() {
        let envelope = tersa_application::mailbox::MessageEnvelope::new(
            tersa_application::mailbox::MessageId::new("m").expect("id"),
            tersa_application::mailbox::ThreadId::new("t").expect("thread"),
            tersa_application::mailbox::HeaderText::new("A <a@example.com>").expect("from"),
            tersa_application::mailbox::HeaderText::new("s").expect("subject"),
            tersa_application::mailbox::HeaderText::new("I don&#39;t &amp; &#27;[2J")
                .expect("preview"),
            tersa_application::mailbox::UnixTimestampMillis::new(0).expect("time"),
            false,
        );
        assert_eq!(
            Row::from_envelope(&envelope).preview.as_str(),
            "I don't & [2J"
        );
    }

    #[test]
    fn sender_names_come_from_the_display_name() {
        assert_eq!(sender_name("Ann Example <ann@example.com>"), "Ann Example");
        assert_eq!(sender_name("\"Bob, Jr\" <bob@example.com>"), "Bob, Jr");
        assert_eq!(sender_name("<carol@example.com>"), "carol@example.com");
        assert_eq!(sender_name("dave@example.com"), "dave@example.com");
        assert_eq!(
            sender_name("\"security@bank.example\" <attacker@evil.example>"),
            "attacker@evil.example",
            "a name that looks like an address gives way to the address"
        );
        for lookalike in ['\u{ff20}', '\u{fe6b}'] {
            assert_eq!(
                sender_name(&format!(
                    "security{lookalike}bank.example <attacker@evil.example>"
                )),
                "attacker@evil.example",
                "{lookalike:?}"
            );
        }
    }

    #[test]
    fn list_motion_stays_in_bounds() {
        let mut app = app(3);
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.selected, 0);
        press(&mut app, KeyCode::Char('G'));
        assert_eq!(app.selected, 2);
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.selected, 2);
        press(&mut app, KeyCode::Char('g'));
        assert_eq!(app.selected, 2, "a single g waits for the second");
        press(&mut app, KeyCode::Char('g'));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn opening_and_leaving_a_message() {
        let mut app = app(2);
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(
            press(&mut app, KeyCode::Enter),
            Some(Request::OpenMessage(1))
        );
        app.show_message(1, Ok(None));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::NotCached))
        );
        assert_eq!(
            press(&mut app, KeyCode::Char('p')),
            Some(Request::OpenMessage(0))
        );
        press(&mut app, KeyCode::Char('q'));
        assert!(matches!(app.screen, Screen::Inbox));
        press(&mut app, KeyCode::Char('q'));
        assert!(app.quit);
    }

    #[test]
    fn downloads_land_only_on_the_message_still_open() {
        let mut app = app(2);
        app.show_message(0, Ok(None));
        app.downloading(0);
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::Downloading))
        );
        app.downloaded(1, Ok(b"Subject: other\r\n\r\nx".to_vec()));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::Downloading))
        );
        app.downloaded(0, Ok(b"Subject: s\r\n\r\nfull body".to_vec()));
        let Screen::Message(view) = &app.screen else {
            panic!("message screen");
        };
        let Body::Rendered(rendered) = &view.body else {
            panic!("rendered");
        };
        assert_eq!(rendered.body.as_str(), "full body");
        app.show_message(1, Ok(None));
        app.downloaded(1, Err("offline".to_owned()));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(&view.body, Body::DownloadFailed(error) if error == "offline"))
        );
    }

    #[test]
    fn an_empty_inbox_opens_nothing() {
        let mut app = app(0);
        assert_eq!(press(&mut app, KeyCode::Enter), None);
        press(&mut app, KeyCode::Char('G'));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn switching_format_rerenders_from_the_cached_bytes() {
        let raw = b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\
Content-Type: text/plain\r\n\r\nplain body\r\n--b\r\nContent-Type: text/html\r\n\r\n\
<p>html body</p>\r\n--b--\r\n";
        let mut app = app(1);
        app.show_message(0, Ok(Some(raw.to_vec())));
        let body = |app: &App| {
            let Screen::Message(view) = &app.screen else {
                panic!("message screen");
            };
            let Body::Rendered(rendered) = &view.body else {
                panic!("rendered");
            };
            rendered.body.as_str().to_owned()
        };
        assert_eq!(body(&app), "html body", "HTML is the default");
        press(&mut app, KeyCode::Char('H'));
        assert_eq!(body(&app), "plain body");
    }

    #[test]
    fn help_closes_on_any_key_and_ctrl_c_quits() {
        let mut app = app(1);
        press(&mut app, KeyCode::Char('?'));
        assert!(app.help);
        press(&mut app, KeyCode::Char('x'));
        assert!(!app.help);
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.quit);
    }
}
