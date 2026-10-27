// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Interface state and key handling, free of terminal I/O so it can be tested.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tersa_application::mailbox::{AccountId, MessageEnvelope, MessageId};
use tersa_presentation::html::decode_entities;
use tersa_presentation::message::{BodyFormat, BodyPreference, RenderedMessage, render_message};
use tersa_presentation::terminal::SafeText;

/// The longest search query, in bytes.
const MAX_QUERY_LEN: usize = 256;

/// One message of one account. Gmail identifiers are only unique within one
/// mailbox, so everything that names a message goes through both.
pub type MessageKey = (AccountId, MessageId);

/// One inbox row, already sanitized.
#[derive(Clone, Debug)]
pub struct Row {
    pub account: AccountId,
    pub id: MessageId,
    pub sender: SafeText,
    pub subject: SafeText,
    pub preview: SafeText,
    pub received_at_millis: i64,
    pub unread: bool,
    /// The lowercased text a search looks through: the full sender, the
    /// subject, and the preview.
    haystack: String,
}

impl Row {
    pub fn from_envelope(envelope: &MessageEnvelope, account: &AccountId) -> Self {
        let from = SafeText::single_line(envelope.from().as_str());
        Self::new(
            account.clone(),
            envelope.message_id().clone(),
            &from,
            SafeText::single_line(sender_name(from.as_str())),
            SafeText::single_line(envelope.subject().as_str()),
            // Gmail's previews arrive HTML-escaped (`&#39;`, `&amp;`).
            SafeText::single_line(&decode_entities(envelope.preview().as_str())),
            envelope.received_at().as_millis(),
            envelope.is_unread(),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one row's fields, each of them needed"
    )]
    fn new(
        account: AccountId,
        id: MessageId,
        from: &SafeText,
        sender: SafeText,
        subject: SafeText,
        preview: SafeText,
        received_at_millis: i64,
        unread: bool,
    ) -> Self {
        let haystack = format!(
            "{}\n{}\n{}",
            from.as_str(),
            subject.as_str(),
            preview.as_str()
        )
        .to_lowercase();
        Self {
            account,
            id,
            sender,
            subject,
            preview,
            received_at_millis,
            unread,
            haystack,
        }
    }

    /// Whether every lowercased word appears in this row.
    fn matches(&self, words: &[String]) -> bool {
        words
            .iter()
            .all(|word| self.haystack.contains(word.as_str()))
    }

    /// The row's account and identifier, the key a request or a download
    /// goes through.
    pub fn message_key(&self) -> MessageKey {
        (self.account.clone(), self.id.clone())
    }

    #[cfg(test)]
    pub fn sample(account: &str, id: &str, sender: &str, subject: &str, unread: bool) -> Self {
        let sender = SafeText::single_line(sender);
        Self::new(
            AccountId::new(account).expect("account"),
            MessageId::new(id).expect("id"),
            &sender,
            sender.clone(),
            SafeText::single_line(subject),
            SafeText::single_line("the preview"),
            1_760_990_000_000,
            unread,
        )
    }
}

/// The short form of an account label shown before the sender when several
/// accounts share one list: the label up to (not including) its `@`, or the
/// whole label when it has none.
pub fn account_tag(label: &str) -> &str {
    match label.split_once('@') {
        Some((name, _)) => name,
        None => label,
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
    pub key: MessageKey,
    pub body: Body,
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

/// The background sync, as the top bar reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncState {
    /// No sync has run in this session, or none is possible.
    Idle,
    Running,
    /// The last sync finished at this time.
    Synced(i64),
    /// The last sync failed, with a message for the reader.
    Failed(String),
}

/// A search over the loaded rows.
#[derive(Debug, Default)]
pub struct Search {
    /// What the user typed.
    pub query: String,
    /// Whether the query is still being typed.
    pub editing: bool,
}

/// Work the interface needs from the outside world.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// Load the cached message named by this account and identifier.
    OpenMessage(MessageKey),
    /// Read the open message again to show it in this format; raw messages
    /// can be large, so they are not kept in memory.
    Reformat(MessageKey, BodyPreference),
    /// Sync the accounts now.
    Sync,
}

/// The whole interface state.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools, reason = "independent interface flags")]
pub struct App {
    /// Every account the source reads, in registry order, each with its
    /// stored Gmail address or its id.
    pub accounts: Vec<(AccountId, SafeText)>,
    /// Stores that failed to open and remain excluded for this session.
    /// Kept separately from transient status text so a key or sync cannot
    /// make a partial inbox appear complete.
    pub unavailable_accounts: usize,
    /// Every loaded row, newest first.
    pub rows: Vec<Row>,
    /// Indexes into `rows` of the rows the list shows, in order.
    pub shown: Vec<usize>,
    /// The selected position in `shown`.
    pub selected: usize,
    /// The first position drawn in the list, kept stable while moving.
    pub list_offset: usize,
    pub screen: Screen,
    pub search: Search,
    pub sync: SyncState,
    pub help: bool,
    pub status: Option<String>,
    pub quit: bool,
    /// Rows or lines that fit on screen, recorded by the last draw.
    pub page: usize,
    pending_g: bool,
    pub preference: BodyPreference,
    /// Set when the screen changes, so the next draw repaints every cell.
    pub repaint: bool,
    /// Whether older rows may still be in the cache, not yet loaded.
    pub more_rows: bool,
    /// Set when rows could not be read, older ones or the list again after a
    /// sync; the top bar says so until the next reload.
    pub rows_unreadable: bool,
    /// The row selected before a reload pushed it past the reloaded rows,
    /// with its received time; it is selected again when its page arrives,
    /// unless a key comes first.
    pending_selection: Option<(MessageKey, i64)>,
    /// Whether the status line counts the matches of a finished search, so
    /// pages that arrive later update it.
    counting_matches: bool,
}

/// Whether `row` comes after the message `key` received at `received_at` in
/// the unified order: received time descending, then account and identifier
/// ascending.
fn listed_after(row: &Row, key: &MessageKey, received_at: i64) -> bool {
    row.received_at_millis < received_at
        || (row.received_at_millis == received_at
            && (row.account.as_str(), row.id.as_str()) > (key.0.as_str(), key.1.as_str()))
}

impl App {
    pub fn new(accounts: Vec<(AccountId, SafeText)>, rows: Vec<Row>) -> Self {
        let shown = (0..rows.len()).collect();
        Self {
            accounts,
            unavailable_accounts: 0,
            rows,
            shown,
            selected: 0,
            list_offset: 0,
            screen: Screen::Inbox,
            search: Search::default(),
            sync: SyncState::Idle,
            help: false,
            status: None,
            quit: false,
            page: 10,
            pending_g: false,
            // Converted HTML reads better than many newsletters' plain parts,
            // and its links are numbered rather than inlined.
            preference: BodyPreference::Html,
            repaint: false,
            more_rows: false,
            rows_unreadable: false,
            pending_selection: None,
            counting_matches: false,
        }
    }

    /// The row at `position` in the list.
    pub fn shown_row(&self, position: usize) -> Option<&Row> {
        self.shown
            .get(position)
            .and_then(|&index| self.rows.get(index))
    }

    /// The label of `account`: its stored Gmail address, or its id.
    pub fn account_label<'a>(&'a self, account: &'a AccountId) -> &'a str {
        self.accounts
            .iter()
            .find(|(known, _)| known == account)
            .map_or(account.as_str(), |(_, label)| label.as_str())
    }

    /// The account text of the top bar: the one account's label, or how many
    /// accounts the list draws from.
    pub fn account_heading(&self) -> String {
        match self.accounts.len() {
            1 => self.accounts[0].1.as_str().to_owned(),
            count => format!("{count} accounts"),
        }
    }

    /// Replaces the account labels, read again after a finished sync. A
    /// changed label must reach the open message's header, whose lines are
    /// cached with the old one, so that cache is dropped; the scroll
    /// position survives the rebuild.
    pub fn set_accounts(&mut self, accounts: Vec<(AccountId, SafeText)>) {
        if self.accounts != accounts
            && let Screen::Message(view) = &mut self.screen
        {
            view.layout = None;
        }
        self.accounts = accounts;
    }

    fn position_of(&self, key: &MessageKey) -> Option<usize> {
        self.shown.iter().position(|&index| {
            self.rows
                .get(index)
                .is_some_and(|row| row.account == key.0 && row.id == key.1)
        })
    }

    /// Whether a search is narrowing the list.
    pub fn filtered(&self) -> bool {
        !self.search.query.is_empty()
    }

    /// Adds older rows after the loaded ones, keeping the selection.
    pub fn append(&mut self, rows: Vec<Row>) {
        let words = self.search_words();
        let start = self.rows.len();
        self.rows.extend(rows);
        let rows = &self.rows;
        self.shown
            .extend((start..rows.len()).filter(|&index| rows[index].matches(&words)));
        if let Some((key, received_at)) = self.pending_selection.clone() {
            if let Some(position) = self.position_of(&key) {
                self.selected = position;
                self.pending_selection = None;
            } else if self
                .rows
                .last()
                .is_some_and(|last| listed_after(last, &key, received_at))
            {
                // The listing has passed where it would be: the sync removed it.
                self.pending_selection = None;
            }
        }
        self.count_matches();
    }

    /// Replaces the rows after a sync, keeping the selection and any open
    /// message; `more` says whether older rows follow.
    pub fn reload(&mut self, rows: Vec<Row>, more: bool) {
        let selected = self
            .shown_row(self.selected)
            .map(|row| (row.message_key(), row.received_at_millis));
        self.rows = rows;
        self.more_rows = more;
        self.rows_unreadable = false;
        self.pending_selection = None;
        self.refilter();
        if let Some((id, received_at)) = selected {
            match self.position_of(&id) {
                Some(position) => self.selected = position,
                // Newer mail pushed it into a page not read again yet.
                None if more => self.pending_selection = Some((id, received_at)),
                None => {}
            }
        }
        self.count_matches();
    }

    /// Whether a reload left the selected row to come back with a later page.
    pub fn selection_pending(&self) -> bool {
        self.pending_selection.is_some()
    }

    /// Stops loading rows after a failed read.
    pub fn rows_failed(&mut self) {
        self.more_rows = false;
        self.rows_unreadable = true;
        self.count_matches();
    }

    /// Updates the match count of a finished search on the status line.
    fn count_matches(&mut self) {
        if !self.counting_matches {
            return;
        }
        // Rows not searched yet, or never readable, may hold more matches.
        let more = if self.more_rows || self.rows_unreadable {
            "+"
        } else {
            ""
        };
        self.status = Some(match self.shown.len() {
            1 if more.is_empty() => "1 match; esc shows every message".to_owned(),
            count => format!("{count}{more} matches; esc shows every message"),
        });
    }

    fn search_words(&self) -> Vec<String> {
        self.search
            .query
            .to_lowercase()
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    }

    fn refilter(&mut self) {
        let words = self.search_words();
        self.shown = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.matches(&words))
            .map(|(index, _)| index)
            .collect();
        self.selected = self.selected.min(self.shown.len().saturating_sub(1));
    }

    fn set_query(&mut self, query: String) {
        let selected = self.shown_row(self.selected).map(Row::message_key);
        self.search.query = query;
        self.selected = 0;
        self.list_offset = 0;
        self.refilter();
        if let Some(position) = selected.and_then(|id| self.position_of(&id)) {
            self.selected = position;
        }
    }

    /// Handles one key press and returns any work the caller must do.
    pub fn key(&mut self, key: KeyEvent) -> Option<Request> {
        self.status = None;
        self.counting_matches = false;
        self.pending_selection = None;
        if self.help {
            self.help = false;
            return None;
        }
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if control && matches!(key.code, KeyCode::Char('c')) {
            self.quit = true;
            return None;
        }
        if self.search.editing {
            self.search_key(key);
            return None;
        }
        let pending_g = std::mem::take(&mut self.pending_g);
        if key.code == KeyCode::Char('?') {
            self.help = true;
            return None;
        }
        if control && matches!(key.code, KeyCode::Char('r')) {
            return Some(Request::Sync);
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
                    self.selected = motion.apply(self.selected, self.shown.len());
                    return None;
                }
                match key.code {
                    KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => self
                        .shown_row(self.selected)
                        .map(|row| Request::OpenMessage(row.message_key())),
                    KeyCode::Char('/') => {
                        self.search.editing = true;
                        self.set_query(String::new());
                        None
                    }
                    KeyCode::Esc if self.filtered() => {
                        self.set_query(String::new());
                        None
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
                    KeyCode::Char('n') => self.step(1),
                    KeyCode::Char('p') => self.step(-1),
                    KeyCode::Char('H') => self.toggle_format(),
                    _ => None,
                }
            }
        }
    }

    /// Keys while a search query is being typed: the list narrows as it
    /// changes.
    fn search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                self.search.editing = false;
                self.counting_matches = self.filtered();
                self.count_matches();
            }
            KeyCode::Esc => {
                self.search.editing = false;
                self.set_query(String::new());
            }
            KeyCode::Backspace => {
                let mut query = std::mem::take(&mut self.search.query);
                if query.pop().is_none() {
                    self.search.editing = false;
                }
                self.set_query(query);
            }
            KeyCode::Down => self.selected = Motion::By(1).apply(self.selected, self.shown.len()),
            KeyCode::Up => self.selected = Motion::By(-1).apply(self.selected, self.shown.len()),
            KeyCode::Char(character)
                if !character.is_control()
                    && !key.modifiers.contains(KeyModifiers::CONTROL)
                    && self.search.query.len() + character.len_utf8() <= MAX_QUERY_LEN =>
            {
                let mut query = self.search.query.clone();
                query.push(character);
                self.set_query(query);
            }
            _ => {}
        }
    }

    /// Opens the next or previous message in the list.
    fn step(&mut self, delta: isize) -> Option<Request> {
        let Screen::Message(view) = &self.screen else {
            return None;
        };
        let current = self.position_of(&view.key).unwrap_or(self.selected);
        let next = current.checked_add_signed(delta)?;
        let request = Request::OpenMessage(self.shown_row(next)?.message_key());
        self.selected = next;
        Some(request)
    }

    /// Shows the message `key` with its cached raw bytes, if any.
    pub fn show_message(&mut self, key: MessageKey, raw: Result<Option<Vec<u8>>, ()>) {
        let body = match raw {
            Ok(Some(raw)) => Body::Rendered(Box::new(render_message(&raw, self.preference))),
            Ok(None) => Body::NotCached,
            Err(()) => Body::Failed,
        };
        if let Some(position) = self.position_of(&key) {
            self.selected = position;
        }
        self.repaint = true;
        self.screen = Screen::Message(MessageView {
            key,
            body,
            preference: self.preference,
            scroll: 0,
            layout: None,
        });
    }

    fn is_open(&self, key: &MessageKey) -> bool {
        self.open_key() == Some(key)
    }

    /// The open message's account and identifier, if any.
    pub fn open_key(&self) -> Option<&MessageKey> {
        match &self.screen {
            Screen::Message(view) => Some(&view.key),
            Screen::Inbox => None,
        }
    }

    /// Marks the open message as downloading.
    pub fn downloading(&mut self, key: &MessageKey) {
        if let Screen::Message(view) = &mut self.screen
            && &view.key == key
        {
            view.body = Body::Downloading;
            view.layout = None;
            self.repaint = true;
        }
    }

    /// Takes a finished download. It is shown only if that message is still
    /// open; it is cached either way.
    pub fn downloaded(&mut self, key: MessageKey, result: Result<Vec<u8>, String>) {
        if !self.is_open(&key) {
            return;
        }
        match result {
            Ok(raw) => self.show_message(key, Ok(Some(raw))),
            Err(error) => {
                if let Screen::Message(view) = &mut self.screen {
                    view.body = Body::DownloadFailed(error);
                    view.layout = None;
                    self.repaint = true;
                }
            }
        }
    }

    /// Records the end of a sync.
    pub fn synced(&mut self, result: Result<(), String>, now_millis: i64) {
        self.sync = match result {
            Ok(()) => SyncState::Synced(now_millis),
            Err(error) => SyncState::Failed(error),
        };
    }

    /// Asks to show the open message in its other format.
    fn toggle_format(&mut self) -> Option<Request> {
        let Screen::Message(view) = &self.screen else {
            return None;
        };
        let Body::Rendered(rendered) = &view.body else {
            return None;
        };
        if !rendered.has_alternative {
            self.status = Some("This message has only one format.".to_owned());
            return None;
        }
        let other = match rendered.format {
            Some(BodyFormat::Html) => BodyPreference::Plain,
            _ => BodyPreference::Html,
        };
        Some(Request::Reformat(view.key.clone(), other))
    }

    /// Shows the open message `key` again from `raw` in `preference`, which
    /// then applies to the messages opened after it. Nothing changes, the
    /// preference included, when `key` is no longer open.
    pub fn reformat(&mut self, key: &MessageKey, raw: &[u8], preference: BodyPreference) {
        if let Screen::Message(view) = &mut self.screen
            && &view.key == key
        {
            self.preference = preference;
            view.body = Body::Rendered(Box::new(render_message(raw, preference)));
            view.preference = preference;
            view.scroll = 0;
            view.layout = None;
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
    use tersa_application::mailbox::{AccountId, MessageId};
    use tersa_presentation::terminal::SafeText;

    use super::{
        App, Body, BodyPreference, MessageKey, Request, Row, Screen, SyncState, sender_name,
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

    fn press(app: &mut App, code: KeyCode) -> Option<Request> {
        app.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn typed(app: &mut App, text: &str) {
        for character in text.chars() {
            press(app, KeyCode::Char(character));
        }
    }

    fn app(rows: usize) -> App {
        App::new(
            labeled(&["acct"]),
            (0..rows)
                .map(|index| {
                    Row::sample(
                        "acct",
                        &format!("m{index}"),
                        "Sender",
                        &format!("s{index}"),
                        true,
                    )
                })
                .collect(),
        )
    }

    fn open(app: &App) -> Option<&str> {
        match &app.screen {
            Screen::Message(view) => Some(view.key.1.as_str()),
            Screen::Inbox => None,
        }
    }

    #[test]
    fn previews_are_unescaped_then_sanitized() {
        let envelope = tersa_application::mailbox::MessageEnvelope::new(
            id("m"),
            tersa_application::mailbox::ThreadId::new("t").expect("thread"),
            tersa_application::mailbox::HeaderText::new("A <a@example.com>").expect("from"),
            tersa_application::mailbox::HeaderText::new("s").expect("subject"),
            tersa_application::mailbox::HeaderText::new("I don&#39;t &amp; &#27;[2J")
                .expect("preview"),
            tersa_application::mailbox::UnixTimestampMillis::new(0).expect("time"),
            false,
        );
        let row = Row::from_envelope(&envelope, &account("acct"));
        assert_eq!(row.preview.as_str(), "I don't & [2J");
        assert_eq!(row.sender.as_str(), "A");
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
            Some(Request::OpenMessage(key("acct", "m1")))
        );
        app.show_message(key("acct", "m1"), Ok(None));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::NotCached))
        );
        assert_eq!(
            press(&mut app, KeyCode::Char('p')),
            Some(Request::OpenMessage(key("acct", "m0")))
        );
        app.show_message(key("acct", "m0"), Ok(None));
        assert_eq!(press(&mut app, KeyCode::Char('p')), None, "already first");
        press(&mut app, KeyCode::Char('q'));
        assert!(matches!(app.screen, Screen::Inbox));
        press(&mut app, KeyCode::Char('q'));
        assert!(app.quit);
    }

    #[test]
    fn downloads_land_only_on_the_message_still_open() {
        let mut app = app(2);
        app.show_message(key("acct", "m0"), Ok(None));
        app.downloading(&key("acct", "m0"));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::Downloading))
        );
        app.downloaded(key("acct", "m1"), Ok(b"Subject: other\r\n\r\nx".to_vec()));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::Downloading))
        );
        app.downloaded(
            key("acct", "m0"),
            Ok(b"Subject: s\r\n\r\nfull body".to_vec()),
        );
        let Screen::Message(view) = &app.screen else {
            panic!("message screen");
        };
        let Body::Rendered(rendered) = &view.body else {
            panic!("rendered");
        };
        assert_eq!(rendered.body.as_str(), "full body");
        app.show_message(key("acct", "m1"), Ok(None));
        app.downloaded(key("acct", "m1"), Err("offline".to_owned()));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(&view.body, Body::DownloadFailed(error) if error == "offline"))
        );
    }

    /// Gmail identifiers are only unique within one mailbox: a message of
    /// another account with the same identifier is a different message.
    #[test]
    fn the_same_id_in_two_accounts_names_two_messages() {
        let mut app = App::new(
            labeled(&["acct_a", "acct_b"]),
            vec![
                Row::sample("acct_a", "m", "Ann <a@example.com>", "From a", true),
                Row::sample("acct_b", "m", "Bob <b@example.com>", "From b", true),
            ],
        );
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(
            press(&mut app, KeyCode::Enter),
            Some(Request::OpenMessage(key("acct_b", "m"))),
            "the request names the row's account"
        );
        app.show_message(key("acct_b", "m"), Ok(None));
        app.downloading(&key("acct_b", "m"));
        // The other account's same-id message finishes downloading first.
        app.downloaded(key("acct_a", "m"), Ok(b"Subject: From a\r\n\r\na".to_vec()));
        assert!(
            matches!(&app.screen, Screen::Message(view) if matches!(view.body, Body::Downloading)),
            "the other account's download changes nothing here"
        );
        app.downloaded(key("acct_b", "m"), Ok(b"Subject: From b\r\n\r\nb".to_vec()));
        let body = |app: &App| {
            let Screen::Message(view) = &app.screen else {
                panic!("message screen");
            };
            let Body::Rendered(rendered) = &view.body else {
                panic!("rendered");
            };
            rendered.body.as_str().to_owned()
        };
        assert_eq!(body(&app), "b");
        // Reformatting the same id in the other account leaves this one open.
        app.reformat(
            &key("acct_a", "m"),
            b"Subject: a\r\n\r\na",
            BodyPreference::Plain,
        );
        assert_eq!(body(&app), "b", "still showing account b's");
        app.reformat(
            &key("acct_b", "m"),
            b"Subject: b\r\n\r\nplain b",
            BodyPreference::Plain,
        );
        assert_eq!(body(&app), "plain b");
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
        app.show_message(key("acct", "m0"), Ok(Some(raw.to_vec())));
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
        assert_eq!(
            press(&mut app, KeyCode::Char('H')),
            Some(Request::Reformat(key("acct", "m0"), BodyPreference::Plain))
        );
        assert_eq!(
            app.preference,
            BodyPreference::Html,
            "nothing changes until the message is shown again"
        );
        app.reformat(&key("acct", "m0"), raw, BodyPreference::Plain);
        assert_eq!(body(&app), "plain body");
        assert_eq!(app.preference, BodyPreference::Plain);
        app.reformat(&key("acct", "other"), raw, BodyPreference::Html);
        assert_eq!(body(&app), "plain body", "only the open message changes");
        assert_eq!(app.preference, BodyPreference::Plain, "nor the preference");
        assert_eq!(
            press(&mut app, KeyCode::Char('H')),
            Some(Request::Reformat(key("acct", "m0"), BodyPreference::Html))
        );
        app.reformat(&key("acct", "m0"), raw, BodyPreference::Html);
        assert_eq!(body(&app), "html body");
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

    fn mailbox() -> App {
        App::new(
            labeled(&["acct"]),
            vec![
                Row::sample(
                    "acct",
                    "a",
                    "Ann <ann@example.com>",
                    "Lunch on Friday",
                    true,
                ),
                Row::sample(
                    "acct",
                    "b",
                    "Bob <bob@work.example>",
                    "Quarterly report",
                    false,
                ),
                Row::sample("acct", "c", "Ann <ann@example.com>", "Report draft", false),
            ],
        )
    }

    fn shown_ids(app: &App) -> Vec<&str> {
        (0..app.shown.len())
            .filter_map(|position| app.shown_row(position))
            .map(|row| row.id.as_str())
            .collect()
    }

    #[test]
    fn search_narrows_the_list_as_the_query_is_typed() {
        let mut app = mailbox();
        press(&mut app, KeyCode::Char('/'));
        assert!(app.search.editing);
        typed(&mut app, "REPORT");
        assert_eq!(shown_ids(&app), ["b", "c"], "case-insensitive");
        typed(&mut app, " ann");
        assert_eq!(shown_ids(&app), ["c"], "every word must match");
        press(&mut app, KeyCode::Enter);
        assert!(!app.search.editing);
        assert_eq!(
            app.status.as_deref(),
            Some("1 match; esc shows every message")
        );
        assert_eq!(
            press(&mut app, KeyCode::Enter),
            Some(Request::OpenMessage(key("acct", "c")))
        );
        app.show_message(key("acct", "c"), Ok(None));
        press(&mut app, KeyCode::Char('q'));
        press(&mut app, KeyCode::Esc);
        assert_eq!(shown_ids(&app), ["a", "b", "c"], "esc clears the search");
        assert_eq!(app.selected, 2, "the selection follows its message");
        assert!(!app.quit);
    }

    #[test]
    fn search_matches_addresses_and_ignores_control_characters() {
        let mut app = mailbox();
        press(&mut app, KeyCode::Char('/'));
        typed(&mut app, "work.example");
        assert_eq!(shown_ids(&app), ["b"]);
        press(&mut app, KeyCode::Char('\u{1b}'));
        assert_eq!(app.search.query, "work.example");
        for _ in 0.."work.example".len() {
            press(&mut app, KeyCode::Backspace);
        }
        assert!(app.search.editing);
        press(&mut app, KeyCode::Backspace);
        assert!(!app.search.editing, "backspace on an empty query leaves");
        assert_eq!(shown_ids(&app), ["a", "b", "c"]);
    }

    #[test]
    fn search_queries_are_bounded() {
        let mut app = mailbox();
        press(&mut app, KeyCode::Char('/'));
        typed(&mut app, &"x".repeat(300));
        assert_eq!(app.search.query.len(), 256);
        assert!(app.shown.is_empty());
        assert_eq!(press(&mut app, KeyCode::Enter), None);
        assert_eq!(press(&mut app, KeyCode::Enter), None, "nothing to open");
    }

    #[test]
    fn next_and_previous_stay_within_search_results() {
        let mut app = mailbox();
        press(&mut app, KeyCode::Char('/'));
        typed(&mut app, "ann");
        press(&mut app, KeyCode::Enter);
        app.show_message(key("acct", "a"), Ok(None));
        assert_eq!(
            press(&mut app, KeyCode::Char('n')),
            Some(Request::OpenMessage(key("acct", "c")))
        );
        app.show_message(key("acct", "c"), Ok(None));
        assert_eq!(press(&mut app, KeyCode::Char('n')), None);
    }

    #[test]
    fn a_reload_keeps_the_selection_and_the_open_message() {
        let mut app = mailbox();
        press(&mut app, KeyCode::Char('j'));
        app.show_message(key("acct", "b"), Ok(None));
        let mut rows = vec![Row::sample("acct", "new", "Zed", "Fresh", true)];
        rows.extend(mailbox().rows);
        app.reload(rows, false);
        assert_eq!(open(&app), Some("b"));
        assert_eq!(app.selected, 2, "b moved down one place");
        assert_eq!(
            press(&mut app, KeyCode::Char('p')),
            Some(Request::OpenMessage(key("acct", "a")))
        );
        app.reload(
            vec![Row::sample("acct", "new", "Zed", "Fresh", true)],
            false,
        );
        assert_eq!(open(&app), Some("b"), "an open message outlives its row");
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn ctrl_r_asks_for_a_sync_and_results_are_recorded() {
        let mut app = mailbox();
        assert_eq!(
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            Some(Request::Sync)
        );
        app.synced(Ok(()), 42);
        assert_eq!(app.sync, SyncState::Synced(42));
        app.synced(Err("offline".to_owned()), 43);
        assert_eq!(app.sync, SyncState::Failed("offline".to_owned()));
    }

    /// The unified order breaks equal received times by account, then
    /// identifier: the catch-up stops only when the listing has passed the
    /// selection in that order.
    #[test]
    fn the_selection_catch_up_follows_the_unified_order() {
        let mut app = App::new(
            labeled(&["acct_a", "acct_b"]),
            vec![Row::sample(
                "acct_b",
                "m",
                "Bob <b@example.com>",
                "Chosen",
                true,
            )],
        );
        app.more_rows = true;
        // A sync stored newer mail on both accounts; the selection is no
        // longer in the reloaded rows.
        app.reload(
            vec![
                Row::sample("acct_a", "a2", "Ann <a@example.com>", "Fresh", true),
                Row::sample("acct_b", "a1", "Bob <b@example.com>", "Fresh", true),
            ],
            true,
        );
        assert!(app.selection_pending());
        // Older pages arrive; acct_a's row at the same received time sorts
        // before the selection, so the catch-up goes on...
        app.append(vec![Row::sample(
            "acct_a",
            "z9",
            "Ann <a@example.com>",
            "Old",
            true,
        )]);
        assert!(app.selection_pending());
        // ...until acct_b's own listing passes it: identifier ascending, "z"
        // comes after "m".
        app.append(vec![Row::sample(
            "acct_b",
            "z9",
            "Bob <b@example.com>",
            "Old",
            true,
        )]);
        assert!(!app.selection_pending());
    }
}
