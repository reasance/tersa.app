// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Drawing. Every provider-derived string reaching the screen is `SafeText`;
//! styling uses only bold, dim, and reverse so it follows the terminal theme.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};
use tersa_presentation::message::{BodyFormat, RenderedMessage};
use tersa_presentation::terminal::SafeText;

use super::app::{App, Body, MessageView, Row, Screen, SyncState};
use super::wrap::{truncate, width, wrap, wrap_chars};
use crate::dates;

/// One drawn line; message layouts are cached as these.
pub type StyledLine = Line<'static>;

const DATE_WIDTH: usize = 6;

/// At most this many wrapped lines of one message are laid out, which keeps
/// a pathological body (half a megabyte of one-character lines) to a few
/// megabytes of layout.
const MAX_MESSAGE_LINES: usize = 20_000;
/// The wrappers stop one line past the cap, so a cut shows as a longer layout.
const LINE_BUDGET: usize = MAX_MESSAGE_LINES + 1;

fn dim() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

/// Draws the whole interface.
pub fn draw(frame: &mut Frame<'_>, app: &mut App, now_millis: i64) {
    let [top, main, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    app.page = usize::from(main.height).max(1);
    draw_top(frame, top, app, now_millis);
    if matches!(app.screen, Screen::Inbox) {
        keep_selection_visible(app);
        draw_inbox(frame, main, app, now_millis);
    } else if let Screen::Message(view) = &mut app.screen {
        let row = app.rows.iter().find(|row| row.id == view.id);
        draw_message(frame, main, view, row, app.page);
    }
    draw_bottom(frame, bottom, app);
    if app.help {
        draw_help(frame, frame.area());
    }
}

fn draw_top(frame: &mut Frame<'_>, area: Rect, app: &App, now_millis: i64) {
    let count = match (app.filtered(), app.rows.len()) {
        (true, total) => format!("{} of {total} messages", app.shown.len()),
        (false, 1) => "1 message".to_owned(),
        (false, count) => format!("{count} messages"),
    };
    let sync = match &app.sync {
        SyncState::Idle => String::new(),
        SyncState::Running => "syncing… ".to_owned(),
        SyncState::Synced(at) => format!("synced {} ", dates::short(*at, now_millis)),
        SyncState::Failed(error) => {
            format!("sync failed: {} ", SafeText::single_line(error).as_str())
        }
    };
    // The sync state sits at the right edge; the account name gives way.
    let total = usize::from(area.width);
    let sync = truncate(&sync, total.saturating_sub(width(" tersa  ") + 4));
    let tail = format!("  ·  {count}");
    let room = total.saturating_sub(width(" tersa  ") + width(&tail) + width(&sync) + 1);
    let left = Line::from(vec![
        Span::styled(" tersa", bold()),
        Span::styled("  ", dim()),
        Span::raw(truncate(app.account.as_str(), room)),
        Span::styled(tail, dim()),
    ]);
    let sync_width = u16::try_from(width(&sync))
        .unwrap_or(u16::MAX)
        .min(area.width);
    let [left_area, sync_area] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(sync_width)]).areas(area);
    frame.render_widget(Paragraph::new(left), left_area);
    frame.render_widget(Paragraph::new(Line::styled(sync, dim())), sync_area);
}

fn draw_bottom(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if app.search.editing {
        let query = SafeText::single_line(&app.search.query);
        let shown = truncate_start(query.as_str(), usize::from(area.width).saturating_sub(3));
        let cursor = u16::try_from(width(&shown) + 2).unwrap_or(u16::MAX);
        frame.render_widget(Paragraph::new(Line::raw(format!(" /{shown}"))), area);
        if cursor < area.width {
            frame.set_cursor_position((area.x + cursor, area.y));
        }
        return;
    }
    let text = match (&app.status, &app.screen) {
        (Some(status), _) => status.clone(),
        (None, Screen::Inbox) if app.filtered() => {
            "j/k move   enter open   / search again   esc all messages   ? help".to_owned()
        }
        (None, Screen::Inbox) => "j/k move   enter open   / search   q quit   ? help".to_owned(),
        (None, Screen::Message(_)) => {
            "j/k scroll   n/p next/previous   H html/plain   q back   ? help".to_owned()
        }
    };
    let line = Line::styled(
        format!(" {}", truncate(&text, usize::from(area.width))),
        dim(),
    );
    frame.render_widget(Paragraph::new(line), area);
}

fn keep_selection_visible(app: &mut App) {
    if app.selected < app.list_offset {
        app.list_offset = app.selected;
    } else if app.selected >= app.list_offset + app.page {
        app.list_offset = app.selected + 1 - app.page;
    }
    app.list_offset = app.list_offset.min(app.shown.len().saturating_sub(1));
}

/// The end of `text` that fits in `columns`, so typing stays visible.
fn truncate_start(text: &str, columns: usize) -> String {
    let mut used = 0;
    let mut start = text.len();
    for (index, character) in text.char_indices().rev() {
        used += width(character.encode_utf8(&mut [0; 4]));
        if used > columns {
            break;
        }
        start = index;
    }
    text[start..].to_owned()
}

fn draw_inbox(frame: &mut Frame<'_>, area: Rect, app: &App, now_millis: i64) {
    if app.shown.is_empty() {
        let lines = if app.filtered() {
            vec![
                Line::raw(""),
                Line::styled("  No messages match.", bold()),
                Line::styled("  Esc shows every message.", dim()),
            ]
        } else if app.sync == SyncState::Running {
            vec![
                Line::raw(""),
                Line::styled("  Downloading recent mail…", bold()),
            ]
        } else {
            vec![
                Line::raw(""),
                Line::styled("  No cached mail yet.", bold()),
                Line::styled("  Ctrl-r syncs recent messages.", dim()),
            ]
        };
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }
    let total = usize::from(area.width);
    let lines: Vec<Line<'_>> = (app.list_offset..app.shown.len())
        .take(usize::from(area.height))
        .filter_map(|position| Some((position, app.shown_row(position)?)))
        .map(|(position, row)| inbox_line(row, position == app.selected, total, now_millis))
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn inbox_line(row: &Row, selected: bool, total: usize, now_millis: i64) -> Line<'static> {
    let sender_width = (total / 4).clamp(10, 24);
    let date = dates::short(row.received_at_millis, now_millis);
    let fixed = 2 + DATE_WIDTH + 2 + sender_width + 2;
    let remaining = total.saturating_sub(fixed);
    let subject = truncate(row.subject.as_str(), remaining);
    let preview_room = remaining.saturating_sub(width(&subject) + 3);
    let weight = if row.unread { bold() } else { Style::new() };
    let mut spans = vec![
        Span::styled(if row.unread { "● " } else { "  " }, weight),
        Span::styled(format!("{date:>DATE_WIDTH$}  "), dim()),
        Span::styled(
            pad(
                &truncate(row.sender.as_str(), sender_width),
                sender_width + 2,
            ),
            weight,
        ),
        Span::styled(subject, weight),
    ];
    if preview_room > 4 && !row.preview.as_str().is_empty() {
        spans.push(Span::styled(
            format!(" · {}", truncate(row.preview.as_str(), preview_room)),
            dim(),
        ));
    }
    let line = Line::from(spans);
    if selected {
        line.style(Style::new().add_modifier(Modifier::REVERSED))
    } else {
        line
    }
}

/// Pads `text` with spaces to `columns` display columns.
fn pad(text: &str, columns: usize) -> String {
    let mut padded = text.to_owned();
    padded.push_str(&" ".repeat(columns.saturating_sub(width(text))));
    padded
}

fn draw_message(
    frame: &mut Frame<'_>,
    area: Rect,
    view: &mut MessageView,
    row: Option<&Row>,
    page: usize,
) {
    let columns = area.width.saturating_sub(2).max(1);
    if view
        .layout
        .as_ref()
        .is_none_or(|(cached, _)| *cached != columns)
    {
        view.layout = Some((columns, message_lines(view, row, usize::from(columns))));
    }
    let lines = view
        .layout
        .as_ref()
        .map_or(&[][..], |(_, lines)| lines.as_slice());
    view.scroll = view.scroll.min(lines.len().saturating_sub(page));
    let visible: Vec<Line<'_>> = lines.iter().skip(view.scroll).take(page).cloned().collect();
    let inner = Rect {
        x: area.x + 1,
        width: columns,
        ..area
    };
    frame.render_widget(Paragraph::new(visible), inner);
}

fn message_lines(view: &MessageView, row: Option<&Row>, columns: usize) -> Vec<StyledLine> {
    let mut lines = Vec::new();
    match &view.body {
        Body::Rendered(rendered) => rendered_lines(rendered, row, columns, &mut lines),
        Body::NotCached | Body::Downloading | Body::DownloadFailed(_) | Body::Failed => {
            if let Some(row) = row {
                push_wrapped(&mut lines, row.subject.as_str(), columns, bold());
                header(&mut lines, "From", row.sender.as_str(), columns);
                header(
                    &mut lines,
                    "Date",
                    &dates::long(row.received_at_millis),
                    columns,
                );
            }
            lines.push(rule(columns));
            let note = match &view.body {
                Body::Failed => "This message could not be read from the local cache.".to_owned(),
                Body::Downloading => "Downloading the full message… Gmail's preview:".to_owned(),
                Body::DownloadFailed(error) => format!(
                    "The full message could not be downloaded: {}. Gmail's preview:",
                    SafeText::single_line(error).as_str()
                ),
                _ => "The full message is not downloaded yet; it arrives with a later sync. \
                      Gmail's preview:"
                    .to_owned(),
            };
            push_wrapped(&mut lines, &note, columns, dim());
            if let Some(row) = row {
                lines.push(Line::raw(""));
                push_wrapped(&mut lines, row.preview.as_str(), columns, Style::new());
            }
        }
    }
    if lines.len() > MAX_MESSAGE_LINES {
        lines.truncate(MAX_MESSAGE_LINES);
        lines.push(Line::styled(
            "[… the rest of this message is too long to show]",
            dim(),
        ));
    }
    lines
}

fn rendered_lines(
    rendered: &RenderedMessage,
    row: Option<&Row>,
    columns: usize,
    lines: &mut Vec<StyledLine>,
) {
    let subject = match (rendered.subject.as_str(), row) {
        ("", Some(row)) => row.subject.as_str(),
        (subject, _) => subject,
    };
    push_wrapped(lines, subject, columns, bold());
    header(lines, "From", rendered.from.as_str(), columns);
    header(lines, "To", rendered.to.as_str(), columns);
    header(lines, "Cc", rendered.cc.as_str(), columns);
    if let Some(row) = row {
        header(lines, "Date", &dates::long(row.received_at_millis), columns);
    }
    if rendered.has_alternative {
        let note = match rendered.format {
            Some(BodyFormat::Html) => "Showing the HTML version as text; H for plain text.",
            _ => "Showing the plain-text version; H for the HTML version.",
        };
        push_wrapped(lines, note, columns, dim());
    }
    lines.push(rule(columns));
    if rendered.body.as_str().is_empty() {
        push_wrapped(
            lines,
            "(This message has no readable text.)",
            columns,
            dim(),
        );
    } else {
        push_wrapped(lines, rendered.body.as_str(), columns, Style::new());
    }
    if !rendered.links.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Links", bold()));
        let indent = format!("[{}] ", rendered.links.len()).len();
        for (number, link) in rendered.links.iter().enumerate() {
            let room = LINE_BUDGET.saturating_sub(lines.len());
            if room == 0 {
                break;
            }
            // Addresses have no good break points: wrap them by character,
            // indented under their reference number.
            let lead = format!("{:<indent$}", format!("[{}]", number + 1));
            for (row, part) in
                wrap_chars(link.as_str(), columns.saturating_sub(indent).max(1), room)
                    .into_iter()
                    .enumerate()
            {
                let lead = if row == 0 {
                    lead.clone()
                } else {
                    " ".repeat(indent)
                };
                lines.push(Line::from(vec![Span::raw(lead), Span::styled(part, dim())]));
            }
        }
    }
    if !rendered.attachments.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Attachments", bold()));
        for attachment in &rendered.attachments {
            push_wrapped(
                lines,
                &format!(
                    "{}  {}  {}",
                    attachment.name.as_str(),
                    attachment.mime_type.as_str(),
                    human_size(attachment.size)
                ),
                columns,
                Style::new(),
            );
        }
    }
}

fn header(lines: &mut Vec<StyledLine>, label: &str, value: &str, columns: usize) {
    if value.is_empty() {
        return;
    }
    let prefix = format!("{label}: ");
    let indent = width(&prefix);
    let room = LINE_BUDGET.saturating_sub(lines.len());
    let wrapped = wrap(value, columns.saturating_sub(indent).max(1), room);
    for (number, part) in wrapped.into_iter().enumerate() {
        let lead = if number == 0 {
            prefix.clone()
        } else {
            " ".repeat(indent)
        };
        lines.push(Line::from(vec![Span::styled(lead, dim()), Span::raw(part)]));
    }
}

fn push_wrapped(lines: &mut Vec<StyledLine>, text: &str, columns: usize, style: Style) {
    let room = LINE_BUDGET.saturating_sub(lines.len());
    lines.extend(
        wrap(text, columns, room)
            .into_iter()
            .map(|line| Line::styled(line, style)),
    );
}

fn rule(columns: usize) -> StyledLine {
    Line::styled("─".repeat(columns), dim())
}

fn human_size(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024 && unit + 1 < UNITS.len() {
        value /= 1024;
        unit += 1;
    }
    format!("{value} {}", UNITS[unit])
}

const HELP: [(&str, &str); 15] = [
    ("j / k, ↓ / ↑", "move or scroll"),
    ("gg / G", "first / last"),
    ("ctrl-d / ctrl-u", "half page down / up"),
    ("space / b", "page down / up"),
    ("enter, l", "open message"),
    ("/", "search sender, subject, preview"),
    ("esc", "show every message again"),
    ("ctrl-r", "sync now (also every 5 minutes)"),
    ("n / p", "next / previous message"),
    ("H", "switch HTML / plain text"),
    ("q, h, esc", "back"),
    ("q", "quit (from the inbox)"),
    ("ctrl-c", "quit"),
    ("?", "this help"),
    ("", "any key closes this help"),
];

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    let height = u16::try_from(HELP.len() + 2)
        .unwrap_or(u16::MAX)
        .min(area.height);
    let width = 52.min(area.width);
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    let lines: Vec<Line<'_>> = HELP
        .iter()
        .map(|(keys, action)| {
            Line::from(vec![
                Span::styled(format!(" {keys:<18}"), bold()),
                Span::raw(*action),
            ])
        })
        .collect();
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Keys ")),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use tersa_application::mailbox::MessageId;
    use tersa_presentation::terminal::SafeText;

    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::draw;
    use crate::tui::app::{App, Row, SyncState};

    fn screen(app: &mut App, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| draw(frame, app, 1_761_000_000_000))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect::<String>()
            })
            .collect()
    }

    fn row(sender: &str, subject: &str, unread: bool) -> Row {
        Row::sample("m", sender, subject, unread)
    }

    #[test]
    fn inbox_rows_fit_the_width_and_mark_unread() {
        let mut app = App::new(
            SafeText::single_line("acct_1234"),
            vec![
                row("Ann", "Hello there", true),
                row(
                    "A very long sender name that cannot fit",
                    "Re: plans",
                    false,
                ),
            ],
        );
        let lines = screen(&mut app, 60, 5);
        assert!(lines[0].starts_with(" tersa  acct_1234  ·  2 messages"));
        assert!(lines[1].starts_with("● "));
        assert!(lines[1].contains("Ann"));
        assert!(lines[1].contains("Hello there · the preview"));
        assert!(lines[2].contains("A very long se… "));
        assert!(lines[4].contains("j/k move"));
    }

    #[test]
    fn hostile_text_never_reaches_the_screen_as_controls() {
        use tersa_application::mailbox::{
            HeaderText, MessageEnvelope, MessageId, ThreadId, UnixTimestampMillis,
        };
        let envelope = MessageEnvelope::new(
            MessageId::new("m").expect("id"),
            ThreadId::new("t").expect("thread"),
            // Envelope headers cannot hold controls, but Gmail's escaped
            // previews decode to them, and bidi controls pass both.
            HeaderText::new("Evil\u{202e}gnp.exe <e@example.com>").expect("from"),
            HeaderText::new("\u{2066}Invoice\u{2069}\u{200b}").expect("subject"),
            HeaderText::new("&#27;]52;c;cGF5bG9hZA==&#7;pre&#155;31mview&#8238;").expect("preview"),
            UnixTimestampMillis::new(1_760_990_000_000).expect("time"),
            true,
        );
        let hostile = Row::from_envelope(&envelope);
        // ratatui also drops graphemes that hold control characters, so only
        // the row itself shows whether SafeText removed them.
        assert_eq!(hostile.preview.as_str(), "]52;c;cGF5bG9hZA==pre31mview");
        for field in [&hostile.sender, &hostile.subject, &hostile.preview] {
            assert!(
                !field
                    .as_str()
                    .chars()
                    .any(|character| character.is_control()
                        || ('\u{202a}'..='\u{202e}').contains(&character)
                        || ('\u{2066}'..='\u{2069}').contains(&character)
                        || character == '\u{200b}'),
                "{:?}",
                field.as_str()
            );
        }
        // Bidi controls are printable to ratatui, so the screen check matters.
        let mut app = App::new(SafeText::single_line("acct"), vec![hostile]);
        for line in screen(&mut app, 80, 4) {
            assert!(
                !line.chars().any(|character| character.is_control()
                    || ('\u{202a}'..='\u{202e}').contains(&character)
                    || ('\u{2066}'..='\u{2069}').contains(&character)),
                "{line:?}"
            );
        }
    }

    #[test]
    fn an_open_message_shows_headers_body_and_links() {
        let raw = b"From: Ann <ann@example.com>\r\nTo: me@example.com\r\nSubject: Plans\r\n\
Content-Type: text/html\r\n\r\n<p>See <a href=\"https://example.com/x\">this</a>.</p>";
        let mut app = App::new(
            SafeText::single_line("acct"),
            vec![row("Ann", "Plans", true)],
        );
        app.show_message(MessageId::new("m").expect("id"), Ok(Some(raw.to_vec())));
        let lines = screen(&mut app, 50, 14);
        let text = lines.join("\n");
        assert!(text.contains("Plans"));
        assert!(text.contains("From: Ann <ann@example.com>"));
        assert!(text.contains("See this [1]."));
        assert!(text.contains("[1] https://example.com/x"));
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let mut app = App::new(SafeText::single_line("acct"), vec![row("a", "b", true)]);
        for (width, height) in [(1, 1), (5, 2), (12, 3)] {
            let _ = screen(&mut app, width, height);
            app.help = true;
            let _ = screen(&mut app, width, height);
            app.help = false;
        }
        app.show_message(MessageId::new("m").expect("id"), Ok(None));
        let _ = screen(&mut app, 3, 3);
    }

    #[test]
    fn the_search_line_and_sync_state_are_drawn_safely() {
        let mut app = App::new(
            SafeText::single_line("acct"),
            vec![row("Ann", "Lunch", true), row("Bob", "Report", false)],
        );
        app.sync = SyncState::Running;
        let top = &screen(&mut app, 70, 4)[0];
        assert!(top.contains("acct  ·  2 messages"));
        assert!(top.ends_with("syncing… "), "{top:?}");
        assert_eq!(
            screen(&mut app, 34, 4)[0],
            " tersa  …  ·  2 messages syncing… ",
            "the account gives way to the sync state"
        );
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "rep".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        let lines = screen(&mut app, 70, 4);
        assert!(lines[0].contains("1 of 2 messages"));
        assert!(lines[1].contains("Report"));
        assert!(lines[3].starts_with(" /rep "));
        app.key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert!(screen(&mut app, 70, 4)[2].contains("No messages match."));
        app.sync = SyncState::Failed("\u{1b}]52;c;eA==\u{7}offline".to_owned());
        let lines = screen(&mut app, 70, 4);
        assert!(
            lines[0].contains("sync failed: ]52;c;eA==offline"),
            "{lines:?}"
        );
        assert!(!lines[0].contains('\u{1b}'));
    }

    #[test]
    fn a_long_query_shows_its_end() {
        let mut app = App::new(SafeText::single_line("acct"), vec![row("a", "b", true)]);
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "abcdefghijklmnopqrstuvwxyz".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        assert_eq!(
            screen(&mut app, 12, 3)[2],
            " /rstuvwxyz ",
            "room for the cursor"
        );
    }

    #[test]
    fn a_huge_message_is_laid_out_up_to_a_bound() {
        let mut raw = b"Subject: long\r\n\r\n".to_vec();
        raw.extend(b"x\n".repeat(200_000));
        let mut app = App::new(SafeText::single_line("acct"), vec![row("a", "long", true)]);
        app.show_message(MessageId::new("m").expect("id"), Ok(Some(raw)));
        let _ = screen(&mut app, 40, 5);
        let crate::tui::app::Screen::Message(view) = &app.screen else {
            panic!("message screen");
        };
        let lines = &view.layout.as_ref().expect("laid out").1;
        assert_eq!(lines.len(), 20_001);
        assert!(lines[20_000].to_string().contains("too long to show"));
    }

    #[test]
    fn a_message_that_exactly_fills_the_bound_is_not_marked_cut() {
        let laid_out_len = |body_lines: usize| {
            let mut raw = b"Subject: long\r\n\r\n".to_vec();
            raw.extend(b"x\n".repeat(body_lines));
            let mut app = App::new(SafeText::single_line("acct"), vec![row("a", "long", true)]);
            app.show_message(MessageId::new("m").expect("id"), Ok(Some(raw)));
            let _ = screen(&mut app, 40, 5);
            laid_out(&app)
        };
        let headers = laid_out_len(1).len() - 1;
        let full = laid_out_len(20_000 - headers);
        assert_eq!(full.len(), 20_000);
        assert!(!full.iter().any(|line| line.contains("too long to show")));
        let over = laid_out_len(20_001 - headers);
        assert_eq!(over.len(), 20_001);
        assert!(over[20_000].contains("too long to show"));
    }

    #[test]
    fn many_long_links_in_a_narrow_pane_stay_within_the_bound() {
        // 500 links of 2 KB at two columns would wrap to 512,000 lines.
        let mut anchors = String::new();
        for number in 0..500 {
            anchors.push_str("<a href=\"https://e.com/");
            anchors.push_str(&number.to_string());
            anchors.push('/');
            anchors.push_str(&"x".repeat(1990));
            anchors.push_str("\">l</a> ");
        }
        let raw = format!("Subject: links\r\nContent-Type: text/html\r\n\r\n<p>{anchors}</p>");
        let mut app = App::new(SafeText::single_line("acct"), vec![row("a", "links", true)]);
        app.show_message(MessageId::new("m").expect("id"), Ok(Some(raw.into_bytes())));
        let _ = screen(&mut app, 8, 5);
        let crate::tui::app::Screen::Message(view) = &app.screen else {
            panic!("message screen");
        };
        let lines = &view.layout.as_ref().expect("laid out").1;
        assert_eq!(lines.len(), 20_001);
        assert!(lines[20_000].to_string().contains("too long to show"));
    }

    /// The open message's lines as laid out, before ratatui sees them.
    /// ratatui drops graphemes that hold control characters, so only these
    /// show whether SafeText removed them.
    fn laid_out(app: &App) -> Vec<String> {
        let crate::tui::app::Screen::Message(view) = &app.screen else {
            panic!("message screen");
        };
        view.layout
            .as_ref()
            .expect("laid out")
            .1
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn assert_no_controls(lines: &[String]) {
        for line in lines {
            assert!(
                !line.chars().any(|character| character.is_control()
                    || ('\u{202a}'..='\u{202e}').contains(&character)
                    || ('\u{2066}'..='\u{2069}').contains(&character)),
                "{line:?}"
            );
        }
    }

    #[test]
    fn hostile_message_parts_never_reach_the_screen_as_controls() {
        let raw = "From: =?utf-8?q?Evil=1B]52;c;eA=3D=3D=07?= <e@example.com>\r\n\
To: \u{1b}[2Jvictim@example.com\r\nCc: \u{202e}cc@example.com\r\n\
Subject: \u{1b}]0;title\u{7}hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n\
<p>body &#27;[31m red &#x9b;1m <a href=\"https://e.com/&#27;]8;;x\">link</a></p>\r\n\
--b\r\nContent-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=\"\u{1b}[2Jevil\u{202e}fdp.exe\"\r\n\r\nxx\r\n--b--\r\n";
        let mut app = App::new(SafeText::single_line("acct"), vec![row("a", "b", true)]);
        app.show_message(
            MessageId::new("m").expect("id"),
            Ok(Some(raw.as_bytes().to_vec())),
        );
        let lines = screen(&mut app, 60, 30);
        assert!(lines.join("\n").contains("Attachments"), "{lines:?}");
        assert_no_controls(&lines);
        assert_no_controls(&laid_out(&app));

        app.show_message(MessageId::new("m").expect("id"), Ok(None));
        app.downloaded(
            MessageId::new("m").expect("id"),
            Err("\u{1b}]52;c;eA==\u{7}\u{202e}offline".to_owned()),
        );
        let lines = screen(&mut app, 60, 12);
        assert!(lines.join("\n").contains("could not be downloaded"));
        assert_no_controls(&lines);
        assert_no_controls(&laid_out(&app));
    }

    #[test]
    fn message_scrolling_is_clamped_to_the_last_page() {
        let mut raw = b"Subject: long\r\n\r\n".to_vec();
        for line in 0..100 {
            raw.extend(format!("line {line}\n").as_bytes());
        }
        let mut app = App::new(SafeText::single_line("acct"), vec![row("a", "long", true)]);
        app.show_message(MessageId::new("m").expect("id"), Ok(Some(raw)));
        let _ = screen(&mut app, 40, 12);
        app.key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        for _ in 0..5 {
            app.key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        let lines = screen(&mut app, 40, 12);
        assert!(lines[10].contains("line 99"), "{lines:?}");
        app.key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        let lines = screen(&mut app, 40, 12);
        assert!(
            lines[10].contains("line 98"),
            "one line up from the end: {lines:?}"
        );
        app.key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert!(screen(&mut app, 40, 12)[1].contains("long"));
    }
}
