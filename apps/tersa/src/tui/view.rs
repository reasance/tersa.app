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

use super::app::{App, Body, MessageView, Row, Screen};
use super::wrap::{truncate, width, wrap, wrap_chars};
use crate::dates;

/// One drawn line; message layouts are cached as these.
pub type StyledLine = Line<'static>;

const DATE_WIDTH: usize = 6;

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
    draw_top(frame, top, app);
    if matches!(app.screen, Screen::Inbox) {
        keep_selection_visible(app);
        draw_inbox(frame, main, app, now_millis);
    } else if let Screen::Message(view) = &mut app.screen {
        let row = app.rows.get(view.index);
        draw_message(frame, main, view, row, app.page);
    }
    draw_bottom(frame, bottom, app);
    if app.help {
        draw_help(frame, frame.area());
    }
}

fn draw_top(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let count = match app.rows.len() {
        1 => "1 message".to_owned(),
        count => format!("{count} messages"),
    };
    let line = Line::from(vec![
        Span::styled(" tersa", bold()),
        Span::styled("  ", dim()),
        Span::raw(app.account.as_str().to_owned()),
        Span::styled(format!("  ·  {count}"), dim()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_bottom(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let text = match (&app.status, &app.screen) {
        (Some(status), _) => status.clone(),
        (None, Screen::Inbox) => "j/k move   enter open   q quit   ? help".to_owned(),
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
    app.list_offset = app.list_offset.min(app.rows.len().saturating_sub(1));
}

fn draw_inbox(frame: &mut Frame<'_>, area: Rect, app: &App, now_millis: i64) {
    if app.rows.is_empty() {
        let lines = vec![
            Line::raw(""),
            Line::styled("  No cached mail yet.", bold()),
            Line::styled("  Run `tersa sync` to download recent messages.", dim()),
        ];
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }
    let total = usize::from(area.width);
    let lines: Vec<Line<'_>> = app
        .rows
        .iter()
        .enumerate()
        .skip(app.list_offset)
        .take(usize::from(area.height))
        .map(|(index, row)| inbox_line(row, index == app.selected, total, now_millis))
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
            // Addresses have no good break points: wrap them by character,
            // indented under their reference number.
            let lead = format!("{:<indent$}", format!("[{}]", number + 1));
            for (row, part) in wrap_chars(link.as_str(), columns.saturating_sub(indent).max(1))
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
    let wrapped = wrap(value, columns.saturating_sub(indent).max(1));
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
    lines.extend(
        wrap(text, columns)
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

const HELP: [(&str, &str); 12] = [
    ("j / k, ↓ / ↑", "move or scroll"),
    ("gg / G", "first / last"),
    ("ctrl-d / ctrl-u", "half page down / up"),
    ("space / b", "page down / up"),
    ("enter, l", "open message"),
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
    use tersa_presentation::terminal::SafeText;

    use super::draw;
    use crate::tui::app::{App, Row};

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
        Row {
            sender: SafeText::single_line(sender),
            subject: SafeText::single_line(subject),
            preview: SafeText::single_line("the preview"),
            received_at_millis: 1_760_990_000_000,
            unread,
        }
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
        app.show_message(0, Ok(Some(raw.to_vec())));
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
        app.show_message(0, Ok(None));
        let _ = screen(&mut app, 3, 3);
    }
}
