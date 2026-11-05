// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded sanitized modal documents with physical-line scrolling.
use super::super::{app::App, wrap};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Clear, Paragraph},
};
use tersa_presentation::terminal::SafeText;

pub(in crate::tui) fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let Some(modal) = &mut app.triage.modal else {
        return;
    };
    let screen = frame.area();
    modal.rendered_size = Some((screen.width, screen.height));
    if !modal.has_supported_frame() {
        frame.render_widget(Clear, screen);
        frame.render_widget(
            Paragraph::new("Resize to at least 32 × 8 for triage; Esc cancels."),
            screen,
        );
        return;
    }
    let area = Rect::new(
        screen.x + 1,
        screen.y + 1,
        screen.width.saturating_sub(2).min(110),
        screen.height.saturating_sub(2),
    );
    let inner = Block::bordered().inner(area);
    let columns = usize::from(inner.width);
    let mut lines = Vec::new();
    for text in &modal.lines {
        lines.extend(
            wrap::wrap(text.as_str(), columns, 2_048)
                .into_iter()
                .map(Line::raw),
        );
    }
    let mut selected_start = lines.len();
    for (i, choice) in modal.choices.iter().enumerate() {
        if i == modal.selected {
            selected_start = lines.len();
        }
        let style = if i == modal.selected {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
        };
        let text = format!(
            "{} {}",
            if i == modal.selected { "›" } else { " " },
            choice.text
        );
        lines.extend(
            wrap::wrap(&text, columns, 2_048)
                .into_iter()
                .map(|line| Line::styled(line, style)),
        );
    }
    if let Some(input) = &modal.input {
        let preview = SafeText::single_line(&input.raw);
        lines.push(Line::raw(format!(
            "Name ({} / 1,024 bytes):",
            input.raw.len()
        )));
        lines.extend(
            wrap::wrap(preview.as_str(), columns, 128)
                .into_iter()
                .map(Line::raw),
        );
    }
    let height = usize::from(inner.height.saturating_sub(1));
    if modal.follow_selection {
        if selected_start < modal.scroll {
            modal.scroll = selected_start;
        } else if selected_start >= modal.scroll + height {
            modal.scroll = selected_start.saturating_sub(height / 2);
        }
        modal.follow_selection = false;
    }
    modal.scroll = modal.scroll.min(lines.len().saturating_sub(height));
    let block = Block::bordered().title(modal.title.as_str());
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    let body = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(1),
    );
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(modal.scroll)
                .take(height)
                .collect::<Vec<_>>(),
        ),
        body,
    );
    frame.render_widget(
        Paragraph::new("j/k choose · Enter select · Space/PgUp scroll · Esc cancel"),
        Rect::new(inner.x, inner.y + inner.height - 1, inner.width, 1),
    );
}
