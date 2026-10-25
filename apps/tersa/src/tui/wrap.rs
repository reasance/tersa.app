// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display-width-aware text wrapping and truncation.

use unicode_width::UnicodeWidthChar;

const TAB_STOP: usize = 4;

fn char_width(character: char) -> usize {
    character.width().unwrap_or(0)
}

/// The display width of `text`.
pub fn width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// Cuts `text` to at most `max` display columns, ending in `…` when cut.
pub fn truncate(text: &str, max: usize) -> String {
    if width(text) <= max {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut used = 0;
    for character in text.chars() {
        let next = char_width(character);
        if used + next + 1 > max {
            break;
        }
        out.push(character);
        used += next;
    }
    if max > 0 {
        out.push('…');
    }
    out
}

/// Wraps `text` to `columns` display columns at any character, for text
/// without natural break points such as web addresses.
pub fn wrap_chars(text: &str, columns: usize) -> Vec<String> {
    let columns = columns.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for character in text.chars() {
        let added = char_width(character);
        if used + added > columns && used > 0 {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        line.push(character);
        used += added;
    }
    lines.push(line);
    lines
}

/// Wraps `text` to `columns` display columns, breaking at spaces when it
/// can and inside words when it must. Tabs expand to the next tab stop and
/// leading indentation is kept.
pub fn wrap(text: &str, columns: usize) -> Vec<String> {
    let columns = columns.max(1);
    let mut lines = Vec::new();
    for source in text.split('\n') {
        let (prefix, continuation) = line_prefix(source);
        let prefix_width = width(prefix);
        if prefix.is_empty() || prefix_width * 2 > columns {
            wrap_line(source, columns, &mut lines);
            continue;
        }
        // Quote marks and list bullets carry over to continuation lines.
        let mut parts = Vec::new();
        wrap_line(&source[prefix.len()..], columns - prefix_width, &mut parts);
        for (row, part) in parts.into_iter().enumerate() {
            let lead = if row == 0 {
                prefix
            } else {
                continuation.as_str()
            };
            lines.push(format!("{lead}{part}"));
        }
    }
    lines
}

/// Splits a line's leading quote marks, indentation, and bullet from its
/// text, and returns what continuation lines should start with instead.
fn line_prefix(line: &str) -> (&str, String) {
    let mut rest = line;
    while let Some(after) = rest.strip_prefix("> ") {
        rest = after;
    }
    let quotes = &line[..line.len() - rest.len()];
    let after_indent = rest.trim_start_matches(' ');
    let after_bullet = after_indent.strip_prefix("• ").unwrap_or(after_indent);
    let prefix = &line[..line.len() - after_bullet.len()];
    let hanging = width(&prefix[quotes.len()..]);
    (prefix, format!("{quotes}{}", " ".repeat(hanging)))
}

fn wrap_line(source: &str, columns: usize, lines: &mut Vec<String>) {
    let mut line = String::new();
    let mut line_width = 0;
    // Byte offset in `line` just after the last space, and the width there.
    let mut last_space: Option<(usize, usize)> = None;
    for character in source.chars() {
        if character == '\t' {
            let spaces = TAB_STOP - line_width % TAB_STOP;
            for _ in 0..spaces {
                push_char(
                    ' ',
                    columns,
                    lines,
                    &mut line,
                    &mut line_width,
                    &mut last_space,
                );
            }
            continue;
        }
        push_char(
            character,
            columns,
            lines,
            &mut line,
            &mut line_width,
            &mut last_space,
        );
    }
    lines.push(line);
}

fn push_char(
    character: char,
    columns: usize,
    lines: &mut Vec<String>,
    line: &mut String,
    line_width: &mut usize,
    last_space: &mut Option<(usize, usize)>,
) {
    let added = char_width(character);
    if *line_width + added > columns && *line_width > 0 {
        if character == ' ' {
            // The line is full exactly here; the space becomes the break.
            lines.push(line.trim_end().to_owned());
            line.clear();
            *line_width = 0;
            *last_space = None;
            return;
        }
        match last_space.take() {
            Some((at, width_at)) if at < line.len() => {
                let rest = line.split_off(at);
                lines.push(line.trim_end().to_owned());
                *line = rest;
                *line_width -= width_at;
            }
            _ => {
                lines.push(line.trim_end().to_owned());
                line.clear();
                *line_width = 0;
            }
        }
    }
    line.push(character);
    *line_width += added;
    if character == ' ' {
        *last_space = Some((line.len(), *line_width));
    }
}

#[cfg(test)]
mod tests {
    use super::{truncate, width, wrap, wrap_chars};

    #[test]
    fn quotes_and_bullets_continue_on_wrapped_lines() {
        assert_eq!(wrap("> > one two three", 11), ["> > one two", "> > three"]);
        assert_eq!(
            wrap("  • alpha beta gamma", 14),
            ["  • alpha beta", "    gamma"]
        );
        assert_eq!(wrap("> • xx yy", 8), ["> • xx", ">   yy"]);
        assert_eq!(
            wrap("> • xx yy", 6),
            ["> • xx", "yy"],
            "too narrow to indent"
        );
        assert_eq!(wrap(">", 10), [">"]);
    }

    #[test]
    fn character_wrap_ignores_spaces() {
        assert_eq!(
            wrap_chars("https://e.com/abc", 8),
            ["https://", "e.com/ab", "c"]
        );
        assert_eq!(wrap_chars("", 4), [""]);
    }

    #[test]
    fn wraps_at_spaces_and_inside_long_words() {
        assert_eq!(wrap("the quick brown fox", 9), ["the quick", "brown fox"]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("a\n\nb", 10), ["a", "", "b"]);
        assert_eq!(
            wrap("  indented text here", 10),
            ["  indented", "  text", "  here"]
        );
    }

    #[test]
    fn counts_display_width_and_expands_tabs() {
        assert_eq!(width("日本"), 4);
        assert_eq!(wrap("日本語の文", 4), ["日本", "語の", "文"]);
        assert_eq!(wrap("a\tb", 10), ["a   b"]);
    }

    #[test]
    fn truncates_by_display_width() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("日本語", 4), "日…");
        assert_eq!(truncate("abc", 0), "");
    }
}
