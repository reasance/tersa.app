// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Terminal rendering of cached RFC 5322 messages (ADR 0031).
//!
//! MIME structure, transfer encodings, charsets, and encoded header words are
//! decoded by `mail-parser`. HTML bodies go through [`crate::html`], so nothing
//! remote is ever fetched. Every string leaves this module as [`SafeText`].

use std::fmt::{self, Write as _};

use mail_parser::{Address, MessageParser, MessagePart, MimeHeaders};

use crate::html::{self, html_to_text};
use crate::terminal::SafeText;

/// The most addresses shown per header.
pub const MAX_ADDRESSES: usize = 50;
/// The most attachments listed.
pub const MAX_ATTACHMENTS: usize = 100;
/// The largest plain-text body shown.
pub const MAX_PLAIN_OUTPUT: usize = html::MAX_TEXT_OUTPUT;
/// The most MIME parts, at every nesting level, a message may have to be
/// shown. `mail-parser` builds every part before returning, with no limit of
/// its own, so a 64 MiB message of tiny parts would allocate millions.
pub const MAX_MIME_PARTS: usize = 5_000;
/// How deep `mail-parser` parses messages attached to messages.
const NESTED_DEPTH: usize = 3;
const TRUNCATED: &str = "[… message truncated]";
const UNREADABLE: &str = "This message could not be read.";
const TOO_MANY_PARTS: &str = "This message has too many parts to show.";

/// Which body the reader would rather see.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BodyPreference {
    /// The plain-text part, falling back to converted HTML.
    #[default]
    Plain,
    /// Converted HTML, falling back to the plain-text part.
    Html,
}

/// Which body was rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFormat {
    /// A `text/plain` part.
    Plain,
    /// A `text/html` part converted to text.
    Html,
}

/// An attachment as listed to the reader. Nothing is opened or saved here.
#[derive(Clone, Eq, PartialEq)]
pub struct AttachmentSummary {
    /// The file name the sender gave, sanitized.
    pub name: SafeText,
    /// The declared MIME type, such as `application/pdf`.
    pub mime_type: SafeText,
    /// The decoded size in bytes.
    pub size: usize,
}

/// A message ready for display.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedMessage {
    /// The decoded subject.
    pub subject: SafeText,
    /// `From`, as `Name <address>` entries.
    pub from: SafeText,
    /// `To`, as `Name <address>` entries.
    pub to: SafeText,
    /// `Cc`, as `Name <address>` entries.
    pub cc: SafeText,
    /// The body text; may contain newlines and tabs.
    pub body: SafeText,
    /// The part the body came from, or `None` when there is no readable body.
    pub format: Option<BodyFormat>,
    /// Whether the other body format also exists, so the reader can switch.
    pub has_alternative: bool,
    /// Link targets referenced as `[n]` in an HTML body.
    pub links: Vec<SafeText>,
    /// The message's attachments.
    pub attachments: Vec<AttachmentSummary>,
}

impl fmt::Debug for AttachmentSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentSummary")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RenderedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Message content is personal data; keep it out of logs.
        formatter
            .debug_struct("RenderedMessage")
            .field("format", &self.format)
            .field("body_len", &self.body.as_str().len())
            .field("links", &self.links.len())
            .field("attachments", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

/// Renders a raw RFC 5322 message for the terminal.
#[must_use]
pub fn render_message(raw: &[u8], preference: BodyPreference) -> RenderedMessage {
    if part_bound(raw, NESTED_DEPTH, MAX_MIME_PARTS) > MAX_MIME_PARTS {
        // Only the headers are parsed, which costs no more than their size.
        let headers = MessageParser::default().parse_headers(raw);
        return RenderedMessage {
            subject: SafeText::single_line(
                headers
                    .as_ref()
                    .and_then(mail_parser::Message::subject)
                    .unwrap_or_default(),
            ),
            from: addresses(headers.as_ref().and_then(mail_parser::Message::from)),
            to: addresses(headers.as_ref().and_then(mail_parser::Message::to)),
            cc: addresses(headers.as_ref().and_then(mail_parser::Message::cc)),
            body: SafeText::multi_line(TOO_MANY_PARTS),
            format: None,
            has_alternative: false,
            links: Vec::new(),
            attachments: Vec::new(),
        };
    }
    let Some(message) = MessageParser::default().parse(raw) else {
        return RenderedMessage {
            subject: SafeText::default(),
            from: SafeText::default(),
            to: SafeText::default(),
            cc: SafeText::default(),
            body: SafeText::multi_line(UNREADABLE),
            format: None,
            has_alternative: false,
            links: Vec::new(),
            attachments: Vec::new(),
        };
    };
    // A `multipart/mixed` message lists every inline text part as body, as in
    // text, an inline image, then more text. All of them are shown, in order.
    let plain: Vec<&str> = message
        .text_bodies()
        .filter(|part| !part.is_text_html())
        .filter_map(readable)
        .collect();
    let html_parts: Vec<&MessagePart<'_>> = message
        .html_bodies()
        .filter(|part| readable(part).is_some())
        .collect();
    let has_html = html_parts.iter().any(|part| part.is_text_html());
    let format = match (preference, plain.is_empty(), has_html) {
        (BodyPreference::Html, _, true) | (BodyPreference::Plain, true, true) => {
            Some(BodyFormat::Html)
        }
        (_, false, _) => Some(BodyFormat::Plain),
        (_, true, false) => None,
    };
    let (body, links) = match format {
        Some(BodyFormat::Plain) => (plain_text(&joined_plain(&plain)), Vec::new()),
        Some(BodyFormat::Html) => {
            let converted = html_to_text(&joined_html(&html_parts));
            (converted.text, converted.links)
        }
        None => (String::new(), Vec::new()),
    };
    let attachments = message
        .attachments()
        .take(MAX_ATTACHMENTS)
        .map(|part| AttachmentSummary {
            name: SafeText::single_line(part.attachment_name().unwrap_or("(unnamed)")),
            mime_type: SafeText::single_line(&part.content_type().map_or_else(
                || "application/octet-stream".to_owned(),
                |kind| match kind.subtype() {
                    Some(subtype) => format!("{}/{subtype}", kind.ctype()),
                    None => kind.ctype().to_owned(),
                },
            )),
            size: part.len(),
        })
        .collect();
    RenderedMessage {
        subject: SafeText::single_line(message.subject().unwrap_or_default()),
        from: addresses(message.from()),
        to: addresses(message.to()),
        cc: addresses(message.cc()),
        body: SafeText::multi_line(&body),
        format,
        has_alternative: !plain.is_empty() && has_html,
        links: links
            .iter()
            .map(|link| SafeText::single_line(link))
            .collect(),
        attachments,
    }
}

/// An upper bound on the parts `mail-parser` builds for `raw`, counted
/// without building them; it stops counting once it passes `limit`.
///
/// Every part after the first starts at a boundary line, and a boundary line
/// starts with `--`, so the lines that do bound the parts at this level. A
/// quoted-printable attached message keeps its boundary lines readable here,
/// but a base64 one hides them, so such a part is decoded and counted too, as
/// deep as `mail-parser` goes. That is any part declared `message/rfc822` or
/// `message/global`, or with no type, which a digest treats as a message.
fn part_bound(raw: &[u8], depth: usize, limit: usize) -> usize {
    let mut count = 1;
    let mut headers = PartHeaders::default();
    let mut in_headers = true;
    // Where the body of a base64 attached message starts.
    let mut nested_body: Option<usize> = None;
    let mut offset = 0;
    while offset < raw.len() && count <= limit {
        let end = raw[offset..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(raw.len(), |position| offset + position + 1);
        let line = &raw[offset..end];
        let content = line.trim_ascii_end();
        if content.starts_with(b"--") {
            if let Some(start) = nested_body.take() {
                count += nested_bound(&raw[start..offset], depth, limit - count);
            }
            count += 1;
            headers = PartHeaders::default();
            in_headers = true;
        } else if in_headers {
            if content.is_empty() {
                in_headers = false;
                if depth > 0 && headers.is_encoded_message() {
                    nested_body = Some(end);
                }
            } else {
                headers.line(content);
            }
        }
        offset = end;
    }
    if let Some(start) = nested_body
        && count <= limit
    {
        count += nested_bound(&raw[start..], depth, limit - count);
    }
    count
}

/// The parts inside a base64 attached message whose body is `encoded`.
fn nested_bound(encoded: &[u8], depth: usize, limit: usize) -> usize {
    mail_parser::decoders::base64::base64_decode(encoded)
        .map_or(0, |decoded| part_bound(&decoded, depth - 1, limit))
}

/// What [`part_bound`] needs from one part's headers.
#[derive(Default)]
struct PartHeaders {
    /// The header being read, lowercased, kept short; folded lines join it.
    current: Vec<u8>,
    typed: bool,
    message: bool,
    base64: bool,
}

impl PartHeaders {
    /// The most bytes of one header kept: its name and the start of its value.
    const KEPT: usize = 128;

    fn line(&mut self, line: &[u8]) {
        if !line.starts_with(b" ") && !line.starts_with(b"\t") {
            self.finish();
        }
        for &byte in line
            .iter()
            .take(Self::KEPT.saturating_sub(self.current.len()))
        {
            self.current.push(byte.to_ascii_lowercase());
        }
    }

    fn finish(&mut self) {
        let header = std::mem::take(&mut self.current);
        let Some(colon) = header.iter().position(|&byte| byte == b':') else {
            return;
        };
        let value: Vec<u8> = header[colon + 1..]
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        match header[..colon].trim_ascii() {
            b"content-type" => {
                self.typed = true;
                self.message =
                    value.starts_with(b"message/rfc822") || value.starts_with(b"message/global");
            }
            b"content-transfer-encoding" => self.base64 = value.starts_with(b"base64"),
            _ => {}
        }
    }

    fn is_encoded_message(&mut self) -> bool {
        self.finish();
        self.base64 && (self.message || !self.typed)
    }
}

/// A text part's non-blank content. The body lists also hold inline
/// binaries (images, SVG source), and a text part can be blank.
fn readable<'a>(part: &'a MessagePart<'a>) -> Option<&'a str> {
    part.text_contents()
        .filter(|text| part.is_text() && !text.trim().is_empty())
}

/// The plain-text parts, a blank line apart. The result stops growing past
/// the output cap, so [`plain_text`] then marks it truncated.
fn joined_plain(parts: &[&str]) -> String {
    let mut joined = String::new();
    for part in parts {
        if joined.len() > MAX_PLAIN_OUTPUT {
            break;
        }
        if !joined.is_empty() {
            joined.push_str("\n\n");
        }
        joined.push_str(part);
    }
    joined
}

/// The HTML body parts as one document, so links are numbered across all of
/// them. A plain-text part among them is escaped and kept preformatted. The
/// result stops growing past the converter's input cap, which then marks it
/// truncated.
fn joined_html(parts: &[&MessagePart<'_>]) -> String {
    let mut joined = String::new();
    for part in parts {
        if joined.len() > html::MAX_HTML_INPUT {
            break;
        }
        let Some(text) = readable(part) else {
            continue;
        };
        if !joined.is_empty() {
            joined.push_str("<p></p>");
        }
        if part.is_text_html() {
            joined.push_str(text);
        } else {
            joined.push_str("<pre>");
            for character in text.chars() {
                match character {
                    '&' => joined.push_str("&amp;"),
                    '<' => joined.push_str("&lt;"),
                    '>' => joined.push_str("&gt;"),
                    other => joined.push(other),
                }
            }
            joined.push_str("</pre>");
        }
    }
    joined
}

/// Normalizes line endings, trims trailing spaces, keeps at most one blank
/// line in a row, and caps the size.
fn plain_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_PLAIN_OUTPUT));
    let mut blank = true;
    for line in text.split('\n') {
        let line = line.trim_end();
        if line.is_empty() {
            if blank {
                continue;
            }
            blank = true;
        } else {
            blank = false;
        }
        if out.len() + line.len() + 1 > MAX_PLAIN_OUTPUT {
            // Keep as much of the crossing line as fits, then the marker.
            let room = MAX_PLAIN_OUTPUT.saturating_sub(out.len());
            out.push_str(&line[..line.floor_char_boundary(room)]);
            out.push('\n');
            out.push_str(TRUNCATED);
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_end().to_owned()
}

fn addresses(header: Option<&Address<'_>>) -> SafeText {
    let Some(header) = header else {
        return SafeText::default();
    };
    let mut parts: Vec<String> = Vec::new();
    let mut total = 0_usize;
    for entry in header.iter() {
        total += 1;
        if parts.len() == MAX_ADDRESSES {
            continue;
        }
        let name = entry.name().map(str::trim).filter(|name| !name.is_empty());
        let address = entry
            .address()
            .map(str::trim)
            .filter(|address| !address.is_empty());
        parts.push(match (name, address) {
            (Some(name), Some(address)) if name != address => format!("{name} <{address}>"),
            (_, Some(address)) => address.to_owned(),
            (Some(name), None) => name.to_owned(),
            (None, None) => continue,
        });
    }
    let mut joined = parts.join(", ");
    if total > MAX_ADDRESSES {
        let _ = write!(joined, ", … and {} more", total - MAX_ADDRESSES);
    }
    SafeText::single_line(&joined)
}

#[cfg(test)]
mod tests {
    use super::{
        BodyFormat, BodyPreference, MAX_MIME_PARTS, MAX_PLAIN_OUTPUT, TOO_MANY_PARTS, TRUNCATED,
        render_message,
    };

    /// A multipart message with `parts` tiny text parts.
    fn many_parts(parts: usize) -> String {
        let mut raw =
            String::from("Subject: many\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n");
        for _ in 0..parts {
            raw.push_str("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n");
        }
        raw.push_str("--b--\r\n");
        raw
    }

    /// Standard base64 with line breaks every 76 characters, as MIME sends it.
    fn base64_lines(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = Vec::new();
        for chunk in bytes.chunks(3) {
            let word = chunk
                .iter()
                .enumerate()
                .fold(0_u32, |word, (index, &byte)| {
                    word | u32::from(byte) << (16 - 8 * index)
                });
            for index in 0..4 {
                encoded.push(if index <= chunk.len() {
                    ALPHABET[(word >> (18 - 6 * index) & 63) as usize]
                } else {
                    b'='
                });
            }
        }
        encoded
            .chunks(76)
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n")
    }

    const ALTERNATIVE: &[u8] = b"From: =?utf-8?q?Ren=C3=A9e?= <renee@example.com>\r\n\
To: a@example.com, \"B, Person\" <b@example.com>\r\n\
Subject: =?utf-8?B?Q2lhbyDwn5GL?=\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=iso-8859-1\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Caff=E8 at 10?   \r\n\
\r\n\
--b\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PHA+Q2FmZsOoIDxhIGhyZWY9Imh0dHBzOi8vZXhhbXBsZS5jb20iPmF0IDEwPC9hPj88L3A+\r\n\
--b--\r\n";

    #[test]
    fn decodes_headers_charsets_and_transfer_encodings() {
        let plain = render_message(ALTERNATIVE, BodyPreference::Plain);
        assert_eq!(plain.subject.as_str(), "Ciao 👋");
        assert_eq!(plain.from.as_str(), "Renée <renee@example.com>");
        assert_eq!(
            plain.to.as_str(),
            "a@example.com, B, Person <b@example.com>"
        );
        assert_eq!(plain.body.as_str(), "Caffè at 10?");
        assert_eq!(plain.format, Some(BodyFormat::Plain));
        assert!(plain.has_alternative);
        assert!(plain.links.is_empty());

        let html = render_message(ALTERNATIVE, BodyPreference::Html);
        assert_eq!(html.body.as_str(), "Caffè at 10 [1]?");
        assert_eq!(html.format, Some(BodyFormat::Html));
        assert_eq!(html.links[0].as_str(), "https://example.com");
    }

    #[test]
    fn html_only_messages_fall_back_to_converted_html() {
        let raw = b"Subject: s\r\nContent-Type: text/html\r\n\r\n<p>only <b>html</b></p>";
        let rendered = render_message(raw, BodyPreference::Plain);
        assert_eq!(rendered.body.as_str(), "only html");
        assert_eq!(rendered.format, Some(BodyFormat::Html));
        assert!(!rendered.has_alternative);
    }

    #[test]
    fn terminal_controls_are_removed_everywhere() {
        let raw = "Subject: \u{1b}]0;pwned\u{7}hi\u{202e}x\r\n\
From: \"\u{1b}[31mEvil\" <e@example.com>\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
safe\u{1b}[2J\u{9b}31m text\u{200b}\r\n";
        let rendered = render_message(raw.as_bytes(), BodyPreference::Plain);
        for text in [&rendered.subject, &rendered.from, &rendered.body] {
            assert!(
                !text.as_str().chars().any(|character| character == '\u{1b}'
                    || character == '\u{9b}'
                    || character == '\u{7}'
                    || character == '\u{202e}'
                    || character == '\u{200b}'),
                "{:?}",
                text.as_str()
            );
        }
        assert_eq!(rendered.body.as_str(), "safe[2J31m text");
    }

    #[test]
    fn attachments_are_listed_not_opened() {
        let raw = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
--x\r\nContent-Type: application/pdf; name=\"../../etc/\x1b[0mreport.pdf\"\r\n\
Content-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n";
        let rendered = render_message(raw, BodyPreference::Plain);
        assert_eq!(rendered.body.as_str(), "see attached");
        assert_eq!(rendered.attachments.len(), 1);
        let attachment = &rendered.attachments[0];
        assert_eq!(attachment.mime_type.as_str(), "application/pdf");
        assert_eq!(attachment.size, 5);
        assert!(!attachment.name.as_str().contains('\u{1b}'));
    }

    #[test]
    fn inline_images_and_blank_parts_do_not_hide_the_text() {
        let image_first = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: image/jpeg\r\nContent-Disposition: inline\r\n\
Content-Transfer-Encoding: base64\r\n\r\n/9j/4AAQ\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nHi\r\n--x--\r\n";
        let rendered = render_message(image_first, BodyPreference::Plain);
        assert_eq!(rendered.body.as_str(), "Hi");
        assert_eq!(rendered.format, Some(BodyFormat::Plain));

        let svg_first = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: image/svg+xml\r\nContent-Disposition: inline\r\n\r\n\
<svg xmlns=\"http://www.w3.org/2000/svg\"/>\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nHi\r\n--x--\r\n";
        let rendered = render_message(svg_first, BodyPreference::Html);
        assert_eq!(rendered.body.as_str(), "Hi");
        assert!(!rendered.has_alternative);

        let blank_first = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/plain\r\n\r\n  \r\n\
--x\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--x--\r\n";
        let rendered = render_message(blank_first, BodyPreference::Plain);
        assert_eq!(rendered.body.as_str(), "second");
    }

    #[test]
    fn every_inline_text_part_is_shown_in_order() {
        // Apple Mail style: text, an inline image, more text.
        let mixed = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nSee the photo:\r\n\
--x\r\nContent-Type: image/jpeg\r\nContent-Disposition: inline\r\n\
Content-Transfer-Encoding: base64\r\n\r\n/9j/4AAQ\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nThanks, Bob\r\n--x--\r\n";
        for preference in [BodyPreference::Plain, BodyPreference::Html] {
            let rendered = render_message(mixed, preference);
            assert_eq!(rendered.body.as_str(), "See the photo:\n\nThanks, Bob");
            assert_eq!(rendered.format, Some(BodyFormat::Plain));
        }

        // An alternative body followed by a plain footer, as mailing lists add.
        let footer = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: multipart/alternative; boundary=y\r\n\r\n\
--y\r\nContent-Type: text/plain\r\n\r\nBody\r\n\
--y\r\nContent-Type: text/html\r\n\r\n<p><a href=\"https://a.example\">Body</a></p>\r\n\
--y--\r\n\
--x\r\nContent-Type: text/plain\r\n\r\n-- \r\nlist <footer> & co\r\n--x--\r\n";
        let plain = render_message(footer, BodyPreference::Plain);
        assert_eq!(plain.body.as_str(), "Body\n\n--\nlist <footer> & co");
        assert!(plain.has_alternative);
        let html = render_message(footer, BodyPreference::Html);
        assert_eq!(html.format, Some(BodyFormat::Html));
        assert!(
            html.body.as_str().starts_with("Body"),
            "{:?}",
            html.body.as_str()
        );
        assert!(
            html.body.as_str().contains("list <footer> & co"),
            "{:?}",
            html.body.as_str()
        );
        assert_eq!(html.links.len(), 1);
    }

    #[test]
    fn garbage_and_empty_input_do_not_panic() {
        for raw in [
            &b""[..],
            b"\xff\xfe\x00",
            b"no headers at all",
            b"Content-Type: multipart/mixed\r\n\r\n--",
        ] {
            let rendered = render_message(raw, BodyPreference::Html);
            assert!(rendered.body.as_str().len() < 1024);
        }
    }

    #[test]
    fn redacted_debug_output() {
        let rendered = render_message(ALTERNATIVE, BodyPreference::Plain);
        let debug = format!("{rendered:?}");
        assert!(!debug.contains("Caff"));
        assert!(!debug.contains("renee"));
    }

    #[test]
    fn a_line_crossing_the_size_cap_is_kept_up_to_the_cap() {
        let mut raw = b"Subject: s\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        raw.extend("é".repeat(300_000).as_bytes());
        let rendered = render_message(&raw, BodyPreference::Plain);
        let body = rendered.body.as_str();
        assert!(body.ends_with(TRUNCATED));
        assert!(body.len() > MAX_PLAIN_OUTPUT - 8, "{}", body.len());
        assert!(body.len() <= MAX_PLAIN_OUTPUT + 2 + TRUNCATED.len());
    }

    /// A cheap, deterministic stand-in for fuzzing: random soups of MIME
    /// fragments must never panic, and every rendered field must be free of
    /// terminal controls.
    #[test]
    fn random_mime_soup_never_panics_or_leaks_controls() {
        const FRAGMENTS: [&str; 26] = [
            "\r\n",
            "\r\n\r\n",
            "Subject: ",
            "From: ",
            "To: ",
            "Content-Type: multipart/mixed; boundary=b\r\n",
            "Content-Type: multipart/alternative; boundary=\"b\"\r\n",
            "Content-Type: text/html; charset=",
            "Content-Type: text/plain; charset=utf-16\r\n",
            "iso-2022-jp",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "Content-Disposition: attachment; filename=\"",
            "--b\r\n",
            "--b--\r\n",
            "=?utf-8?b?",
            "=?utf-8?q?=1B]52;",
            "?=",
            "=1B[2J",
            "\u{1b}]8;;x\u{7}",
            "\u{202e}",
            "<a href=\"https://e.com/&#27;\">",
            "&#x9b;",
            "PHA+",
            "é😀",
            "\"",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for round in 0..1_500 {
            let mut raw = String::new();
            for _ in 0..48 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                raw.push_str(FRAGMENTS[usize::try_from(state % 26).expect("index")]);
            }
            let preference = if round % 2 == 0 {
                BodyPreference::Html
            } else {
                BodyPreference::Plain
            };
            let rendered = render_message(raw.as_bytes(), preference);
            let mut texts = vec![
                &rendered.subject,
                &rendered.from,
                &rendered.to,
                &rendered.cc,
                &rendered.body,
            ];
            texts.extend(rendered.links.iter());
            texts.extend(
                rendered
                    .attachments
                    .iter()
                    .map(|attachment| &attachment.name),
            );
            for text in texts {
                assert!(
                    !text
                        .as_str()
                        .chars()
                        .any(|character| (character.is_control()
                            && character != '\n'
                            && character != '\t')
                            || ('\u{202a}'..='\u{202e}').contains(&character)),
                    "{:?}",
                    text.as_str()
                );
            }
        }
    }

    #[test]
    fn a_message_with_too_many_parts_shows_only_its_headers() {
        let fine = render_message(
            many_parts(MAX_MIME_PARTS - 10).as_bytes(),
            BodyPreference::Plain,
        );
        assert!(
            fine.body.as_str().starts_with('x'),
            "{:?}",
            &fine.body.as_str()[..20]
        );

        let flood = render_message(many_parts(MAX_MIME_PARTS).as_bytes(), BodyPreference::Plain);
        assert_eq!(flood.subject.as_str(), "many");
        assert_eq!(flood.body.as_str(), TOO_MANY_PARTS);
        assert_eq!(flood.format, None);
    }

    #[test]
    fn parts_hidden_in_a_base64_attached_message_are_counted() {
        let inner = many_parts(MAX_MIME_PARTS);
        for content_type in [
            "Content-Type: message/rfc822",
            "Content-Type:\r\n Message/RFC822",
            // No type: a digest would parse it as a message, so it counts.
            "Content-Disposition: attachment",
        ] {
            let raw = format!(
                "Subject: outer\r\nContent-Type: multipart/mixed; boundary=o\r\n\r\n\
--o\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
--o\r\n{content_type}\r\nContent-Transfer-Encoding: BASE64\r\n\r\n{}\r\n--o--\r\n",
                base64_lines(inner.as_bytes())
            );
            let rendered = render_message(raw.as_bytes(), BodyPreference::Plain);
            assert_eq!(rendered.body.as_str(), TOO_MANY_PARTS, "{content_type:?}");
            assert_eq!(rendered.subject.as_str(), "outer");
        }

        // A small attached message is shown as usual.
        let small = format!(
            "Subject: outer\r\nContent-Type: multipart/mixed; boundary=o\r\n\r\n\
--o\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
--o\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--o--\r\n",
            base64_lines(many_parts(3).as_bytes())
        );
        let rendered = render_message(small.as_bytes(), BodyPreference::Plain);
        assert!(rendered.body.as_str().starts_with("see attached"));
    }
}
