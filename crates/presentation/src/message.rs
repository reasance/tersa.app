// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Terminal rendering of cached RFC 5322 messages (ADR 0031).
//!
//! MIME structure, transfer encodings, charsets, and encoded header words are
//! decoded by `mail-parser`. HTML bodies go through [`crate::html`], so nothing
//! remote is ever fetched. Every string leaves this module as [`SafeText`].

use std::borrow::Cow;
use std::fmt::{self, Write as _};

use mail_parser::decoders::DecodeFnc;
use mail_parser::parsers::MessageStream;
use mail_parser::{
    Address, ContentType, GetHeader, HeaderName, HeaderValue, MessageParser, MessagePart,
    MimeHeaders,
};

use crate::html::{self, html_parts_to_text};
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
/// The longest MIME boundary accepted; RFC 2046 allows 70 characters.
/// `mail-parser` compares the whole boundary at every `--` it meets, so a
/// boundary of megabytes of dashes over a body of dashes takes minutes.
pub const MAX_BOUNDARY_LEN: usize = 100;
/// How deep `mail-parser` 0.11.9 parses encoded messages attached to messages.
const NESTED_DEPTH: usize = 3;
/// The most bytes of a message given to `mail-parser`. Whatever the counting
/// below misses, this bounds what one message can cost, at about 25 bytes of
/// parser structures per input byte. Text bodies come first and the
/// converters keep far less, so a longer message loses only attachments.
pub const MAX_PARSED_LEN: usize = 4 * 1024 * 1024;
const CUT: &str = "[… the rest of this message is over 4 MiB and is not shown, \
                   including any attachments there]";
const TRUNCATED: &str = "[… message truncated]";
const UNREADABLE: &str = "This message could not be read.";
const TOO_COMPLEX: &str =
    "This message is too complex to show: it has too many parts or an over-long boundary.";

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
    let cut = raw.len() > MAX_PARSED_LEN;
    let raw = &raw[..raw.len().min(MAX_PARSED_LEN)];
    if count_parts(raw, NESTED_DEPTH, MAX_MIME_PARTS) > MAX_MIME_PARTS {
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
            body: SafeText::multi_line(TOO_COMPLEX),
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
            let converted = html_parts_to_text(&html_documents(&html_parts));
            (converted.text, converted.links)
        }
        None => (String::new(), Vec::new()),
    };
    let body = if cut {
        let mut body = body;
        if !body.is_empty() {
            body.push_str("\n\n");
        }
        body.push_str(CUT);
        body
    } else {
        body
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

/// The parts `mail-parser` 0.11.9 builds for `raw`, counted without building
/// them; counting stops once it passes `limit`.
///
/// This walks `raw` with the parser's own public stream functions in the
/// order `MessageParser::parse` does: the same header parser, the same
/// boundary search (a boundary counts anywhere in a line), the same
/// transfer-encoding decoders, and the same nesting into attached messages,
/// up to [`NESTED_DEPTH`] for encoded ones. `mail-parser` is pinned to that
/// version, and a test checks the count against real parses. A boundary
/// longer than [`MAX_BOUNDARY_LEN`] counts as past `limit`.
fn count_parts(raw: &[u8], depth: usize, limit: usize) -> usize {
    let parser = MessageParser::default();
    let mut stream = MessageStream::new(raw);
    let mut count = 0;
    let mut state = Walk::default();
    // Each entry is the state to restore and whether it was pushed when
    // entering an unencoded attached message.
    let mut stack: Vec<(Walk, bool)> = Vec::new();
    let mut headers = Vec::new();
    'outer: loop {
        if count > limit {
            break;
        }
        headers.clear();
        if !stream.parse_headers(&parser, &mut headers) {
            // Headers with no body still make one part.
            if count == 0 && !headers.is_empty() {
                count = 1;
            }
            break;
        }
        count += 1;
        let content_type = headers
            .header_value(&HeaderName::ContentType)
            .and_then(HeaderValue::as_content_type);
        let (multipart, mut message) = classify(content_type, state.digest);
        if multipart
            && let Some(boundary) = content_type.and_then(|kind| kind.attribute("boundary"))
        {
            if boundary.len() > MAX_BOUNDARY_LEN {
                // Counts as too many parts, before any search can start.
                return limit.saturating_add(1);
            }
            if stream.seek_next_part(boundary.as_bytes()) {
                let digest = content_type.and_then(ContentType::subtype) == Some("digest");
                stack.push((std::mem::take(&mut state), false));
                state = Walk {
                    message: false,
                    digest,
                    boundary: Some(boundary.as_bytes().to_vec()),
                };
                stream.skip_crlf();
                continue;
            }
            message = false;
        }
        let decode = match transfer_decoder(&headers) {
            Some(decode) => decode,
            None if message => {
                // An unencoded attached message is parsed in place.
                let boundary = state.boundary.take();
                stack.push((std::mem::take(&mut state), true));
                state = Walk {
                    message: true,
                    digest: false,
                    boundary,
                };
                continue;
            }
            None => MessageStream::mime_part,
        };
        let (end, bytes) = decode(&mut stream, state.boundary.as_deref().unwrap_or_default());
        if end == usize::MAX {
            // The parser keeps an undecodable part as text.
            message = false;
            let (_, found) = stream.seek_part_end(state.boundary.as_deref());
            if !found {
                state.boundary = None;
            }
        }
        if message && depth > 0 {
            count =
                count.saturating_add(count_parts(&bytes, depth - 1, limit.saturating_sub(count)));
        }
        if state.boundary.is_some() {
            loop {
                if state.message {
                    // The attached message ended; its parent goes on.
                    match stack.pop() {
                        Some((mut parent, true)) => {
                            parent.boundary = state.boundary.take();
                            state = parent;
                        }
                        _ => break 'outer,
                    }
                }
                if !stream.is_multipart_end() {
                    break;
                }
                let Some((parent, _)) = stack.pop() else {
                    break 'outer;
                };
                state = parent;
                if let Some(boundary) = state.boundary.as_deref()
                    && stream.seek_next_part_offset(boundary).is_some()
                {
                    continue;
                }
                break 'outer;
            }
        } else if stream.offset() >= raw.len() {
            break;
        }
    }
    count
}

/// The decoder `mail-parser` uses for a part's transfer encoding, or `None`
/// when the part is not base64 or quoted-printable.
fn transfer_decoder<'x>(headers: &Vec<mail_parser::Header<'_>>) -> Option<DecodeFnc<'x>> {
    match headers.header_value(&HeaderName::ContentTransferEncoding) {
        Some(HeaderValue::Text(encoding)) if encoding.eq_ignore_ascii_case("base64") => {
            Some(MessageStream::decode_base64_mime)
        }
        Some(HeaderValue::Text(encoding)) if encoding.eq_ignore_ascii_case("quoted-printable") => {
            Some(MessageStream::decode_quoted_printable_mime)
        }
        _ => None,
    }
}

/// Where [`count_parts`] is: inside an attached message or a digest, and
/// the boundary that ends the current part.
#[derive(Default)]
struct Walk {
    message: bool,
    digest: bool,
    boundary: Option<Vec<u8>>,
}

/// Whether a part is a multipart, and whether it is an attached message,
/// as `mail-parser` decides: an untyped part of a digest is a message.
fn classify(content_type: Option<&ContentType<'_>>, in_digest: bool) -> (bool, bool) {
    match content_type {
        Some(kind) => match kind.ctype() {
            "multipart" => (true, false),
            "message" => (false, matches!(kind.subtype(), Some("rfc822" | "global"))),
            _ => (false, false),
        },
        None => (false, in_digest),
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

/// The HTML body parts as documents for [`html_parts_to_text`], which parses
/// each on its own and numbers links across them. A plain-text part among
/// them is escaped and kept preformatted. Collecting stops past the
/// converter's input cap, which then marks the text truncated.
fn html_documents<'a>(parts: &[&'a MessagePart<'a>]) -> Vec<Cow<'a, str>> {
    let mut documents = Vec::new();
    let mut total = 0;
    for part in parts {
        if total > html::MAX_HTML_INPUT {
            break;
        }
        let Some(text) = readable(part) else {
            continue;
        };
        let document = if part.is_text_html() {
            Cow::Borrowed(text)
        } else {
            let mut escaped = String::with_capacity(text.len() + 11);
            escaped.push_str("<pre>");
            for character in text.chars() {
                match character {
                    '&' => escaped.push_str("&amp;"),
                    '<' => escaped.push_str("&lt;"),
                    '>' => escaped.push_str("&gt;"),
                    other => escaped.push(other),
                }
            }
            escaped.push_str("</pre>");
            Cow::Owned(escaped)
        };
        total += document.len();
        documents.push(document);
    }
    documents
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
    use mail_parser::{MessageParser, PartType};

    use super::{
        BodyFormat, BodyPreference, CUT, MAX_BOUNDARY_LEN, MAX_MIME_PARTS, MAX_PARSED_LEN,
        MAX_PLAIN_OUTPUT, NESTED_DEPTH, TOO_COMPLEX, TRUNCATED, count_parts, render_message,
    };

    /// Every part `mail-parser` built, nested messages included.
    fn built_parts(message: &mail_parser::Message<'_>) -> usize {
        message.parts.len()
            + message
                .parts
                .iter()
                .map(|part| match &part.body {
                    PartType::Message(nested) => built_parts(nested),
                    _ => 0,
                })
                .sum::<usize>()
    }

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
        // Multipart mixed body: text, an inline image, more text.
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
    fn markup_left_open_in_one_html_part_does_not_hide_the_next() {
        let raw = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/html\r\n\r\n<p>Reset your <a href=\"https://a.example\">password</a></p><!--\r\n\
--x\r\nContent-Type: text/html\r\n\r\n<p>This message failed <a href=\"https://b.example\">authentication</a>.</p><script>\r\n\
--x\r\nContent-Type: text/html\r\n\r\n<div hidden><p>third</p>\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nfooter\r\n--x--\r\n";
        let rendered = render_message(raw, BodyPreference::Html);
        assert_eq!(rendered.format, Some(BodyFormat::Html));
        let body = rendered.body.as_str();
        // An unclosed hidden element shows its content, as in one document.
        for shown in [
            "Reset your password [1]",
            "This message failed authentication [2].",
            "third",
            "footer",
        ] {
            assert!(body.contains(shown), "{shown:?} in {body:?}");
        }
        assert_eq!(rendered.links.len(), 2);
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
        assert_eq!(flood.body.as_str(), TOO_COMPLEX);
        assert_eq!(flood.format, None);
    }

    #[test]
    fn parts_hidden_in_a_base64_attached_message_are_counted() {
        let inner = many_parts(MAX_MIME_PARTS);
        for content_type in [
            "Content-Type: message/rfc822",
            "Content-Type:\r\n Message/RFC822",
        ] {
            let raw = format!(
                "Subject: outer\r\nContent-Type: multipart/mixed; boundary=o\r\n\r\n\
--o\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
--o\r\n{content_type}\r\nContent-Transfer-Encoding: BASE64\r\n\r\n{}\r\n--o--\r\n",
                base64_lines(inner.as_bytes())
            );
            let rendered = render_message(raw.as_bytes(), BodyPreference::Plain);
            assert_eq!(rendered.body.as_str(), TOO_COMPLEX, "{content_type:?}");
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

        // An untyped part of a mixed message is text, not a message, so the
        // parser never opens it and neither does the count.
        let untyped = format!(
            "Subject: outer\r\nContent-Type: multipart/mixed; boundary=o\r\n\r\n\
--o\r\nContent-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--o--\r\n",
            base64_lines(inner.as_bytes())
        );
        assert_eq!(count_parts(untyped.as_bytes(), NESTED_DEPTH, usize::MAX), 2);
    }

    /// Wraps `inner` as the body of a part attached to an outer message.
    fn attached(headers: &str, body: &str) -> String {
        format!(
            "Subject: outer\r\nContent-Type: multipart/mixed; boundary=o\r\n\r\n\
--o\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
--o\r\n{headers}\r\n\r\n{body}\r\n--o--\r\n"
        )
    }

    #[test]
    fn floods_written_the_ways_the_parser_still_reads_are_counted() {
        // Boundaries in the middle of a line.
        let mut mid_line =
            String::from("Subject: s\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n");
        for _ in 0..MAX_MIME_PARTS {
            mid_line.push_str("x--b\r\nContent-Type: text/plain\r\n\r\n");
        }
        // A quoted-printable attached message is not listed: the parser's
        // decoder stops at its first `--` line, so it never builds a flood;
        // the comparison test below covers that decoder.
        let encoded = base64_lines(many_parts(MAX_MIME_PARTS).as_bytes());
        // The encoding after a run of spaces, as an encoded word, and the type
        // after a long parameter.
        let spaced = attached(
            &format!(
                "Content-Type: message/rfc822\r\nContent-Transfer-Encoding:{}base64",
                " ".repeat(200)
            ),
            &encoded,
        );
        let worded = attached(
            "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: =?utf-8?Q?base64?=",
            &encoded,
        );
        let late_type = attached(
            &format!(
                "Content-Type: message/rfc822; x-pad=\"{}\"\r\nContent-Transfer-Encoding: base64",
                "p".repeat(200)
            ),
            &encoded,
        );
        for (name, raw) in [
            ("mid-line boundaries", &mid_line),
            ("spaced encoding", &spaced),
            ("encoded-word encoding", &worded),
            ("long type", &late_type),
        ] {
            let parsed = MessageParser::default()
                .parse(raw.as_bytes())
                .expect("parses");
            let built = built_parts(&parsed);
            let counted = count_parts(raw.as_bytes(), NESTED_DEPTH, usize::MAX);
            assert!(
                counted >= built && built > MAX_MIME_PARTS,
                "{name}: counted {counted}, built {built}"
            );
            assert_eq!(
                render_message(raw.as_bytes(), BodyPreference::Plain)
                    .body
                    .as_str(),
                TOO_COMPLEX,
                "{name}"
            );
        }
    }

    #[test]
    fn an_over_long_boundary_is_never_searched() {
        // The parser's search is quadratic in such a boundary over dashes.
        let raw = |length: usize| {
            let mut raw = format!(
                "Subject: s\r\nContent-Type: multipart/mixed; boundary=\"{}x\"\r\n\r\n",
                "-".repeat(length - 1)
            );
            raw.push_str(&"-".repeat(1_000_000));
            raw
        };
        let long = raw(MAX_BOUNDARY_LEN + 1);
        assert_eq!(
            count_parts(long.as_bytes(), NESTED_DEPTH, MAX_MIME_PARTS),
            MAX_MIME_PARTS + 1
        );
        let rendered = render_message(long.as_bytes(), BodyPreference::Plain);
        assert_eq!(rendered.body.as_str(), TOO_COMPLEX);
        assert_eq!(rendered.subject.as_str(), "s");
        let longest = raw(MAX_BOUNDARY_LEN);
        assert!(count_parts(longest.as_bytes(), NESTED_DEPTH, MAX_MIME_PARTS) <= MAX_MIME_PARTS);
    }

    #[test]
    fn the_count_matches_what_the_parser_builds() {
        const FRAGMENTS: [&str; 22] = [
            "\r\n",
            "\r\n\r\n",
            "Subject: s\r\n",
            "Content-Type: multipart/mixed; boundary=b\r\n",
            "Content-Type: multipart/digest; boundary=b\r\n",
            "Content-Type: multipart/alternative; boundary=\"c\"\r\n",
            "Content-Type: message/rfc822\r\n",
            "Content-Type: message/global\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "--b\r\n",
            "--b--\r\n",
            "x--b\r\n",
            "--c\r\n",
            "--c--\r\n",
            "=2D-b\r\n",
            "=\r\n",
            "text ",
            // `Content-Type: multipart/mixed; boundary=b`, a blank line, `--b`.
            "Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvbWl4ZWQ7IGJvdW5kYXJ5PWINCg0KLS1iDQo=\r\n",
            "LS1iDQoNCngNCi0tYi0tDQo=\r\n",
            "-",
        ];
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut skipped = 0;
        for _ in 0..4_000 {
            let mut raw = String::new();
            for _ in 0..40 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                raw.push_str(FRAGMENTS[usize::try_from(state % 22).expect("index")]);
            }
            // mail-parser has debug assertions that some malformed input
            // trips; release builds skip them. Those inputs are not compared.
            let Ok(built) = std::panic::catch_unwind(|| {
                MessageParser::default()
                    .parse(raw.as_bytes())
                    .map_or(0, |message| built_parts(&message))
            }) else {
                skipped += 1;
                continue;
            };
            let counted = count_parts(raw.as_bytes(), NESTED_DEPTH, usize::MAX);
            assert_eq!(counted, built, "{raw:?}");
        }
        assert!(
            skipped < 100,
            "{skipped} inputs tripped the parser's debug assertions"
        );
    }

    #[test]
    fn only_the_first_part_of_a_huge_message_is_parsed() {
        let mut raw = String::from(
            "Subject: big\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nthe text\r\n\
--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n",
        );
        while raw.len() <= MAX_PARSED_LEN {
            raw.push_str(&"QUFB".repeat(19));
            raw.push_str("\r\n");
        }
        raw.push_str("--b\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"late.png\"\r\n\r\nx\r\n--b--\r\n");
        let rendered = render_message(raw.as_bytes(), BodyPreference::Plain);
        assert_eq!(rendered.subject.as_str(), "big");
        assert!(rendered.body.as_str().starts_with("the text"));
        assert!(rendered.body.as_str().ends_with(CUT));
        assert!(
            rendered
                .attachments
                .iter()
                .all(|attachment| attachment.name.as_str() != "late.png"),
            "parts past the cut are not parsed"
        );
    }
}
