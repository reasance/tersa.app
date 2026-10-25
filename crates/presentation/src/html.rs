// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTML to plain text for terminal display (ADR 0031).
//!
//! A single forward pass over the input with no tree and no recursion, so the
//! cost is linear in the input and deeply nested or malformed markup cannot
//! exhaust the stack or take quadratic time. Nothing is fetched: images are
//! dropped, and links become numbered references listed after the text.
//!
//! The output is plain, unsanitized text; callers wrap it in
//! [`crate::terminal::SafeText`] before it reaches a terminal.

use crate::terminal::is_allowed;

/// The largest HTML input converted; the rest is dropped with a marker.
pub const MAX_HTML_INPUT: usize = 2 * 1024 * 1024;
/// The largest text output produced.
pub const MAX_TEXT_OUTPUT: usize = 512 * 1024;
/// The most links collected; later links keep their text but get no number.
pub const MAX_LINKS: usize = 500;
/// The longest link target kept.
pub const MAX_LINK_LEN: usize = 2048;
/// Nesting deeper than this is not indented further.
const MAX_INDENT: usize = 8;
/// The longest tag considered; longer tags are skipped as garbage.
const MAX_TAG_LEN: usize = 16 * 1024;
const TRUNCATED: &str = "[… message truncated]";

/// Plain text converted from HTML, with the links it referenced.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HtmlText {
    /// The readable text. Links appear as `text [n]`.
    pub text: String,
    /// Link targets; entry `i` is reference `[i + 1]`.
    pub links: Vec<String>,
}

/// Converts HTML to plain text.
#[must_use]
pub fn html_to_text(html: &str) -> HtmlText {
    html_parts_to_text(&[html])
}

/// Converts several HTML documents to one text, in order, a blank line
/// apart. Each document is parsed on its own, so markup one leaves open (an
/// unclosed comment, `<script>`, or hidden element) cannot hide the next.
/// Links are numbered across all of them, and the input and output caps apply
/// to the whole.
#[must_use]
pub fn html_parts_to_text<S: AsRef<str>>(parts: &[S]) -> HtmlText {
    let mut writer = Writer::default();
    let mut budget = MAX_HTML_INPUT;
    let mut input_truncated = false;
    for part in parts {
        if writer.full || input_truncated {
            break;
        }
        let part = part.as_ref();
        let input = if part.len() > budget {
            input_truncated = true;
            floor_char_boundary(part, budget)
        } else {
            part
        };
        budget -= input.len();
        writer.start_document();
        let mut rest = input;
        while !rest.is_empty() && !writer.full {
            rest = match rest.find('<') {
                None => {
                    writer.text(rest);
                    ""
                }
                Some(0) => writer.markup(rest),
                Some(at) => {
                    writer.text(&rest[..at]);
                    &rest[at..]
                }
            };
        }
    }
    if input_truncated && !writer.full {
        writer.paragraph();
        writer.push_raw(TRUNCATED);
    }
    writer.finish()
}

/// What a closing or opening tag does to the layout.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Block {
    /// Inline: no line structure.
    Inline,
    /// Starts and ends on its own line.
    Line,
    /// Separated from its neighbours by a blank line.
    Paragraph,
}

fn block_kind(name: &str) -> Block {
    match name {
        "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "table" | "ul" | "ol" | "dl" | "pre"
        | "blockquote" | "figure" | "address" => Block::Paragraph,
        "div" | "li" | "tr" | "section" | "article" | "header" | "footer" | "main" | "nav"
        | "aside" | "dt" | "dd" | "caption" | "center" | "form" | "fieldset" | "details"
        | "summary" | "tbody" | "thead" | "tfoot" => Block::Line,
        _ => Block::Inline,
    }
}

/// Elements whose content is never displayed.
fn is_hidden_container(name: &str) -> bool {
    matches!(
        name,
        "head"
            | "script"
            | "style"
            | "title"
            | "template"
            | "noscript"
            | "svg"
            | "math"
            | "object"
            | "iframe"
    )
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools, reason = "independent writer flags")]
struct Writer {
    out: String,
    links: Vec<String>,
    /// Whether the output ends in collapsible whitespace.
    pending_space: bool,
    /// Line breaks requested before the next text (0, 1, or 2).
    pending_breaks: u8,
    /// Whether any text has been written yet.
    started: bool,
    list_depth: usize,
    quote_depth: usize,
    pre_depth: usize,
    /// The open link's target, numbered only if it gets visible text.
    open_link: Option<String>,
    /// Where the open link's text starts in `out`.
    link_text_start: usize,
    /// Set after a hidden element or container had no closing tag, so later
    /// ones are shown rather than searched for again (keeps it linear).
    hiding_disabled: bool,
    full: bool,
}

impl Writer {
    /// Handles markup at the start of `input` and returns what follows it.
    fn markup<'a>(&mut self, input: &'a str) -> &'a str {
        if let Some(rest) = input.strip_prefix("<!--") {
            // `<!-->` and `<!--->` are complete, empty comments.
            if let Some(after) = rest.strip_prefix('>').or_else(|| rest.strip_prefix("->")) {
                return after;
            }
            return rest.find("-->").map_or("", |end| &rest[end + 3..]);
        }
        if input.starts_with("<!") || input.starts_with("<?") {
            return input.find('>').map_or("", |end| &input[end + 1..]);
        }
        let end = match scan_tag(input) {
            TagScan::End(end) => end,
            TagScan::Abort(stop) => {
                // Not a tag: show what was scanned as text, so every byte is
                // examined a bounded number of times.
                let stop = stop.max(1);
                self.text(&input[..stop]);
                return &input[stop..];
            }
        };
        let tag = &input[1..end];
        let rest = &input[end + 1..];
        let (closing, body) = match tag.strip_prefix('/') {
            Some(body) => (true, body),
            None => (false, tag),
        };
        let name_end = body
            .find(|character: char| character.is_ascii_whitespace() || character == '/')
            .unwrap_or(body.len());
        let name = body[..name_end].to_ascii_lowercase();
        if name.is_empty() || !name.starts_with(|character: char| character.is_ascii_alphabetic()) {
            // `<` followed by something that is not a tag name, as in `a < b`.
            self.text("<");
            return &input[1..];
        }
        if !closing && !self.hiding_disabled && is_hidden_container(&name) {
            if let Some(after) = skip_container(rest, &name) {
                return after;
            }
            // Never closed: show its content rather than drop the rest of the
            // message, and stop searching for later closings.
            self.hiding_disabled = true;
            return rest;
        }
        let attributes = &body[name_end..];
        if !closing && !self.hiding_disabled && is_hidden_by_markup(attributes) {
            if is_void(&name) || tag.ends_with('/') {
                return rest;
            }
            match skip_element(rest, &name) {
                Some(after) => return after,
                None => self.hiding_disabled = true,
            }
        }
        self.tag(&name, closing, attributes);
        rest
    }

    fn tag(&mut self, name: &str, closing: bool, attributes: &str) {
        match (name, closing) {
            ("br", _) => {
                // Consecutive breaks add up to one blank line.
                if self.started {
                    self.pending_breaks = (self.pending_breaks + 1).min(2);
                }
                self.pending_space = false;
            }
            ("hr", false) => {
                self.line_break(1);
                self.push_text_raw("──────────");
                self.line_break(1);
            }
            ("ul" | "ol" | "dl", false) => {
                self.list_depth += 1;
                self.paragraph();
            }
            ("ul" | "ol" | "dl", true) => {
                self.list_depth = self.list_depth.saturating_sub(1);
                self.paragraph();
            }
            ("li", false) => {
                self.line_break(1);
                let indent = self.list_depth.clamp(1, MAX_INDENT) - 1;
                self.push_text_raw(&"  ".repeat(indent));
                self.push_text_raw("• ");
                self.pending_space = false;
            }
            ("blockquote", false) => {
                self.quote_depth += 1;
                self.paragraph();
            }
            ("blockquote", true) => {
                self.paragraph();
                self.quote_depth = self.quote_depth.saturating_sub(1);
            }
            ("pre", false) => {
                self.pre_depth += 1;
                self.paragraph();
            }
            ("pre", true) => {
                self.pre_depth = self.pre_depth.saturating_sub(1);
                self.paragraph();
            }
            ("td" | "th", false) => {
                if self.started && !self.at_line_start() && self.pending_breaks == 0 {
                    self.push_text_raw("  ");
                    self.pending_space = false;
                }
            }
            ("a", false) => self.open_link(attributes),
            ("a", true) => self.close_link(),
            (other, _) => match block_kind(other) {
                Block::Inline => {}
                Block::Line => self.line_break(1),
                Block::Paragraph => self.paragraph(),
            },
        }
    }

    fn open_link(&mut self, attributes: &str) {
        self.close_link();
        let Some(target) = attribute(attributes, "href") else {
            return;
        };
        let target = decode_entities(target.trim());
        if !is_displayable_link(&target) {
            return;
        }
        self.open_link = Some(target);
        self.link_text_start = self.out.len();
    }

    /// Numbers the open link if it showed text other than its own address.
    /// Image-only links get no number, so references stay consecutive.
    fn close_link(&mut self) {
        let Some(target) = self.open_link.take() else {
            return;
        };
        let shown = self.out[self.link_text_start..].trim();
        let bare = target
            .strip_prefix("mailto:")
            .or_else(|| target.strip_prefix("https://"))
            .or_else(|| target.strip_prefix("http://"))
            .unwrap_or(&target);
        if shown.is_empty() || shown == target || shown == bare {
            return;
        }
        let index = match self.links.iter().position(|known| *known == target) {
            Some(index) => index,
            None if self.links.len() < MAX_LINKS => {
                self.links.push(target);
                self.links.len() - 1
            }
            None => return,
        };
        self.pending_space = false;
        self.push_text_raw(&format!(" [{}]", index + 1));
    }

    fn text(&mut self, raw: &str) {
        let decoded = decode_entities(raw);
        if self.pre_depth > 0 {
            for (number, line) in decoded.split('\n').enumerate() {
                if number > 0 {
                    self.line_break(1);
                }
                self.push_text_raw(line.trim_end_matches('\r'));
            }
            return;
        }
        for (index, word) in decoded.split(char::is_whitespace).enumerate() {
            if index > 0 {
                self.pending_space = true;
            }
            // Preheader padding (`&#847;&zwnj;` runs) is invisible on screen.
            if !word.chars().any(is_visible) {
                continue;
            }
            if self.pending_space
                && self.started
                && !self.at_line_start()
                && self.pending_breaks == 0
            {
                self.push_raw(" ");
            }
            self.pending_space = false;
            self.push_text_raw(word);
        }
    }

    /// Writes text, first emitting any pending line breaks and quote marks.
    fn push_text_raw(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if self.started && self.pending_breaks > 0 {
            for _ in 0..self.pending_breaks {
                self.push_raw("\n");
            }
        }
        if self.at_line_start() || !self.started {
            let marks = self.quote_depth.min(MAX_INDENT);
            for _ in 0..marks {
                self.push_raw("> ");
            }
        }
        self.pending_breaks = 0;
        self.started = true;
        self.push_raw(text);
    }

    fn push_raw(&mut self, text: &str) {
        if self.full {
            return;
        }
        if self.out.len() + text.len() > MAX_TEXT_OUTPUT {
            self.out.push_str(floor_char_boundary(
                text,
                MAX_TEXT_OUTPUT.saturating_sub(self.out.len()),
            ));
            self.out.push('\n');
            self.out.push_str(TRUNCATED);
            self.full = true;
            return;
        }
        self.out.push_str(text);
    }

    fn at_line_start(&self) -> bool {
        self.out.is_empty() || self.out.ends_with('\n')
    }

    fn line_break(&mut self, breaks: u8) {
        if self.started {
            self.pending_breaks = self.pending_breaks.max(breaks);
        }
        self.pending_space = false;
    }

    fn paragraph(&mut self) {
        self.line_break(2);
    }

    /// Ends whatever the previous document left open, keeping the output and
    /// the numbered links, and starts the next one on a new paragraph.
    fn start_document(&mut self) {
        self.close_link();
        self.list_depth = 0;
        self.quote_depth = 0;
        self.pre_depth = 0;
        self.hiding_disabled = false;
        if self.started {
            self.paragraph();
        }
    }

    fn finish(mut self) -> HtmlText {
        self.close_link();
        let text = collapse_blank_lines(&self.out);
        HtmlText {
            text,
            links: self.links,
        }
    }
}

enum TagScan {
    /// The index of the `>` that ends the tag.
    End(usize),
    /// Not a complete tag; the index where scanning stopped (an unquoted `<`,
    /// the length limit, or the end of input).
    Abort(usize),
}

/// Finds the `>` that ends the tag at the start of `input`, honouring quoted
/// attribute values.
fn scan_tag(input: &str) -> TagScan {
    let mut quote = None;
    for (at, byte) in input.bytes().enumerate().skip(1) {
        if at > MAX_TAG_LEN {
            return TagScan::Abort(floor_char_boundary(input, at).len());
        }
        match (quote, byte) {
            (None, b'"' | b'\'') => quote = Some(byte),
            (Some(open), _) if byte == open => quote = None,
            (None, b'>') => return TagScan::End(at),
            (None, b'<') => return TagScan::Abort(at),
            _ => {}
        }
    }
    TagScan::Abort(input.len())
}

/// Skips a hidden element's content up to its closing tag, in one pass.
fn skip_container<'a>(input: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(offset) = input[from..].find('<') {
        let at = from + offset;
        let candidate = &input.as_bytes()[at + 1..];
        let closes = candidate.first() == Some(&b'/')
            && candidate.len() > name.len()
            && candidate[1..=name.len()].eq_ignore_ascii_case(name.as_bytes());
        if closes {
            let after = &input[at..];
            return Some(after.find('>').map_or("", |end| &after[end + 1..]));
        }
        // `</head>` is optional: the body starts the visible content.
        if name == "head" && candidate.len() >= 4 && candidate[..4].eq_ignore_ascii_case(b"body") {
            return Some(&input[at..]);
        }
        from = at + 1;
    }
    None
}

/// Whether the element's own markup hides it: a `hidden` attribute or an
/// inline style with `display: none`, `visibility: hidden`, or Outlook's
/// `mso-hide: all`. Newsletters hide preview padding this way.
fn is_hidden_by_markup(attributes: &str) -> bool {
    if attributes.is_empty() {
        return false;
    }
    if has_attribute(attributes, "hidden") {
        return true;
    }
    let Some(style) = attribute(attributes, "style") else {
        return false;
    };
    let compact: String = style
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect();
    compact.contains("display:none")
        || compact.contains("visibility:hidden")
        || compact.contains("mso-hide:all")
}

fn is_void(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "source"
            | "track"
            | "wbr"
    )
}

/// Skips a hidden element's content through its matching closing tag,
/// counting nested elements of the same name. Returns `None` when it is
/// never closed.
fn skip_element<'a>(input: &'a str, name: &str) -> Option<&'a str> {
    let name = name.as_bytes();
    let bytes = input.as_bytes();
    let mut depth = 1_usize;
    let mut from = 0;
    while let Some(offset) = input[from..].find('<') {
        let at = from + offset;
        let (closing, start) = if bytes.get(at + 1) == Some(&b'/') {
            (true, at + 2)
        } else {
            (false, at + 1)
        };
        let matches = bytes.len() >= start + name.len()
            && bytes[start..start + name.len()].eq_ignore_ascii_case(name)
            && bytes
                .get(start + name.len())
                .is_none_or(|&next| next == b'>' || next == b'/' || next.is_ascii_whitespace());
        from = at + 1;
        if !matches {
            continue;
        }
        let end = input[at..].find('>').map(|end| at + end)?;
        if closing {
            depth -= 1;
            if depth == 0 {
                return Some(&input[end + 1..]);
            }
        } else if bytes[end - 1] != b'/' {
            depth += 1;
        }
        from = end + 1;
    }
    None
}

/// An attribute as written in a tag.
enum Attribute<'a> {
    Absent,
    /// Present without a value, as in `<span hidden>`.
    Bare,
    Value(&'a str),
}

fn has_attribute(attributes: &str, wanted: &str) -> bool {
    !matches!(find_attribute(attributes, wanted), Attribute::Absent)
}

/// Returns the raw value of attribute `wanted` from a tag's attribute text.
fn attribute<'a>(attributes: &'a str, wanted: &str) -> Option<&'a str> {
    match find_attribute(attributes, wanted) {
        Attribute::Value(value) => Some(value),
        Attribute::Absent | Attribute::Bare => None,
    }
}

fn find_attribute<'a>(attributes: &'a str, wanted: &str) -> Attribute<'a> {
    let bytes = attributes.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        while at < bytes.len() && (bytes[at].is_ascii_whitespace() || bytes[at] == b'/') {
            at += 1;
        }
        let name_start = at;
        while at < bytes.len()
            && !matches!(bytes[at], b'=' | b'/' | b'>')
            && !bytes[at].is_ascii_whitespace()
        {
            at += 1;
        }
        let name = &attributes[name_start..at];
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        let mut value = None;
        if at < bytes.len() && bytes[at] == b'=' {
            at += 1;
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            if at < bytes.len() && matches!(bytes[at], b'"' | b'\'') {
                let quote = bytes[at];
                let start = at + 1;
                let end = attributes[start..]
                    .bytes()
                    .position(|byte| byte == quote)
                    .map_or(bytes.len(), |offset| start + offset);
                value = Some(&attributes[start..end]);
                at = (end + 1).min(bytes.len());
            } else {
                let start = at;
                while at < bytes.len() && !bytes[at].is_ascii_whitespace() {
                    at += 1;
                }
                value = Some(&attributes[start..at]);
            }
        }
        if name.eq_ignore_ascii_case(wanted) {
            return value.map_or(Attribute::Bare, Attribute::Value);
        }
        if name.is_empty() {
            at += 1;
        }
    }
    Attribute::Absent
}

fn is_displayable_link(target: &str) -> bool {
    if target.len() > MAX_LINK_LEN {
        return false;
    }
    let lowered = target.to_ascii_lowercase();
    lowered.starts_with("https://")
        || lowered.starts_with("http://")
        || lowered.starts_with("mailto:")
}

/// Decodes HTML character references, as found in HTML text and in Gmail's
/// message previews. Unknown names are kept as written.
#[must_use]
pub fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let candidate = &rest[at + 1..];
        let end = candidate
            .char_indices()
            .take(33)
            .find(|&(_, character)| character == ';')
            .map(|(index, _)| index);
        let decoded = end.and_then(|end| decode_reference(&candidate[..end]));
        if let (Some(character), Some(end)) = (decoded, end) {
            out.push(character);
            rest = &candidate[end + 1..];
        } else {
            out.push('&');
            rest = candidate;
        }
    }
    out.push_str(rest);
    out
}

/// Named character references worth decoding in mail; others stay as written.
const NAMED_REFERENCES: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", ' '),
    ("ensp", ' '),
    ("emsp", ' '),
    ("thinsp", ' '),
    ("shy", '\u{200b}'),
    ("zwnj", '\u{200b}'),
    ("zwj", '\u{200b}'),
    ("lrm", '\u{200b}'),
    ("rlm", '\u{200b}'),
    ("copy", '©'),
    ("reg", '®'),
    ("trade", '™'),
    ("hellip", '…'),
    ("mdash", '—'),
    ("ndash", '–'),
    ("lsquo", '‘'),
    ("rsquo", '’'),
    ("sbquo", '‚'),
    ("ldquo", '“'),
    ("rdquo", '”'),
    ("bdquo", '„'),
    ("laquo", '«'),
    ("raquo", '»'),
    ("lsaquo", '‹'),
    ("rsaquo", '›'),
    ("bull", '•'),
    ("middot", '·'),
    ("deg", '°'),
    ("plusmn", '±'),
    ("times", '×'),
    ("divide", '÷'),
    ("euro", '€'),
    ("pound", '£'),
    ("yen", '¥'),
    ("cent", '¢'),
    ("sect", '§'),
    ("para", '¶'),
    ("dagger", '†'),
    ("Dagger", '‡'),
    ("permil", '‰'),
    ("prime", '′'),
    ("Prime", '″'),
    ("larr", '←'),
    ("rarr", '→'),
    ("uarr", '↑'),
    ("darr", '↓'),
    ("harr", '↔'),
    ("iexcl", '¡'),
    ("iquest", '¿'),
    ("frac12", '½'),
    ("frac14", '¼'),
    ("frac34", '¾'),
    ("sup1", '¹'),
    ("sup2", '²'),
    ("sup3", '³'),
    ("micro", 'µ'),
    ("ordf", 'ª'),
    ("ordm", 'º'),
    ("agrave", 'à'),
    ("aacute", 'á'),
    ("acirc", 'â'),
    ("atilde", 'ã'),
    ("auml", 'ä'),
    ("aring", 'å'),
    ("aelig", 'æ'),
    ("ccedil", 'ç'),
    ("egrave", 'è'),
    ("eacute", 'é'),
    ("ecirc", 'ê'),
    ("euml", 'ë'),
    ("igrave", 'ì'),
    ("iacute", 'í'),
    ("icirc", 'î'),
    ("iuml", 'ï'),
    ("ntilde", 'ñ'),
    ("ograve", 'ò'),
    ("oacute", 'ó'),
    ("ocirc", 'ô'),
    ("otilde", 'õ'),
    ("ouml", 'ö'),
    ("oslash", 'ø'),
    ("ugrave", 'ù'),
    ("uacute", 'ú'),
    ("ucirc", 'û'),
    ("uuml", 'ü'),
    ("yacute", 'ý'),
    ("yuml", 'ÿ'),
    ("szlig", 'ß'),
    ("Agrave", 'À'),
    ("Aacute", 'Á'),
    ("Acirc", 'Â'),
    ("Auml", 'Ä'),
    ("Aring", 'Å'),
    ("Ccedil", 'Ç'),
    ("Egrave", 'È'),
    ("Eacute", 'É'),
    ("Ecirc", 'Ê'),
    ("Igrave", 'Ì'),
    ("Iacute", 'Í'),
    ("Ntilde", 'Ñ'),
    ("Ograve", 'Ò'),
    ("Oacute", 'Ó'),
    ("Ouml", 'Ö'),
    ("Oslash", 'Ø'),
    ("Ugrave", 'Ù'),
    ("Uacute", 'Ú'),
    ("Uuml", 'Ü'),
];

fn decode_reference(reference: &str) -> Option<char> {
    if let Some(number) = reference.strip_prefix('#') {
        let value = match number.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => number.parse::<u32>().ok()?,
        };
        return Some(
            char::from_u32(value)
                .filter(|&character| character != '\0')
                .unwrap_or('\u{fffd}'),
        );
    }
    NAMED_REFERENCES
        .iter()
        .find(|(name, _)| *name == reference)
        .map(|&(_, character)| character)
}

/// Whether `character` shows something on screen.
fn is_visible(character: char) -> bool {
    !character.is_whitespace() && is_allowed(character)
}

/// Trims trailing spaces and keeps at most one blank line in a row.
fn collapse_blank_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut blank_run = 0;
    for line in text.split('\n') {
        let line = line.trim_end();
        if line
            .chars()
            .any(|character| character != '>' && is_visible(character))
        {
            blank_run = 0;
        } else {
            blank_run += 1;
            if blank_run > 1 || out.is_empty() {
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_end().to_owned()
}

fn floor_char_boundary(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{MAX_LINKS, MAX_TEXT_OUTPUT, html_parts_to_text, html_to_text};

    fn text(html: &str) -> String {
        html_to_text(html).text
    }

    #[test]
    fn paragraphs_breaks_and_whitespace() {
        assert_eq!(
            text("<p>Hello   <b>big</b>\n world</p><p>Second<br>line</p>"),
            "Hello big world\n\nSecond\nline"
        );
        assert_eq!(text("<div>a</div><div>b</div>"), "a\nb");
        assert_eq!(text("  plain  text  "), "plain text");
    }

    #[test]
    fn hidden_content_and_comments_are_dropped() {
        assert_eq!(
            text(
                "<head><title>T</title><style>p{}</style></head><script>alert(1)</script><!-- c --><p>shown</p>"
            ),
            "shown"
        );
        assert_eq!(text("<p>a</p><SCRIPT>x</SCRIPT><p>b</p>"), "a\n\nb");
        assert_eq!(text("<style>never closed"), "never closed");
    }

    #[test]
    fn links_become_numbered_references() {
        let converted = html_to_text(
            "<p>Read <a href=\"https://example.com/a?x=1&amp;y=2\">the post</a> or \
             <a href='mailto:me@example.com'>mail</a>. Again: \
             <a href=https://example.com/a?x=1&amp;y=2>here</a>.</p>",
        );
        assert_eq!(
            converted.text,
            "Read the post [1] or mail [2]. Again: here [1]."
        );
        assert_eq!(
            converted.links,
            ["https://example.com/a?x=1&y=2", "mailto:me@example.com"]
        );
    }

    #[test]
    fn unsafe_or_redundant_links_get_no_number() {
        let converted = html_to_text(
            "<a href=\"javascript:alert(1)\">x</a> <a href=\"https://e.com\">https://e.com</a> \
             <a href=\"https://e.com\">e.com</a> <a href=\"data:text/html,hi\">d</a> <a>none</a>",
        );
        assert_eq!(converted.text, "x https://e.com e.com d none");
        assert!(converted.links.is_empty());
    }

    #[test]
    fn lists_quotes_tables_and_rules() {
        assert_eq!(
            text("<ul><li>one<li>two<ul><li>deep</li></ul></ul>"),
            "• one\n• two\n\n  • deep"
        );
        assert_eq!(
            text("<blockquote><p>quoted</p><p>more</p></blockquote>after"),
            "> quoted\n\n> more\n\nafter"
        );
        assert_eq!(
            text("<table><tr><td>a</td><td>b</td></tr><tr><td>c</td></tr></table>"),
            "a  b\nc"
        );
        assert_eq!(text("a<hr>b"), "a\n──────────\nb");
    }

    #[test]
    fn preformatted_text_keeps_its_layout() {
        assert_eq!(text("<pre>  a\n    b</pre>"), "  a\n    b");
    }

    #[test]
    fn entities_decode_and_unknown_ones_stay() {
        assert_eq!(
            text("r&eacute;sum&eacute; &amp; &lt;b&gt; &#8364; &#x1F600; &bogus; & x &#0;"),
            "résumé & <b> € 😀 &bogus; & x \u{fffd}"
        );
    }

    #[test]
    fn stray_brackets_are_text() {
        assert_eq!(text("1 < 2 and 3 > 2"), "1 < 2 and 3 > 2");
        assert_eq!(text("<p>a <unterminated"), "a <unterminated");
        assert_eq!(text("<1>x"), "<1>x");
    }

    #[test]
    fn hostile_nesting_is_linear_and_bounded() {
        let depth = 200_000;
        let html = "<div><ul><li><blockquote>".repeat(depth) + "x";
        let started = std::time::Instant::now();
        let converted = html_to_text(&html);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(converted.text.len() <= super::MAX_TEXT_OUTPUT + 64);
        assert!(converted.text.ends_with('x') || converted.text.ends_with("truncated]"));
    }

    #[test]
    fn unterminated_quotes_and_hidden_floods_stay_linear() {
        let started = std::time::Instant::now();
        let quotes = "<a \"".repeat(600_000);
        let _ = html_to_text(&quotes);
        let scripts = "<script></script>x".repeat(100_000);
        assert_eq!(html_to_text(&scripts).text.len(), 100_000);
        let long_tag = format!("<a {}>", "x".repeat(super::MAX_TAG_LEN * 4)).repeat(20);
        let _ = html_to_text(&long_tag);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn consecutive_breaks_make_one_blank_line() {
        assert_eq!(text("a<br>b"), "a\nb");
        assert_eq!(text("a<br><br>b"), "a\n\nb");
        assert_eq!(text("a<br><br><br><br>b"), "a\n\nb");
        assert_eq!(text("<p>a<br></p><p>b</p>"), "a\n\nb");
    }

    #[test]
    fn image_only_links_take_no_number() {
        let converted = html_to_text(
            "<a href=\"https://e.com/1\"><img src=\"x\"></a> \
             <a href=\"https://e.com/2\">text</a> <a href=\"https://e.com/3\"> </a>",
        );
        assert_eq!(converted.text, "text [1]");
        assert_eq!(converted.links, ["https://e.com/2"]);
    }

    #[test]
    fn hidden_elements_and_preheader_padding_are_dropped() {
        assert_eq!(
            text(
                "<div style=\"display: none; max-height:0\">pre <div>inner</div> tail</div>\
                 <p>shown</p>"
            ),
            "shown"
        );
        assert_eq!(
            text("<span hidden>x</span>y<img style=\"display:none\">z"),
            "yz"
        );
        assert_eq!(text("<td style=\"mso-hide:all\">o</td>v"), "v");
        assert_eq!(
            text("<p>Hi</p><div>&#847; &zwnj; &nbsp; &#847;&shy;</div><p>There</p>"),
            "Hi\n\nThere"
        );
        assert_eq!(text("<p style=\"font-family: hidden\">kept</p>"), "kept");
        assert_eq!(text("<p title=\"a hidden b\">kept</p>"), "kept");
    }

    #[test]
    fn an_unclosed_hidden_element_does_not_swallow_the_message() {
        assert_eq!(
            text("<div style=\"display:none\">never closed<p>body</p>"),
            "never closed\n\nbody"
        );
    }

    /// A cheap, deterministic stand-in for fuzzing: random soups of HTML
    /// fragments must never panic and must stay within the output bound.
    #[test]
    fn random_fragment_soup_never_panics() {
        const FRAGMENTS: [&str; 24] = [
            "<",
            ">",
            "</",
            "<a href=\"",
            "\"",
            "'",
            "<p>",
            "</p>",
            "<li>",
            "<ul>",
            "</ul>",
            "<blockquote>",
            "</blockquote>",
            "<pre>",
            "</pre>",
            "&",
            "&#x",
            ";",
            "&amp;",
            "<!--",
            "-->",
            "<script>",
            "é😀",
            " \n\t",
        ];
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..2_000 {
            let mut html = String::new();
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                html.push_str(FRAGMENTS[usize::try_from(state % 24).expect("index")]);
            }
            let converted = html_to_text(&html);
            assert!(converted.text.len() <= super::MAX_TEXT_OUTPUT + 64);
            assert!(converted.links.len() <= MAX_LINKS);
        }
    }

    #[test]
    fn oversized_input_and_link_floods_are_capped() {
        let html = "<p>word</p>".repeat(super::MAX_HTML_INPUT / 10 + 10);
        assert!(html_to_text(&html).text.ends_with("[… message truncated]"));
        let links = (0..MAX_LINKS + 50).fold(String::new(), |mut html, index| {
            let _ = write!(html, "<a href=\"https://e.com/{index}\">l</a>");
            html
        });
        assert_eq!(html_to_text(&links).links.len(), MAX_LINKS);
    }

    #[test]
    fn an_unclosed_head_or_container_does_not_swallow_the_message() {
        assert_eq!(
            html_to_text("<head><meta charset=utf-8><title>t</title><body>Hi").text,
            "Hi"
        );
        assert_eq!(html_to_text("<HEAD><BODY><p>Hi</p>").text, "Hi");
        assert_eq!(
            html_to_text("<p>Hi</p><style>p { color: red }").text,
            "Hi\n\np { color: red }"
        );
        assert_eq!(
            html_to_text("<style>x</style><p>a</p><script>never closed<p>b</p>").text,
            "a\n\nnever closed\n\nb"
        );
    }

    #[test]
    fn abruptly_closed_comments_are_empty() {
        assert_eq!(html_to_text("<!-->Hi<!-- x -->!").text, "Hi!");
        assert_eq!(html_to_text("<!--->Hi").text, "Hi");
    }

    #[test]
    fn many_unclosed_containers_stay_linear() {
        let html = "<script>".repeat(200_000);
        let started = std::time::Instant::now();
        let _ = html_to_text(&html);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn several_documents_share_links_and_caps() {
        let converted = html_parts_to_text(&[
            "<ul><li><a href=\"https://a.example\">one</a>",
            "<blockquote><p><a href=\"https://a.example\">again</a> <a href=\"https://b.example\">two</a>",
            "<p>after</p>",
        ]);
        assert_eq!(
            converted.text, "• one [1]\n\n> again [1] two [2]\n\nafter",
            "nesting ends with each document; a repeated link keeps its number"
        );
        assert_eq!(converted.links, ["https://a.example", "https://b.example"]);

        let big = "<p>word</p>".repeat(40_000);
        let many = html_parts_to_text(&[big.as_str(), big.as_str(), big.as_str()]);
        assert!(many.text.len() <= MAX_TEXT_OUTPUT + 64);
        assert!(many.text.ends_with("[… message truncated]"));
    }
}
