// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Terminal-safe text (ADR 0031).
//!
//! Every provider-derived string must become [`SafeText`] before it reaches a
//! terminal. Sanitizing removes the characters a terminal interprets as
//! commands or that can disguise text:
//!
//! - C0 controls except newline and tab (this includes ESC, which starts ANSI,
//!   OSC, DCS, and similar sequences), and DEL;
//! - C1 controls (U+0080–U+009F), which some terminals treat as 8-bit
//!   introducers such as CSI and OSC;
//! - bidirectional embeddings, overrides, and isolates (U+202A–U+202E,
//!   U+2066–U+2069) and marks (U+200E, U+200F, U+061C), used to reorder
//!   displayed text;
//! - zero-width and invisible formatting characters (U+200B–U+200D,
//!   U+2060–U+2064, U+FEFF, the soft hyphen U+00AD, the combining grapheme
//!   joiner U+034F, Hangul and Mongolian fillers and selectors) and the Tag
//!   block (U+E0000–U+E007F), used to hide content or pad previews;
//! - variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF). They switch emoji
//!   presentation, which terminals and width tables disagree on, so keeping
//!   them misaligns the screen;
//! - the rest of Unicode's default-ignorable code points that render as
//!   nothing: U+2060–U+206F, U+FFF0–U+FFF8, U+1BCA0–U+1BCA3, U+1D173–U+1D17A,
//!   and U+E0000–U+E0FFF.
//!
//! The line and paragraph separators U+2028 and U+2029 become ordinary line
//! breaks. Marks stacked on one character, as in "zalgo" text, are capped:
//! each grapheme cluster keeps at most [`MAX_COMBINING_RUN`] zero-width marks,
//! from any script, and [`MAX_GRAPHEME_CHARS`] code points in all. A terminal
//! may still draw a few marks outside the cell, but no character can pile up
//! enough of them to cover the lines around it.

use std::fmt;

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthChar;

/// Text that is safe to write to a terminal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SafeText(String);

impl SafeText {
    /// Sanitizes multi-line text, keeping newlines and tabs.
    #[must_use]
    pub fn multi_line(input: &str) -> Self {
        Self(sanitize(input, |character| match character {
            '\n' | '\t' => Some(character),
            '\u{2028}' | '\u{2029}' => Some('\n'),
            _ => None,
        }))
    }

    /// Sanitizes text for a single line: line breaks and tabs become spaces.
    #[must_use]
    pub fn single_line(input: &str) -> Self {
        Self(sanitize(input, |character| match character {
            '\n' | '\r' | '\t' | '\u{2028}' | '\u{2029}' => Some(' '),
            _ => None,
        }))
    }

    /// The sanitized text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The most zero-width marks kept on one character. Real text needs up to
/// four: Hebrew with a dot, a point, and a cantillation mark, or a Devanagari
/// conjunct of four consonants.
pub const MAX_COMBINING_RUN: usize = 4;

/// The most code points kept in one grapheme cluster. Real text stays well
/// below it: an Indic conjunct with a vowel sign, or Hebrew with points and a
/// cantillation mark, takes about seven.
pub const MAX_GRAPHEME_CHARS: usize = 10;

/// Drops disallowed characters and caps the marks on each character. `layout`
/// maps the whitespace and separators a caller keeps or converts.
fn sanitize(input: &str, layout: impl Fn(char) -> Option<char>) -> String {
    let mut kept = String::with_capacity(input.len());
    for character in input.chars() {
        match layout(character) {
            Some(replacement) => kept.push(replacement),
            None if is_allowed(character) => kept.push(character),
            None => {}
        }
    }
    let mut output = String::with_capacity(kept.len());
    for grapheme in kept.graphemes(true) {
        let mut marks = 0;
        for character in grapheme.chars().take(MAX_GRAPHEME_CHARS) {
            if is_mark(character) {
                marks += 1;
                if marks > MAX_COMBINING_RUN {
                    continue;
                }
            }
            output.push(character);
        }
    }
    output
}

/// Whether `character` takes no column of its own. After the invisible
/// characters are gone, that leaves the nonspacing and enclosing marks of every
/// script, which are what stack in "zalgo" text, and the medial Hangul jamo.
fn is_mark(character: char) -> bool {
    character.width() == Some(0)
}

/// Whether `character` survives sanitizing.
pub(crate) const fn is_allowed(character: char) -> bool {
    !matches!(
        character,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2028}'..='\u{2029}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

#[cfg(test)]
mod tests {
    use super::{MAX_COMBINING_RUN, MAX_GRAPHEME_CHARS, SafeText};

    #[test]
    fn strips_escape_sequences_and_controls() {
        let hostile = "a\u{1b}]52;c;ZXZpbA==\u{7}b\u{1b}[2Jc\u{9b}31md\u{7f}e\u{0}";
        let safe = SafeText::multi_line(hostile);
        assert!(
            !safe
                .as_str()
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
        );
        assert_eq!(safe.as_str(), "a]52;c;ZXZpbA==b[2Jc31mde");
    }

    #[test]
    fn strips_every_invisible_range_and_converts_separators() {
        let hidden = "a\u{2065}\u{206a}\u{206f}\u{fff0}\u{fff8}\u{1bca0}\u{1d173}\u{e0080}\u{e01f0}\u{e0fff}b";
        assert_eq!(SafeText::single_line(hidden).as_str(), "ab");
        assert_eq!(
            SafeText::single_line("a\u{2028}b\u{2029}c").as_str(),
            "a b c"
        );
        assert_eq!(
            SafeText::multi_line("a\u{2028}b\u{2029}c").as_str(),
            "a\nb\nc"
        );
    }

    #[test]
    fn long_combining_runs_are_cut() {
        let zalgo = format!("z{}a", "\u{301}".repeat(300));
        let safe = SafeText::single_line(&zalgo);
        assert_eq!(safe.as_str(), format!("z{}a", "\u{301}".repeat(4)));
        assert_eq!(
            SafeText::single_line("re\u{301}sume\u{301} na\u{ef}ve \u{928}\u{93f}").as_str(),
            "re\u{301}sume\u{301} na\u{ef}ve \u{928}\u{93f}",
            "ordinary accents and script marks are kept"
        );
    }

    #[test]
    fn interleaved_script_marks_do_not_reset_the_cap() {
        let hostile = format!("x{}y", "\u{301}\u{301}\u{301}\u{301}\u{5b0}".repeat(2000));
        assert_eq!(
            SafeText::multi_line(&hostile).as_str(),
            "x\u{301}\u{301}\u{301}\u{301}y"
        );
        // Marks outside the generic combining blocks count too: Hebrew points,
        // Thai tone marks, and enclosing marks.
        for mark in ['\u{5b0}', '\u{e49}', '\u{489}'] {
            let stacked = format!("x{}y", mark.to_string().repeat(500));
            assert_eq!(
                SafeText::single_line(&stacked).as_str(),
                format!("x{}y", mark.to_string().repeat(MAX_COMBINING_RUN)),
                "{mark:?}"
            );
        }
        // Spacing marks take a column, so only the code point cap holds them.
        let spacing = format!("\u{915}{}", "\u{93e}".repeat(500));
        assert_eq!(
            SafeText::single_line(&spacing).as_str().chars().count(),
            MAX_GRAPHEME_CHARS
        );
        // Hebrew with points and cantillation, a Devanagari conjunct with a
        // vowel sign, and a Thai syllable with two marks stay whole.
        for real in [
            "\u{5e9}\u{5c1}\u{5b8}\u{5c1}\u{591}\u{5dc}\u{5d5}\u{5b9}\u{5dd}",
            "\u{915}\u{94d}\u{937}\u{94d}\u{92e}\u{94d}\u{92f}\u{93e}",
            "\u{e01}\u{e34}\u{e48}",
        ] {
            assert_eq!(SafeText::single_line(real).as_str(), real);
        }
    }

    #[test]
    fn strips_bidi_controls() {
        assert_eq!(
            SafeText::single_line("invoice\u{202e}fdp.exe\u{2066}x\u{2069}").as_str(),
            "invoicefdp.exex"
        );
    }

    #[test]
    fn strips_bidi_marks_and_invisible_characters() {
        let hostile = "a\u{200e}b\u{200f}c\u{61c}d\u{200b}e\u{200d}f\u{2060}g\u{feff}h\u{e0041}i";
        assert_eq!(SafeText::single_line(hostile).as_str(), "abcdefghi");
    }

    #[test]
    fn strips_padding_fillers_and_variation_selectors() {
        let padded = "a\u{34f}\u{ad}b\u{3164}c\u{fe0f}d\u{e0100}e\u{2063}f";
        assert_eq!(SafeText::single_line(padded).as_str(), "abcdef");
        assert_eq!(
            SafeText::single_line("\u{2764}\u{fe0f}").as_str(),
            "\u{2764}"
        );
    }

    #[test]
    fn line_handling_differs_by_mode() {
        assert_eq!(SafeText::multi_line("a\r\nb\tc").as_str(), "a\nb\tc");
        assert_eq!(SafeText::single_line("a\r\nb\tc").as_str(), "a  b c");
    }

    #[test]
    fn keeps_ordinary_unicode() {
        assert_eq!(
            SafeText::single_line("Città → ok ✓").as_str(),
            "Città → ok ✓"
        );
    }
}
