use crate::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    Phrase,
    Token,
    Frame,
    Net,
}

impl Detector {
    pub fn survives(self, e: &Evasion) -> bool {
        match self {
            Detector::Phrase => !e.breaks_phrase,
            Detector::Token => !e.breaks_words,
            Detector::Frame => !e.breaks_phrase && !e.breaks_words,
            Detector::Net => !e.breaks_words,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Evasion {
    pub name: &'static str,
    pub apply: fn(&str) -> String,
    pub breaks_phrase: bool,
    pub breaks_words: bool,
    pub severity: Severity,
}

impl std::fmt::Debug for Evasion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

fn runs(text: &str, f: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for c in text.chars() {
        if c.is_alphabetic() {
            run.push(c);
        } else {
            out.push_str(&flush(&mut run, &f));
            out.push(c);
        }
    }
    out.push_str(&flush(&mut run, &f));
    out
}

fn flush(run: &mut String, f: &impl Fn(&str) -> String) -> String {
    let taken = std::mem::take(run);
    if taken.chars().count() >= 4 {
        f(&taken)
    } else {
        taken
    }
}

fn stuff(c: char) -> impl Fn(&str) -> String {
    move |w: &str| {
        let mut s = String::new();
        for (i, ch) in w.chars().enumerate() {
            s.push(ch);
            if i == 1 {
                s.push(c);
            }
        }
        s
    }
}

fn interleave(sep: char) -> impl Fn(&str) -> String {
    move |w: &str| {
        w.chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(&sep.to_string())
    }
}

fn homoglyph(table: &'static [(char, char)]) -> impl Fn(&str) -> String {
    move |w: &str| {
        w.chars()
            .map(|c| {
                table
                    .iter()
                    .find(|(from, _)| *from == c)
                    .map(|(_, to)| *to)
                    .unwrap_or(c)
            })
            .collect()
    }
}

const CYRILLIC: &[(char, char)] = &[
    ('a', 'а'),
    ('c', 'с'),
    ('e', 'е'),
    ('o', 'о'),
    ('p', 'р'),
    ('s', 'ѕ'),
    ('x', 'х'),
    ('y', 'у'),
    ('i', 'і'),
];

const GREEK: &[(char, char)] = &[
    ('a', 'α'),
    ('b', 'β'),
    ('e', 'ε'),
    ('i', 'ι'),
    ('k', 'κ'),
    ('o', 'ο'),
    ('p', 'ρ'),
    ('s', 'σ'),
    ('t', 'τ'),
    ('u', 'υ'),
];

fn math_block(base: u32) -> impl Fn(&str) -> String {
    move |w: &str| {
        w.chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    char::from_u32(base + (c as u32 - 'A' as u32)).unwrap_or(c)
                } else if c.is_ascii_lowercase() {
                    char::from_u32(base + 26 + (c as u32 - 'a' as u32)).unwrap_or(c)
                } else {
                    c
                }
            })
            .collect()
    }
}

fn fullwidth(w: &str) -> String {
    w.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                char::from_u32(0xFF41 + (c as u32 - 'a' as u32)).unwrap_or(c)
            } else if c.is_ascii_uppercase() {
                char::from_u32(0xFF21 + (c as u32 - 'A' as u32)).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

fn circled(w: &str) -> String {
    w.chars()
        .map(|c| {
            let l = c.to_ascii_lowercase();
            if l.is_ascii_lowercase() {
                char::from_u32(0x24D0 + (l as u32 - 'a' as u32)).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

fn leet(w: &str) -> String {
    w.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'o' => '0',
            'i' => '1',
            'e' => '3',
            'a' => '4',
            's' => '5',
            't' => '7',
            _ => c,
        })
        .collect()
}

fn combining(w: &str) -> String {
    stuff('\u{0301}')(w)
}

pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

pub fn b64(s: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(s)
}

fn reversed(s: &str) -> String {
    s.chars().rev().collect()
}

fn alternating_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

pub const ALL: &[Evasion] = &[
    Evasion {
        name: "plain (control)",
        apply: |s| s.to_string(),
        breaks_phrase: false,
        breaks_words: false,
        severity: Severity::Medium,
    },
    Evasion {
        name: "zero-width space in keyword",
        apply: |s| runs(s, stuff('\u{200B}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "zero-width non-joiner in keyword",
        apply: |s| runs(s, stuff('\u{200C}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "zero-width joiner in keyword",
        apply: |s| runs(s, stuff('\u{200D}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "word joiner in keyword",
        apply: |s| runs(s, stuff('\u{2060}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "soft hyphen in keyword",
        apply: |s| runs(s, stuff('\u{00AD}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "byte-order mark in keyword",
        apply: |s| runs(s, stuff('\u{FEFF}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "right-to-left override in keyword",
        apply: |s| runs(s, stuff('\u{202E}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "combining grapheme joiner in keyword",
        apply: |s| runs(s, stuff('\u{034F}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "variation selector in keyword",
        apply: |s| runs(s, stuff('\u{FE0F}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "Unicode tag character in keyword",
        apply: |s| runs(s, stuff('\u{E0041}')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "combining acute accent in keyword",
        apply: |s| runs(s, combining),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "Cyrillic homoglyphs",
        apply: |s| runs(s, homoglyph(CYRILLIC)),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "Greek homoglyphs",
        apply: |s| runs(s, homoglyph(GREEK)),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "fullwidth forms",
        apply: |s| runs(s, fullwidth),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "mathematical bold",
        apply: |s| runs(s, math_block(0x1D400)),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "mathematical monospace",
        apply: |s| runs(s, math_block(0x1D670)),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "mathematical script",
        apply: |s| runs(s, math_block(0x1D4D0)),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "enclosed alphanumerics",
        apply: |s| runs(s, circled),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "leetspeak",
        apply: |s| runs(s, leet),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "letters spaced apart",
        apply: |s| runs(s, interleave(' ')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "letters separated by periods",
        apply: |s| runs(s, interleave('.')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "letters separated by underscores",
        apply: |s| runs(s, interleave('_')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "letters separated by hyphens",
        apply: |s| runs(s, interleave('-')),
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "ROT13",
        apply: rot13,
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "base64",
        apply: b64,
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "reversed text",
        apply: reversed,
        breaks_phrase: true,
        breaks_words: true,
        severity: Severity::Medium,
    },
    Evasion {
        name: "non-breaking spaces between words",
        apply: |s| s.replace(' ', "\u{00A0}"),
        breaks_phrase: true,
        breaks_words: false,
        severity: Severity::Medium,
    },
    Evasion {
        name: "doubled spaces between words",
        apply: |s| s.replace(' ', "  "),
        breaks_phrase: true,
        breaks_words: false,
        severity: Severity::Medium,
    },
    Evasion {
        name: "ideographic space between words",
        apply: |s| s.replace(' ', "\u{3000}"),
        breaks_phrase: true,
        breaks_words: false,
        severity: Severity::Medium,
    },
    Evasion {
        name: "alternating case (control)",
        apply: alternating_case,
        breaks_phrase: false,
        breaks_words: false,
        severity: Severity::Medium,
    },
    Evasion {
        name: "wrapped in an HTML comment (control)",
        apply: |s| format!("<!-- {s} -->"),
        breaks_phrase: false,
        breaks_words: false,
        severity: Severity::Medium,
    },
    Evasion {
        name: "markdown blockquote prefix (control)",
        apply: |s| format!("> {s}"),
        breaks_phrase: false,
        breaks_words: false,
        severity: Severity::Medium,
    },
    Evasion {
        name: "surrounded by plausible prose (control)",
        apply: |s| format!("Per the thread: {s} Thanks."),
        breaks_phrase: false,
        breaks_words: false,
        severity: Severity::Medium,
    },
];
