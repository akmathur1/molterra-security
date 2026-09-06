use std::fmt::Write;

pub fn visible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push('⏎'),
            '\t' => out.push_str("⟨TAB⟩"),
            ' '..='~' => out.push(c),
            _ => {
                let _ = write!(out, "⟨U+{:04X}⟩", c as u32);
            }
        }
    }
    out
}

pub fn has_visible_non_ascii(s: &str) -> bool {
    s.chars()
        .any(|c| !c.is_ascii() && !crate::defenses::normalize::is_invisible(c))
}

pub fn as_seen(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s
        .chars()
        .filter(|c| !crate::defenses::normalize::is_invisible(*c))
    {
        match c {
            '\n' => out.push('⏎'),
            '\t' => out.push_str("⟨TAB⟩"),
            ' '..='~' => out.push(c),
            c if c.is_control() || c.is_whitespace() => {
                let _ = write!(out, "⟨U+{:04X}⟩", c as u32);
            }
            _ => out.push(c),
        }
    }
    out
}

pub fn quote(s: &str) -> String {
    if s.is_empty() {
        "∅".to_string()
    } else {
        format!("«{}»", visible(s))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn cell(s: &str) -> String {
    s.replace('|', "\\|")
}
