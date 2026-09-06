use crate::{corpus, render, Attack, Family, Payload, Report, Severity, Trace, Verdict};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Entry {
    pub id: String,
    pub family: Family,
    pub technique: &'static str,
    pub intent: &'static str,
    pub severity: Severity,
    pub surface: &'static str,
    pub payload: String,
    pub as_seen: Option<String>,
    pub wins_if: String,
    pub shipped: Verdict,
    pub shipped_evidence: String,
    pub hardened: Verdict,
    pub hardened_evidence: String,
}

pub fn entries(attacks: &[Attack], report: &Report) -> Vec<Entry> {
    attacks
        .iter()
        .zip(report.traces.iter())
        .map(|(a, t)| entry(a, t))
        .collect()
}

fn entry(a: &Attack, t: &Trace) -> Entry {
    assert_eq!(a.id, t.id, "traces are in corpus order");
    let (surface, payload, as_seen, wins_if) = match &a.payload {
        Payload::Text { text, witness } => {
            let surface = match witness {
                crate::Witness::FenceMissesLine => "one line of a captured record",
                crate::Witness::ExcerptCarries(_) => "record body → prompt excerpt",
                crate::Witness::SpanSurvives => "record title → prompt span",
                crate::Witness::LabelEscapes => "provider metadata → prompt source label",
            };
            let as_seen = render::has_visible_non_ascii(text).then(|| render::as_seen(text));
            (surface, render::visible(text), as_seen, witness.describe())
        }
        Payload::Composition(case) => {
            let payload = format!(
                "sentence {} cited to [{}]",
                render::quote(&case.sentence),
                case.citations
                    .iter()
                    .map(|c| render::quote(c))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let as_seen = render::has_visible_non_ascii(&case.sentence)
                .then(|| render::as_seen(&case.sentence));
            (
                "composed sentence → rendered card",
                payload,
                as_seen,
                "`verify_composition` returns Ok and the sentence renders".to_string(),
            )
        }
        Payload::Vault(case) => (
            "integration_accounts row (AES-256-GCM ciphertext)",
            case.describe(),
            None,
            "decryption returns plaintext the attacker was not entitled to".to_string(),
        ),
        Payload::Credential(case) => (
            "login_codes row (digest of a six-digit code)",
            case.describe(),
            None,
            "the attacker learns or reuses a live code, or two inputs share a digest".to_string(),
        ),
    };
    Entry {
        id: a.id.clone(),
        family: a.family,
        technique: a.technique,
        intent: a.intent,
        severity: a.severity,
        surface,
        payload,
        as_seen,
        wins_if,
        shipped: t.shipped.verdict,
        shipped_evidence: t.shipped.evidence.clone(),
        hardened: t.hardened.verdict,
        hardened_evidence: t.hardened.evidence.clone(),
    }
}

fn family_preamble(f: Family) -> &'static str {
    match f {
        Family::Injection => "Target: `molterra_capture::pack::injection_line`, the real function that decides \
whether one line of a captured record is model-control language and must be dropped before \
the record reaches a prompt. Each row is one instruction rendered through one evasion. The \
attacker wins when the line is read as ordinary text. Hardened: `defenses::normalize::injection_line`, \
which folds the line through the normalizations in `defenses/normalize.rs` before running the \
same detectors.",
        Family::Steganography => "Targets: `pack::sanitize_excerpt`, `pack::sanitize_span`, and `pack::source_label` — \
the real functions that carry a record's body, title, and provider name into a prompt. Each row \
plants bytes a reader cannot see and asks whether they survive into the prompt (a channel *in*) \
or carry something out with them (a channel *out*). Hardened: the same three functions in \
`defenses/normalize.rs`, which strip invisible code points at the boundary and close the \
provider label to an allowlist.",
        Family::Composition => "Target: `molterra_capture::compose::verify_composition`, the real hallucination fence \
that decides whether a model-composed sentence may render on a card. Every row is judged against \
one fixture (below). The attacker wins when the fence returns `Ok`. Hardened: \
`defenses::compose::verify`, which rejects invisible code points and re-runs the echoed-injection \
check through the hardened detector, then calls the shipped fence unchanged.",
        Family::Vault => "Target: a byte-faithful mirror of `backend/src/integrations/crypto.rs` — AES-256-GCM with a \
random 96-bit nonce, stored as `base64(nonce ‖ ciphertext ‖ tag)`, no associated data. The \
attacker holds write access to the `integration_accounts` table but not the key. Hardened: the \
same cipher with the row's (org, account, field) bound in as AAD. `tests/mirror_tests.rs` pins \
the mirror to the shipped wire format.",
        Family::Credential => "Target: a byte-faithful mirror of `backend/src/auth/code.rs` — a six-digit login code stored \
as `sha256(\"{email}:{code}\")`, five online attempts, ten-minute TTL. The attacker holds a \
copy of the `login_codes` row (a backup, a replica, a logged query). Hardened: \
`hmac-sha256(key, len(email) ‖ email ‖ code)` with a key that lives outside the database, and a \
constant-time compare.",
    }
}

pub fn render_index(entries: &[Entry], report: &Report) -> String {
    let mut s = String::new();
    s.push_str("# Attack dossier\n\n");
    s.push_str(
        "Every attack in the corpus, both verdicts, with the evidence behind each. Generated by \
`cargo run --bin redteam -- --write`; do not edit. The full offense/defense record for each row \
— payload as the detector sees it, function called, value returned — is in the per-family pages \
under `attacks/`. `FINDINGS.md` is the same data grouped by technique; `attacks.json` is this \
page as data.\n\n",
    );
    s.push_str(
        "**How to read a row.** *Shipped* is the code on `main`, called for real. *Hardened* is \
the same call with the layer in `src/defenses/` in front of it — proposed, not deployed. \
`blocked` means the attacker got nothing; `LANDED` means the payload reached the place it was \
aimed at or the secret came out. Payloads are printed with every non-ASCII code point escaped as \
`⟨U+XXXX⟩`, because the point of half of them is that you cannot see them.\n\n",
    );
    s.push_str(&format!(
        "**{} attacks.** Shipped: {} blocked, {} landed. Hardened: {} blocked, {} landed. Drift: {}.\n\n",
        report.total,
        report.shipped_blocked,
        report.shipped_landed,
        report.hardened_blocked,
        report.hardened_landed,
        report.drift.len()
    ));
    s.push_str(
        "| Family | Page | Attacks | Shipped blocked | Shipped landed | Hardened landed |\n",
    );
    s.push_str("|---|---|---:|---:|---:|---:|\n");
    for f in &report.by_family {
        s.push_str(&format!(
            "| {} | [`attacks/{}.md`](attacks/{}.md) | {} | {} | {} | {} |\n",
            f.family,
            f.family,
            f.family,
            f.total,
            f.shipped_blocked,
            f.shipped_landed,
            f.hardened_landed
        ));
    }
    s.push_str("\n## Every attack\n\n");
    s.push_str("| Id | Severity | Technique | Shipped | Hardened |\n|---|---|---|---|---|\n");
    for e in entries {
        s.push_str(&format!(
            "| [{}](attacks/{}.md#{}) | {} | {} | {} | {} |\n",
            e.id,
            e.family,
            e.id.to_lowercase(),
            e.severity,
            render::cell(e.technique),
            e.shipped,
            e.hardened
        ));
    }
    s
}

pub fn render_family(family: Family, entries: &[Entry]) -> String {
    let rows: Vec<&Entry> = entries.iter().filter(|e| e.family == family).collect();
    let shipped_landed = rows.iter().filter(|e| e.shipped == Verdict::Landed).count();
    let hardened_landed = rows
        .iter()
        .filter(|e| e.hardened == Verdict::Landed)
        .count();
    let mut s = String::new();
    s.push_str(&format!(
        "# {} — {} attacks\n\n",
        capitalize(&family.to_string()),
        rows.len()
    ));
    s.push_str("Generated by `cargo run --bin redteam -- --write`; do not edit. Index: [`../ATTACKS.md`](../ATTACKS.md).\n\n");
    s.push_str(family_preamble(family));
    s.push_str("\n\n");
    if family == Family::Composition {
        s.push_str(&format!(
            "**Fixture.** {}\n\n",
            corpus::composition::fixture()
        ));
    }
    s.push_str(&format!(
        "Shipped: {} blocked, {} landed. Hardened: {} blocked, {} landed.\n\n",
        rows.len() - shipped_landed,
        shipped_landed,
        rows.len() - hardened_landed,
        hardened_landed
    ));
    for e in rows {
        s.push_str(&format!("## {}\n\n", e.id));
        s.push_str(&format!(
            "**{}** — {}\n\n",
            e.technique,
            capitalize(e.intent)
        ));
        s.push_str("| | |\n|---|---|\n");
        s.push_str(&format!("| Severity if landed | {} |\n", e.severity));
        s.push_str(&format!("| Surface | {} |\n", render::cell(e.surface)));
        s.push_str(&format!(
            "| Payload | `{}` |\n",
            render::cell(&backtick_safe(&e.payload))
        ));
        if let Some(seen) = &e.as_seen {
            s.push_str(&format!(
                "| As a reader sees it | `{}` |\n",
                render::cell(&backtick_safe(seen))
            ));
        }
        s.push_str(&format!(
            "| Attacker wins if | {} |\n",
            render::cell(&e.wins_if)
        ));
        s.push_str(&format!(
            "| **Shipped** | **{}** — {} |\n",
            e.shipped,
            render::cell(&e.shipped_evidence)
        ));
        s.push_str(&format!(
            "| **Hardened** | **{}** — {} |\n",
            e.hardened,
            render::cell(&e.hardened_evidence)
        ));
        s.push('\n');
    }
    s
}

fn backtick_safe(s: &str) -> String {
    s.replace('`', "ˋ")
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}
