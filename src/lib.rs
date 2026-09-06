use std::fmt;

pub mod corpus;
pub mod defenses;
pub mod dossier;
pub mod findings;
pub mod render;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Family {
    Injection,
    Steganography,
    Composition,
    Vault,
    Credential,
}

impl Family {
    pub const ALL: [Family; 5] = [
        Family::Injection,
        Family::Steganography,
        Family::Composition,
        Family::Vault,
        Family::Credential,
    ];

    pub fn prefix(self) -> &'static str {
        match self {
            Family::Injection => "INJ",
            Family::Steganography => "STG",
            Family::Composition => "CMP",
            Family::Vault => "VLT",
            Family::Credential => "CRD",
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Family::Injection => "injection",
            Family::Steganography => "steganography",
            Family::Composition => "composition",
            Family::Vault => "vault",
            Family::Credential => "credential",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Verdict {
    Blocked,
    Landed,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Blocked => "blocked",
            Verdict::Landed => "LANDED",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Shipped,
    Hardened,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Shipped => "shipped",
            Mode::Hardened => "hardened",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Attack {
    pub id: String,
    pub family: Family,
    pub technique: &'static str,
    pub intent: &'static str,
    pub payload: Payload,
    pub shipped: Verdict,
    pub hardened: Verdict,
    pub severity: Severity,
}

impl Attack {
    pub fn execute(&self, mode: Mode) -> Verdict {
        self.trace(mode).verdict
    }

    pub fn trace(&self, mode: Mode) -> Outcome {
        match &self.payload {
            Payload::Text { text, witness } => text_outcome(text, witness, mode),
            Payload::Composition(case) => corpus::composition::run(case, mode),
            Payload::Vault(case) => corpus::vault::run(case, mode),
            Payload::Credential(case) => corpus::credential::run(case, mode),
        }
    }

    pub fn is_finding(&self) -> bool {
        self.shipped == Verdict::Landed
    }
}

#[derive(Debug, Clone)]
pub enum Payload {
    Text { text: String, witness: Witness },
    Composition(corpus::composition::Case),
    Vault(corpus::vault::Case),
    Credential(corpus::credential::Case),
}

#[derive(Debug, Clone)]
pub enum Witness {
    FenceMissesLine,
    ExcerptCarries(String),
    SpanSurvives,
    LabelEscapes,
}

impl Witness {
    pub fn describe(&self) -> String {
        match self {
            Witness::FenceMissesLine => {
                "`injection_line` returns false — the instruction is not recognized as \
                 model-control language and survives into the evidence pack"
                    .to_string()
            }
            Witness::ExcerptCarries(needle) => format!(
                "the sanitized excerpt still contains {}",
                render::quote(needle)
            ),
            Witness::SpanSurvives => "the sanitized title is non-empty — an instruction posing \
                                     as a title should sanitize to nothing"
                .to_string(),
            Witness::LabelEscapes => "`source_label` returns anything but the fixed constant \
                                     `workspace record`"
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Outcome {
    pub verdict: Verdict,
    pub evidence: String,
}

impl Outcome {
    pub fn new(landed: bool, evidence: impl Into<String>) -> Self {
        Outcome {
            verdict: if landed {
                Verdict::Landed
            } else {
                Verdict::Blocked
            },
            evidence: evidence.into(),
        }
    }
}

fn text_outcome(text: &str, witness: &Witness, mode: Mode) -> Outcome {
    use molterra_capture::pack;
    let (shipped_fn, hardened_fn) = match witness {
        Witness::FenceMissesLine => ("pack::injection_line", "normalize::injection_line"),
        Witness::ExcerptCarries(_) => ("pack::sanitize_excerpt", "normalize::sanitize_excerpt"),
        Witness::SpanSurvives => ("pack::sanitize_span", "normalize::sanitize_span"),
        Witness::LabelEscapes => ("pack::source_label", "normalize::source_label"),
    };
    let target = match mode {
        Mode::Shipped => shipped_fn,
        Mode::Hardened => hardened_fn,
    };
    match witness {
        Witness::FenceMissesLine => {
            let recognized = match mode {
                Mode::Shipped => pack::injection_line(text),
                Mode::Hardened => defenses::normalize::injection_line(text),
            };
            Outcome::new(
                !recognized,
                format!(
                    "`{target}` → {recognized}{}",
                    if recognized {
                        " (recognized as model-control language; the line is dropped)"
                    } else {
                        " (read as ordinary text; the instruction survives)"
                    }
                ),
            )
        }
        Witness::ExcerptCarries(needle) => {
            let out = match mode {
                Mode::Shipped => pack::sanitize_excerpt(text),
                Mode::Hardened => defenses::normalize::sanitize_excerpt(text),
            };
            let carries = out.contains(needle.as_str());
            Outcome::new(
                carries,
                format!(
                    "`{target}` → {}; needle {} {}",
                    render::quote(&out),
                    render::quote(needle),
                    if carries { "PRESENT" } else { "absent" }
                ),
            )
        }
        Witness::SpanSurvives => {
            let out = match mode {
                Mode::Shipped => pack::sanitize_span(text),
                Mode::Hardened => defenses::normalize::sanitize_span(text),
            };
            let survives = !out.trim().is_empty();
            Outcome::new(
                survives,
                format!(
                    "`{target}` → {}{}",
                    render::quote(&out),
                    if survives {
                        " (title survives)"
                    } else {
                        " (title sanitized to nothing)"
                    }
                ),
            )
        }
        Witness::LabelEscapes => {
            let out = match mode {
                Mode::Shipped => pack::source_label(text),
                Mode::Hardened => defenses::normalize::source_label(text),
            };
            let escapes = out != "workspace record";
            Outcome::new(
                escapes,
                format!(
                    "`{target}` → {}{}",
                    render::quote(&out),
                    if escapes {
                        " (attacker bytes reached the prompt label)"
                    } else {
                        " (fell back to the trusted constant)"
                    }
                ),
            )
        }
    }
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Report {
    pub total: usize,
    pub shipped_blocked: usize,
    pub shipped_landed: usize,
    pub hardened_blocked: usize,
    pub hardened_landed: usize,
    pub drift: Vec<Drift>,
    pub by_family: Vec<FamilyReport>,
    pub traces: Vec<Trace>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Trace {
    pub id: String,
    pub shipped: Outcome,
    pub hardened: Outcome,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FamilyReport {
    pub family: Family,
    pub total: usize,
    pub shipped_blocked: usize,
    pub shipped_landed: usize,
    pub hardened_landed: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Drift {
    pub id: String,
    pub mode: &'static str,
    pub recorded: Verdict,
    pub observed: Verdict,
}

pub fn run_all() -> Report {
    let attacks = corpus::all();
    let mut r = Report {
        total: attacks.len(),
        ..Default::default()
    };
    for family in Family::ALL {
        r.by_family.push(FamilyReport {
            family,
            total: 0,
            shipped_blocked: 0,
            shipped_landed: 0,
            hardened_landed: 0,
        });
    }
    for a in &attacks {
        let shipped_outcome = a.trace(Mode::Shipped);
        let hardened_outcome = a.trace(Mode::Hardened);
        let (shipped, hardened) = (shipped_outcome.verdict, hardened_outcome.verdict);
        r.traces.push(Trace {
            id: a.id.clone(),
            shipped: shipped_outcome,
            hardened: hardened_outcome,
        });
        if shipped != a.shipped {
            r.drift.push(Drift {
                id: a.id.clone(),
                mode: "shipped",
                recorded: a.shipped,
                observed: shipped,
            });
        }
        if hardened != a.hardened {
            r.drift.push(Drift {
                id: a.id.clone(),
                mode: "hardened",
                recorded: a.hardened,
                observed: hardened,
            });
        }
        let fam = r
            .by_family
            .iter_mut()
            .find(|f| f.family == a.family)
            .expect("every family is pre-seeded");
        fam.total += 1;
        match shipped {
            Verdict::Blocked => {
                r.shipped_blocked += 1;
                fam.shipped_blocked += 1;
            }
            Verdict::Landed => {
                r.shipped_landed += 1;
                fam.shipped_landed += 1;
            }
        }
        match hardened {
            Verdict::Blocked => r.hardened_blocked += 1,
            Verdict::Landed => {
                r.hardened_landed += 1;
                fam.hardened_landed += 1;
            }
        }
    }
    r
}
