use crate::defenses::credential::{
    self as c, compare_steps, constant_time_eq, hardened_code_hash, shipped_code_hash, CODE_SPACE,
    MAX_ATTEMPTS,
};
use crate::{Attack, Family, Mode, Outcome, Payload, Severity, Verdict};

use Verdict::{Blocked, Landed};

const EMAIL: &str = "ada@lovelace.example";
const OTHER_EMAIL: &str = "grace@hopper.example";
const PEPPER: &[u8] = b"pepper-lives-in-the-kms-not-the-row";
const HARDENED_PROBE: u32 = 25_000;

#[derive(Debug, Clone)]
pub enum Case {
    OfflineEnumeration { code: &'static str },
    OfflineEnumerationNoKey { code: &'static str, budget: u32 },
    CrossAccountReplay,
    RainbowTableReuse { code: &'static str },
    OnlineGuessing,
    TimingOracle,
    AmbiguousConcatenation,
}

fn flip_nibble(digest: &str, at: usize) -> String {
    digest
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i != at {
                return c;
            }
            let v = c.to_digit(16).expect("hex digest") ^ 1;
            std::char::from_digit(v, 16).expect("nibble stays hex")
        })
        .collect()
}

impl Case {
    pub fn describe(&self) -> String {
        match self {
            Case::OfflineEnumeration { code } => format!(
                "steal the `login_codes` row for {EMAIL} holding the digest of code {code}, \
                 then hash all 10^6 candidates offline until one matches"
            ),
            Case::OfflineEnumerationNoKey { code, budget } => format!(
                "same theft, but concede after {budget} candidate digests — a measured work \
                 budget rather than the full space (target code {code})"
            ),
            Case::CrossAccountReplay => {
                format!("take {OTHER_EMAIL}'s stored digest and present it as {EMAIL}'s")
            }
            Case::RainbowTableReuse { code } => format!(
                "precompute the digest of code {code} for {EMAIL} and reuse it against \
                 {OTHER_EMAIL}"
            ),
            Case::OnlineGuessing => format!(
                "guess at the API within the {MAX_ATTEMPTS}-attempt ceiling, trying the codes an \
                 attacker would pick first"
            ),
            Case::TimingOracle => "submit two wrong codes whose digests differ from the stored \
                                  digest at opposite ends, and count the byte comparisons the \
                                  verify performs"
                .to_string(),
            Case::AmbiguousConcatenation => "find two (email, code) pairs whose `{email}:{code}` \
                                            concatenations are the same string"
                .to_string(),
        }
    }
}

pub fn run(case: &Case, mode: Mode) -> Outcome {
    let hash_fn = match mode {
        Mode::Shipped => "code_hash = sha256(\"{email}:{code}\")",
        Mode::Hardened => "hardened_code_hash = hmac-sha256(key, len(email) ‖ email ‖ code)",
    };
    match case {
        Case::OfflineEnumeration { code } => match mode {
            Mode::Shipped => {
                let digest = shipped_code_hash(EMAIL, code);
                let found = c::enumerate_offline(EMAIL, &digest);
                let landed = found.as_ref().is_some_and(|(f, _)| f == code);
                Outcome::new(
                    landed,
                    match &found {
                        Some((f, tried)) => format!(
                            "`{hash_fn}`; enumerated {tried} of {} candidates and recovered the \
                             live code {f} — the {MAX_ATTEMPTS}-attempt server ceiling never \
                             engages because no guess was sent",
                            c::CODE_SPACE
                        ),
                        None => "the space was exhausted with no match".to_string(),
                    },
                )
            }
            Mode::Hardened => {
                let digest = hardened_code_hash(PEPPER, EMAIL, code);
                let found = c::enumerate_offline_keyed(EMAIL, &digest, HARDENED_PROBE);
                Outcome::new(
                    found.is_some(),
                    format!(
                        "`{hash_fn}`; {HARDENED_PROBE} candidates tried against a keyed digest \
                         whose key is not in the row — no match, and the failure is structural \
                         rather than a matter of budget"
                    ),
                )
            }
        },
        Case::OfflineEnumerationNoKey { code, budget } => {
            let digest = match mode {
                Mode::Shipped => shipped_code_hash(EMAIL, code),
                Mode::Hardened => hardened_code_hash(PEPPER, EMAIL, code),
            };
            let found = c::enumerate_offline_keyed(EMAIL, &digest, *budget);
            Outcome::new(
                found.is_some(),
                format!(
                    "`{hash_fn}`; {budget} candidate digests computed → {}",
                    match &found {
                        Some(f) => format!("recovered code {f} inside the budget"),
                        None => "no match inside the budget".to_string(),
                    }
                ),
            )
        }
        Case::CrossAccountReplay => {
            let stolen = match mode {
                Mode::Shipped => shipped_code_hash(OTHER_EMAIL, "314159"),
                Mode::Hardened => hardened_code_hash(PEPPER, OTHER_EMAIL, "314159"),
            };
            let mine = match mode {
                Mode::Shipped => shipped_code_hash(EMAIL, "314159"),
                Mode::Hardened => hardened_code_hash(PEPPER, EMAIL, "314159"),
            };
            Outcome::new(
                stolen == mine,
                format!(
                    "`{hash_fn}`; {OTHER_EMAIL}'s digest {} vs {EMAIL}'s {} — {}",
                    &stolen[..16],
                    &mine[..16],
                    if stolen == mine {
                        "equal, so the row replays"
                    } else {
                        "different, because the address is inside the hash"
                    }
                ),
            )
        }
        Case::RainbowTableReuse { code } => {
            let a = match mode {
                Mode::Shipped => shipped_code_hash(EMAIL, code),
                Mode::Hardened => hardened_code_hash(PEPPER, EMAIL, code),
            };
            let b = match mode {
                Mode::Shipped => shipped_code_hash(OTHER_EMAIL, code),
                Mode::Hardened => hardened_code_hash(PEPPER, OTHER_EMAIL, code),
            };
            Outcome::new(
                a == b,
                format!(
                    "`{hash_fn}`; digest for {EMAIL} {} vs the same code for {OTHER_EMAIL} {} — {}",
                    &a[..16],
                    &b[..16],
                    if a == b {
                        "equal, so one table covers every account"
                    } else {
                        "different, so a table is per-address and worth 10^6 hashes each"
                    }
                ),
            )
        }
        Case::OnlineGuessing => {
            let secret = "480291";
            let target = match mode {
                Mode::Shipped => shipped_code_hash(EMAIL, secret),
                Mode::Hardened => hardened_code_hash(PEPPER, EMAIL, secret),
            };
            let guesses = ["000000", "123456", "111111", "999999", "654321"];
            let hit = guesses.iter().take(MAX_ATTEMPTS as usize).any(|guess| {
                let attempt = match mode {
                    Mode::Shipped => shipped_code_hash(EMAIL, guess),
                    Mode::Hardened => hardened_code_hash(PEPPER, EMAIL, guess),
                };
                attempt == target
            });
            Outcome::new(
                hit,
                format!(
                    "`{hash_fn}`; {MAX_ATTEMPTS} guesses [{}] against the digest of a code drawn \
                     from 10^6 → {}; the code then expires (`MAX_ATTEMPTS`) and dies after ten \
                     minutes regardless",
                    guesses[..MAX_ATTEMPTS as usize].join(", "),
                    if hit { "MATCH" } else { "no match" }
                ),
            )
        }
        Case::TimingOracle => {
            let target = shipped_code_hash(EMAIL, "480291");
            let near = flip_nibble(&target, target.len() - 1);
            let far = flip_nibble(&target, 0);
            match mode {
                Mode::Shipped => {
                    let a = compare_steps(&target, &near);
                    let b = compare_steps(&target, &far);
                    Outcome::new(
                        a != b,
                        format!(
                            "`code_hash(..) != stored_hash` is a `String` compare with no \
                             constant-time contract; a byte-serial surrogate of it reads {a} byte(s) \
                             for a candidate differing at the last nibble and {b} for one differing \
                             at the first — a modelled work difference, not a wall-clock \
                             measurement of the shipped binary"
                        ),
                    )
                }
                Mode::Hardened => {
                    let hit = constant_time_eq(&target, &near) || constant_time_eq(&target, &far);
                    Outcome::new(
                        hit,
                        "`subtle::ConstantTimeEq` reads every byte of both digests, so there is \
                         no prefix length to count; both wrong candidates are rejected"
                            .to_string(),
                    )
                }
            }
        }
        Case::AmbiguousConcatenation => {
            let (a, b) = match mode {
                Mode::Shipped => (
                    shipped_code_hash("a@b:1", "23456"),
                    shipped_code_hash("a@b", "1:23456"),
                ),
                Mode::Hardened => (
                    hardened_code_hash(PEPPER, "a@b:1", "23456"),
                    hardened_code_hash(PEPPER, "a@b", "1:23456"),
                ),
            };
            Outcome::new(
                a == b,
                format!(
                    "`{hash_fn}`; (\"a@b:1\", \"23456\") → {} and (\"a@b\", \"1:23456\") → {} — {}",
                    &a[..16],
                    &b[..16],
                    if a == b {
                        "one digest for two inputs: the encoding is not injective"
                    } else {
                        "distinct, because the length prefix makes the encoding injective"
                    }
                ),
            )
        }
    }
}

const CODES: &[&str] = &["000000", "000042", "013337"];

pub fn attacks() -> Vec<Attack> {
    let mut out = Vec::new();

    for code in CODES {
        out.push(Attack {
            id: String::new(),
            family: Family::Credential,
            technique: "offline enumeration of a stolen code digest",
            intent: "recover a live login code from a database row without touching the server",
            payload: Payload::Credential(Case::OfflineEnumeration { code }),
            shipped: Landed,
            hardened: Blocked,
            severity: Severity::Critical,
        });
    }

    out.push(Attack {
        id: String::new(),
        family: Family::Credential,
        technique: "offline enumeration, worst case in the space",
        intent: "recover the highest code in the space to bound the attacker's cost",
        payload: Payload::Credential(Case::OfflineEnumeration { code: "999999" }),
        shipped: Landed,
        hardened: Blocked,
        severity: Severity::Critical,
    });

    for budget in [1_000u32, 100_000, CODE_SPACE] {
        out.push(Attack {
            id: String::new(),
            family: Family::Credential,
            technique: "offline enumeration under a fixed work budget",
            intent: "measure how much compute a stolen digest actually costs to break",
            payload: Payload::Credential(Case::OfflineEnumerationNoKey {
                code: "480291",
                budget,
            }),
            shipped: if budget == CODE_SPACE {
                Landed
            } else {
                Blocked
            },
            hardened: Blocked,
            severity: Severity::Critical,
        });
    }

    out.push(Attack {
        id: String::new(),
        family: Family::Credential,
        technique: "digest replayed across accounts",
        intent: "log in as one user with another user's code digest",
        payload: Payload::Credential(Case::CrossAccountReplay),
        shipped: Blocked,
        hardened: Blocked,
        severity: Severity::Critical,
    });

    for code in CODES {
        out.push(Attack {
            id: String::new(),
            family: Family::Credential,
            technique: "precomputed table reused across addresses",
            intent: "amortize one enumeration over every account in the table",
            payload: Payload::Credential(Case::RainbowTableReuse { code }),
            shipped: Blocked,
            hardened: Blocked,
            severity: Severity::High,
        });
    }

    out.push(Attack {
        id: String::new(),
        family: Family::Credential,
        technique: "online guessing inside the attempt ceiling",
        intent: "guess a live code before the fifth failure burns it",
        payload: Payload::Credential(Case::OnlineGuessing),
        shipped: Blocked,
        hardened: Blocked,
        severity: Severity::Medium,
    });

    out.push(Attack {
        id: String::new(),
        family: Family::Credential,
        technique: "variable-time digest comparison (surrogate, not measured)",
        intent: "shipped verify uses String !=, which has no constant-time contract; \
                 this row models a byte-serial compare and does not time the shipped binary",
        payload: Payload::Credential(Case::TimingOracle),
        shipped: Landed,
        hardened: Blocked,
        severity: Severity::Low,
    });

    out.push(Attack {
        id: String::new(),
        family: Family::Credential,
        technique: "ambiguous concatenation in the hash preimage",
        intent: "find two (email, code) pairs with one digest",
        payload: Payload::Credential(Case::AmbiguousConcatenation),
        shipped: Landed,
        hardened: Blocked,
        severity: Severity::Low,
    });

    out
}
