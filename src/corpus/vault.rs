use crate::defenses::vault::{
    self as v, hardened_decrypt, hardened_encrypt, shipped_decrypt, shipped_encrypt, Binding,
    NONCE_LEN, TAG_LEN,
};
use crate::{render, Attack, Family, Mode, Outcome, Payload, Severity, Verdict};
use aes_gcm::{Aes256Gcm, Key, KeyInit};

use Verdict::{Blocked, Landed};

const TOKEN: &str = "fixture-oauth-token-AAAAAAAAAAAAAAAAAAAA";
const OTHER: &str = "fixture-oauth-token-BBBBBBBBBBBBBBBBBBBB";

const KEY: [u8; 32] = [
    0x9f, 0x2a, 0x41, 0x8c, 0x33, 0x0d, 0xb7, 0x61, 0x5e, 0xa4, 0x12, 0xcc, 0x7d, 0x90, 0x38, 0x22,
    0x4b, 0xe1, 0x06, 0xf5, 0x8a, 0x77, 0x2e, 0xd3, 0x19, 0x64, 0xbb, 0x50, 0xa1, 0xfc, 0x87, 0x35,
];
const OTHER_KEY: [u8; 32] = [0x11; 32];

#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub org: &'static str,
    pub account: &'static str,
    pub field: &'static str,
}

impl Row {
    fn binding(&self) -> Binding<'_> {
        Binding {
            org_id: self.org,
            account_id: self.account,
            field: self.field,
        }
    }
}

const A: Row = Row {
    org: "org-a1b2",
    account: "acct-0001",
    field: "refresh_token",
};

#[derive(Debug, Clone)]
pub enum Case {
    Transplant { from: Row, to: Row },
    BitFlip { byte: usize },
    TagZeroed,
    TagTruncated,
    NonceSwapped,
    WrongKey,
    Truncated { bytes: usize },
    NotBase64,
    ForgedBlob,
    NonceCollision,
}

impl Case {
    pub fn describe(&self) -> String {
        match self {
            Case::Transplant { from, to } => format!(
                "copy the stored ciphertext from row {} into row {}",
                from.label(),
                to.label()
            ),
            Case::BitFlip { byte } => format!("flip one bit of ciphertext byte {byte}"),
            Case::TagZeroed => "zero the GCM authentication tag".to_string(),
            Case::TagTruncated => "drop the last byte of the GCM tag".to_string(),
            Case::NonceSwapped => "pair the ciphertext with another message's nonce".to_string(),
            Case::WrongKey => "decrypt under a different key".to_string(),
            Case::Truncated { bytes } => format!("truncate the stored value to {bytes} bytes"),
            Case::NotBase64 => "store a value that is not base64".to_string(),
            Case::ForgedBlob => {
                "store plausible-looking bytes that were never encrypted".to_string()
            }
            Case::NonceCollision => {
                "encrypt two tokens under one (key, nonce) pair, XOR the ciphertexts".to_string()
            }
        }
    }
}

pub fn run(case: &Case, mode: Mode) -> Outcome {
    let (encrypt_fn, decrypt_fn) = match mode {
        Mode::Shipped => ("crypto::encrypt (no AAD)", "crypto::decrypt (no AAD)"),
        Mode::Hardened => (
            "hardened_encrypt (AAD = binding)",
            "hardened_decrypt (AAD = binding)",
        ),
    };
    match case {
        Case::Transplant { from, to } => {
            let out = match mode {
                Mode::Shipped => {
                    let ct = shipped_encrypt(&KEY, TOKEN).expect("encrypt");
                    shipped_decrypt(&KEY, &ct)
                }
                Mode::Hardened => {
                    let ct = hardened_encrypt(&KEY, TOKEN, &from.binding()).expect("encrypt");
                    hardened_decrypt(&KEY, &ct, &to.binding())
                }
            };
            let landed = out.as_deref() == Ok(TOKEN);
            Outcome::new(
                landed,
                format!(
                    "encrypted for {} with `{encrypt_fn}`, stored in {}, `{decrypt_fn}` → {}",
                    from.label(),
                    to.label(),
                    describe(&out)
                ),
            )
        }
        Case::NonceCollision => {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&KEY));
            let nonce = [7u8; NONCE_LEN];
            let aad: Vec<u8> = match mode {
                Mode::Shipped => Vec::new(),
                Mode::Hardened => A.binding().aad(),
            };
            let a = v::encrypt_with_nonce(&cipher, &nonce, TOKEN.as_bytes(), &aad).expect("a");
            let b = v::encrypt_with_nonce(&cipher, &nonce, OTHER.as_bytes(), &aad).expect("b");
            let recovered = v::nonce_reuse_xor(&a, &b, TOKEN.as_bytes());
            let landed = recovered
                .as_deref()
                .is_some_and(|recovered| recovered == OTHER.as_bytes());
            Outcome::new(
                landed,
                format!(
                    "two messages under one key with nonce {} (staged; AAD {}); \
                     ct_a ⊕ ct_b ⊕ known_plaintext_a → {}",
                    render::hex(&nonce),
                    if aad.is_empty() { "empty" } else { "= binding" },
                    match recovered {
                        Some(bytes) if landed => format!(
                            "{} — the second token, recovered in full without the key",
                            render::quote(&String::from_utf8_lossy(&bytes))
                        ),
                        Some(bytes) => format!("{} bytes, not the second token", bytes.len()),
                        None => "nothing (nonces differ)".to_string(),
                    }
                ),
            )
        }
        other => {
            let ct = match mode {
                Mode::Shipped => shipped_encrypt(&KEY, TOKEN).expect("encrypt"),
                Mode::Hardened => hardened_encrypt(&KEY, TOKEN, &A.binding()).expect("encrypt"),
            };
            let (mutated, what) = mutate(other, &ct, mode);
            let out = if matches!(other, Case::WrongKey) {
                match mode {
                    Mode::Shipped => shipped_decrypt(&OTHER_KEY, &ct),
                    Mode::Hardened => hardened_decrypt(&OTHER_KEY, &ct, &A.binding()),
                }
            } else {
                match mode {
                    Mode::Shipped => shipped_decrypt(&KEY, &mutated),
                    Mode::Hardened => hardened_decrypt(&KEY, &mutated, &A.binding()),
                }
            };
            Outcome::new(
                out.is_ok(),
                format!(
                    "stored value = base64(nonce[{NONCE_LEN}] ‖ ct[{}] ‖ tag[{TAG_LEN}]); {what}; \
                     `{decrypt_fn}` → {}",
                    TOKEN.len(),
                    describe(&out)
                ),
            )
        }
    }
}

fn describe(out: &Result<String, String>) -> String {
    match out {
        Ok(pt) if pt == TOKEN => "Ok(the live token) — plaintext came out".to_string(),
        Ok(pt) => format!("Ok({} bytes of other plaintext)", pt.len()),
        Err(e) => format!("Err({e})"),
    }
}

impl Row {
    fn label(&self) -> String {
        format!("{}/{}/{}", self.org, self.account, self.field)
    }
}

fn mutate(case: &Case, encoded: &str, mode: Mode) -> (String, String) {
    let Some((nonce, mut ct, mut tag)) = v::parts(encoded) else {
        return (encoded.to_string(), "stored value unparseable".to_string());
    };
    match case {
        Case::BitFlip { byte } => {
            let mut what = "ciphertext empty, nothing to flip".to_string();
            if !ct.is_empty() {
                let i = byte % ct.len();
                ct[i] ^= 1 << (byte % 8);
                what = format!("flipped bit {} of ciphertext byte {i}", byte % 8);
            }
            (v::join(&nonce, &ct, &tag), what)
        }
        Case::TagZeroed => {
            tag = vec![0u8; TAG_LEN];
            (
                v::join(&nonce, &ct, &tag),
                format!("replaced the {TAG_LEN}-byte tag with zeros"),
            )
        }
        Case::TagTruncated => {
            tag.pop();
            (
                v::join(&nonce, &ct, &tag),
                format!("dropped the last tag byte ({} remain)", tag.len()),
            )
        }
        Case::NonceSwapped => {
            let other = match mode {
                Mode::Shipped => shipped_encrypt(&KEY, OTHER).expect("encrypt"),
                Mode::Hardened => hardened_encrypt(&KEY, OTHER, &A.binding()).expect("encrypt"),
            };
            let (other_nonce, _, _) = v::parts(&other).expect("parts");
            (
                v::join(&other_nonce, &ct, &tag),
                "kept ciphertext and tag, substituted another message's nonce".to_string(),
            )
        }
        Case::Truncated { bytes } => {
            let mut all = nonce;
            all.extend_from_slice(&ct);
            all.extend_from_slice(&tag);
            all.truncate(*bytes);
            (
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, all),
                format!("truncated the decoded value to {bytes} bytes"),
            )
        }
        Case::NotBase64 => (
            "this is not base64 !!!".to_string(),
            "stored a non-base64 string".to_string(),
        ),
        Case::ForgedBlob => {
            let blob = vec![0xABu8; NONCE_LEN + TOKEN.len() + TAG_LEN];
            (
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob),
                format!(
                    "stored {} bytes of 0xAB, base64-encoded, the right length for a ciphertext",
                    blob.len()
                ),
            )
        }
        Case::WrongKey => (
            encoded.to_string(),
            "untouched ciphertext, decrypted under a different 256-bit key".to_string(),
        ),
        Case::Transplant { .. } | Case::NonceCollision => {
            (encoded.to_string(), "untouched".to_string())
        }
    }
}

const TARGETS: &[(Row, &str, Severity)] = &[
    (
        Row {
            org: "org-a1b2",
            account: "acct-0002",
            field: "refresh_token",
        },
        "move a live refresh token to another account in the same org",
        Severity::Critical,
    ),
    (
        Row {
            org: "org-z9y8",
            account: "acct-0001",
            field: "refresh_token",
        },
        "move a live refresh token across a tenant boundary",
        Severity::Critical,
    ),
    (
        Row {
            org: "org-z9y8",
            account: "acct-7777",
            field: "refresh_token",
        },
        "plant a stolen token in an unrelated tenant's account",
        Severity::Critical,
    ),
    (
        Row {
            org: "org-a1b2",
            account: "acct-0001",
            field: "access_token",
        },
        "swap the two credential columns of one row",
        Severity::High,
    ),
];

pub fn attacks() -> Vec<Attack> {
    let mut out = Vec::new();

    for (to, intent, severity) in TARGETS {
        out.push(Attack {
            id: String::new(),
            family: Family::Vault,
            technique: "ciphertext transplanted to another row",
            intent,
            payload: Payload::Vault(Case::Transplant { from: A, to: *to }),
            shipped: Landed,
            hardened: Blocked,
            severity: *severity,
        });
    }

    for byte in 0..TOKEN.len() {
        out.push(Attack {
            id: String::new(),
            family: Family::Vault,
            technique: "single-bit flip in the ciphertext",
            intent: "alter the stored token so it decrypts to something else",
            payload: Payload::Vault(Case::BitFlip { byte }),
            shipped: Blocked,
            hardened: Blocked,
            severity: Severity::High,
        });
    }

    for (case, technique, intent, severity) in [
        (
            Case::TagZeroed,
            "GCM tag zeroed",
            "strip authentication by erasing the tag",
            Severity::High,
        ),
        (
            Case::TagTruncated,
            "GCM tag truncated by one byte",
            "weaken the tag to a forgeable length",
            Severity::High,
        ),
        (
            Case::NonceSwapped,
            "nonce substituted from another ciphertext",
            "decrypt one message under another's nonce",
            Severity::High,
        ),
        (
            Case::WrongKey,
            "decryption under a rotated key",
            "read the vault with a key that is not the vault's",
            Severity::Critical,
        ),
        (
            Case::Truncated { bytes: 0 },
            "empty stored value",
            "make an empty column read as an empty token",
            Severity::Medium,
        ),
        (
            Case::Truncated { bytes: NONCE_LEN },
            "nonce only, no ciphertext",
            "exploit a length check that stops at the nonce",
            Severity::Medium,
        ),
        (
            Case::Truncated {
                bytes: NONCE_LEN + 4,
            },
            "ciphertext truncated inside the tag",
            "pass a length check with an incomplete tag",
            Severity::Medium,
        ),
        (
            Case::NotBase64,
            "non-base64 stored value",
            "reach the cipher with a decoder error",
            Severity::Low,
        ),
        (
            Case::ForgedBlob,
            "plausible forged blob of the right length",
            "forge a token without the key",
            Severity::Critical,
        ),
    ] {
        out.push(Attack {
            id: String::new(),
            family: Family::Vault,
            technique,
            intent,
            payload: Payload::Vault(case),
            shipped: Blocked,
            hardened: Blocked,
            severity,
        });
    }

    out.push(Attack {
        id: String::new(),
        family: Family::Vault,
        technique: "staged nonce collision, plaintext recovered by XOR",
        intent: "recover a second token from two ciphertexts sharing a nonce",
        payload: Payload::Vault(Case::NonceCollision),
        shipped: Landed,
        hardened: Landed,
        severity: Severity::Critical,
    });

    out
}
