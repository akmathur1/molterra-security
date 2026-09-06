use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn hash_token(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

pub fn shipped_code_hash(email: &str, code: &str) -> String {
    hash_token(&format!("{email}:{code}"))
}

pub fn hardened_code_hash(key: &[u8], email: &str, code: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(&(email.len() as u32).to_be_bytes());
    mac.update(email.as_bytes());
    mac.update(code.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub const CODE_SPACE: u32 = 1_000_000;
pub const MAX_ATTEMPTS: u32 = 5;

pub fn enumerate_offline(email: &str, digest: &str) -> Option<(String, u32)> {
    for n in 0..CODE_SPACE {
        let candidate = format!("{n:06}");
        if shipped_code_hash(email, &candidate) == digest {
            return Some((candidate, n + 1));
        }
    }
    None
}

pub fn enumerate_offline_keyed(email: &str, digest: &str, budget: u32) -> Option<String> {
    for n in 0..budget.min(CODE_SPACE) {
        let candidate = format!("{n:06}");
        if shipped_code_hash(email, &candidate) == digest {
            return Some(candidate);
        }
    }
    None
}

pub fn compare_steps(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut steps = 0;
    for i in 0..a.len().min(b.len()) {
        steps += 1;
        if a[i] != b[i] {
            return steps;
        }
    }
    steps
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
