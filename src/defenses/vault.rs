use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub fn shipped_encrypt(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    encrypt_with_nonce(&cipher, &nonce_bytes, plaintext.as_bytes(), b"")
}

pub fn shipped_decrypt(key: &[u8; 32], encoded: &str) -> Result<String, String> {
    let data = STANDARD
        .decode(encoded)
        .map_err(|e| format!("decrypt/b64: {e}"))?;
    if data.len() < NONCE_LEN {
        return Err("decrypt: ciphertext too short".into());
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("decrypt: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| format!("decrypt/utf8: {e}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding<'a> {
    pub org_id: &'a str,
    pub account_id: &'a str,
    pub field: &'a str,
}

impl Binding<'_> {
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [self.org_id, self.account_id, self.field] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part.as_bytes());
        }
        out
    }
}

pub fn hardened_encrypt(
    key: &[u8; 32],
    plaintext: &str,
    binding: &Binding<'_>,
) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    encrypt_with_nonce(&cipher, &nonce_bytes, plaintext.as_bytes(), &binding.aad())
}

pub fn hardened_decrypt(
    key: &[u8; 32],
    encoded: &str,
    binding: &Binding<'_>,
) -> Result<String, String> {
    let data = STANDARD
        .decode(encoded)
        .map_err(|e| format!("decrypt/b64: {e}"))?;
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err("decrypt: ciphertext too short".into());
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let aad = binding.aad();
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| format!("decrypt: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| format!("decrypt/utf8: {e}"))
}

pub fn encrypt_with_nonce(
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<String, String> {
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(out))
}

pub fn nonce_reuse_xor(
    encoded_a: &str,
    encoded_b: &str,
    known_plaintext_a: &[u8],
) -> Option<Vec<u8>> {
    let a = STANDARD.decode(encoded_a).ok()?;
    let b = STANDARD.decode(encoded_b).ok()?;
    if a[..NONCE_LEN] != b[..NONCE_LEN] {
        return None;
    }
    let ct_a = &a[NONCE_LEN..a.len() - TAG_LEN];
    let ct_b = &b[NONCE_LEN..b.len() - TAG_LEN];
    let n = ct_a.len().min(ct_b.len()).min(known_plaintext_a.len());
    Some(
        (0..n)
            .map(|i| ct_a[i] ^ ct_b[i] ^ known_plaintext_a[i])
            .collect(),
    )
}

pub fn parts(encoded: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let data = STANDARD.decode(encoded).ok()?;
    if data.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, rest) = data.split_at(NONCE_LEN);
    let (ct, tag) = rest.split_at(rest.len() - TAG_LEN);
    Some((nonce.to_vec(), ct.to_vec(), tag.to_vec()))
}

pub fn join(nonce: &[u8], ct: &[u8], tag: &[u8]) -> String {
    let mut out = nonce.to_vec();
    out.extend_from_slice(ct);
    out.extend_from_slice(tag);
    STANDARD.encode(out)
}
