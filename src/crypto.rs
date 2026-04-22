// All Rights Reserved — The Cochran Block, LLC
//! AES-256-GCM encryption for customer credentials.
//! Credentials encrypted in the binary, emailed as base64 blob.
//! Key lives on mac mini (~/.secrets/), never on gd.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, engine::general_purpose::STANDARD as b64};
use rand::TryRngCore;

/// Encrypt plaintext with AES-256-GCM. Returns base64(nonce + ciphertext).
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("key: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| format!("rng: {e}"))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encrypt: {e}"))?;
    let mut out = nonce_bytes.to_vec();
    out.extend(ct);
    Ok(b64.encode(&out))
}

/// Decrypt base64(nonce + ciphertext) back to plaintext.
pub fn decrypt(blob: &str, key: &[u8; 32]) -> Result<String, String> {
    let raw = b64.decode(blob).map_err(|e| format!("base64: {e}"))?;
    if raw.len() < 13 {
        return Err("ciphertext too short".into());
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("key: {e}"))?;
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|_| "decryption failed — wrong key or corrupted".to_string())?;
    String::from_utf8(plaintext).map_err(|e| format!("utf8: {e}"))
}

/// Derive a 32-byte key from a passphrase using BLAKE3.
pub fn key_from_passphrase(passphrase: &str) -> [u8; 32] {
    let hash = blake3::hash(passphrase.as_bytes());
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = key_from_passphrase("test-key-whobelooking");
        let plaintext = "zone:abc123\ntoken:sk_test_xyz";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = key_from_passphrase("correct");
        let key2 = key_from_passphrase("wrong");
        let encrypted = encrypt("secret", &key1).unwrap();
        assert!(decrypt(&encrypted, &key2).is_err());
    }
}
