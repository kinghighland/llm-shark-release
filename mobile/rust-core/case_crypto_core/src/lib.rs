use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedCkBlob {
    pub version: u8,
    pub kek_id: String,
    pub nonce_b64: String,
    pub wrapped_ck_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedCaseBlob {
    pub version: u8,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedCaseItem {
    pub case_id: String,
    pub blob: EncryptedCaseBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptedCaseItem {
    pub case_id: String,
    pub plaintext: String,
}

#[derive(Debug, Error)]
pub enum CaseCryptoError {
    #[error("invalid key bytes length")]
    InvalidKeyLength,
    #[error("base64 decode failed: {0}")]
    Base64Decode(String),
    #[error("encrypt failed")]
    EncryptFailed,
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("invalid utf8 plaintext")]
    InvalidUtf8,
}

pub fn generate_ck_b64() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let out = STANDARD.encode(key);
    key.zeroize();
    out
}

pub fn wrap_ck(ck_b64: &str, kek_b64: &str, kek_id: &str) -> Result<WrappedCkBlob, CaseCryptoError> {
    let mut ck = decode_32bytes_b64(ck_b64)?;
    let kek = decode_32bytes_b64(kek_b64)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| CaseCryptoError::InvalidKeyLength)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let wrapped_ck = cipher
        .encrypt(nonce, ck.as_ref())
        .map_err(|_| CaseCryptoError::EncryptFailed)?;
    ck.zeroize();
    Ok(WrappedCkBlob {
        version: 1,
        kek_id: kek_id.to_string(),
        nonce_b64: STANDARD.encode(nonce_bytes),
        wrapped_ck_b64: STANDARD.encode(wrapped_ck),
    })
}

pub fn unwrap_ck(blob: &WrappedCkBlob, kek_b64: &str) -> Result<String, CaseCryptoError> {
    let kek = decode_32bytes_b64(kek_b64)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| CaseCryptoError::InvalidKeyLength)?;
    let nonce_bytes = decode_b64(&blob.nonce_b64)?;
    let wrapped_ck = decode_b64(&blob.wrapped_ck_b64)?;
    let ck = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), wrapped_ck.as_ref())
        .map_err(|_| CaseCryptoError::DecryptFailed)?;
    Ok(STANDARD.encode(ck))
}

pub fn encrypt_case_plaintext(plaintext: &str, ck_b64: &str) -> Result<EncryptedCaseBlob, CaseCryptoError> {
    let ck = decode_32bytes_b64(ck_b64)?;
    let cipher = Aes256Gcm::new_from_slice(&ck).map_err(|_| CaseCryptoError::InvalidKeyLength)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| CaseCryptoError::EncryptFailed)?;
    Ok(EncryptedCaseBlob {
        version: 1,
        nonce_b64: STANDARD.encode(nonce_bytes),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_case_plaintext(blob: &EncryptedCaseBlob, ck_b64: &str) -> Result<String, CaseCryptoError> {
    let ck = decode_32bytes_b64(ck_b64)?;
    let cipher = Aes256Gcm::new_from_slice(&ck).map_err(|_| CaseCryptoError::InvalidKeyLength)?;
    let nonce_bytes = decode_b64(&blob.nonce_b64)?;
    let ciphertext = decode_b64(&blob.ciphertext_b64)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| CaseCryptoError::DecryptFailed)?;
    String::from_utf8(plaintext).map_err(|_| CaseCryptoError::InvalidUtf8)
}

pub fn decrypt_candidate_cases(
    encrypted: &[EncryptedCaseItem],
    candidate_case_ids: &HashSet<String>,
    ck_b64: &str,
) -> Result<Vec<DecryptedCaseItem>, CaseCryptoError> {
    let mut out = Vec::new();
    for item in encrypted {
        if candidate_case_ids.contains(&item.case_id) {
            let plaintext = decrypt_case_plaintext(&item.blob, ck_b64)?;
            out.push(DecryptedCaseItem {
                case_id: item.case_id.clone(),
                plaintext,
            });
        }
    }
    Ok(out)
}

fn decode_32bytes_b64(input: &str) -> Result<[u8; 32], CaseCryptoError> {
    let decoded = decode_b64(input)?;
    if decoded.len() != 32 {
        return Err(CaseCryptoError::InvalidKeyLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn decode_b64(input: &str) -> Result<Vec<u8>, CaseCryptoError> {
    STANDARD
        .decode(input)
        .map_err(|e| CaseCryptoError::Base64Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_ck_roundtrip() {
        let ck = generate_ck_b64();
        let kek = generate_ck_b64();
        let wrapped = wrap_ck(&ck, &kek, "android-keystore-v1").expect("wrap");
        let unwrapped = unwrap_ck(&wrapped, &kek).expect("unwrap");
        assert_eq!(ck, unwrapped);
        assert_eq!(wrapped.version, 1);
        assert_eq!(wrapped.kek_id, "android-keystore-v1");
    }

    #[test]
    fn encrypt_decrypt_case_roundtrip() {
        let ck = generate_ck_b64();
        let blob = encrypt_case_plaintext("{\"case\":\"a\"}", &ck).expect("encrypt");
        let plain = decrypt_case_plaintext(&blob, &ck).expect("decrypt");
        assert_eq!(plain, "{\"case\":\"a\"}");
    }

    #[test]
    fn decrypt_candidate_only() {
        let ck = generate_ck_b64();
        let a = EncryptedCaseItem {
            case_id: "c1".to_string(),
            blob: encrypt_case_plaintext("alpha", &ck).expect("enc"),
        };
        let b = EncryptedCaseItem {
            case_id: "c2".to_string(),
            blob: encrypt_case_plaintext("beta", &ck).expect("enc"),
        };
        let c = EncryptedCaseItem {
            case_id: "c3".to_string(),
            blob: encrypt_case_plaintext("gamma", &ck).expect("enc"),
        };
        let candidate_ids = HashSet::from_iter(["c2".to_string(), "c3".to_string()]);
        let result = decrypt_candidate_cases(&[a, b, c], &candidate_ids, &ck).expect("decrypt");
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|v| v.case_id == "c2" && v.plaintext == "beta"));
        assert!(result.iter().any(|v| v.case_id == "c3" && v.plaintext == "gamma"));
    }

    #[test]
    fn unwrap_with_wrong_kek_fails() {
        let ck = generate_ck_b64();
        let wrapped = wrap_ck(&ck, &generate_ck_b64(), "kek").expect("wrap");
        let wrong_kek = generate_ck_b64();
        let out = unwrap_ck(&wrapped, &wrong_kek);
        assert!(matches!(out, Err(CaseCryptoError::DecryptFailed)));
    }
}
