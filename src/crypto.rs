// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::*;
use rand::Rng;

const CONNECTION_IV_LENGTH: usize = 12;

pub fn encrypt_secret_payload(payload: &[u8], key: String) -> Result<(String, String)> {
    let key_bytes = base64::decode(key)?;
    let k = Key::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(k);

    let iv = rand::thread_rng().gen::<[u8; CONNECTION_IV_LENGTH]>();
    let nonce = Nonce::from_slice(&iv);

    let encrypted_payload = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow!("Encryption Error: {}", e))?;

    let encrypted_payload_b64 = base64::encode(encrypted_payload);
    let iv_b64 = base64::encode(iv);

    Ok((encrypted_payload_b64, iv_b64))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTION_KEY_LENGTH: usize = 32;

    #[test]
    pub fn test_payload_encryption() -> Result<()> {
        let payload = b"Test Payload";

        let key_bytes: Vec<u8> = rand::thread_rng()
            .gen::<[u8; CONNECTION_KEY_LENGTH]>()
            .to_vec();
        let key_b64 = base64::encode(&key_bytes);
        let key = Key::from_slice(&key_bytes);

        let cipher = Aes256Gcm::new(key);

        let (encrypted_payload, iv) = encrypt_secret_payload(payload, key_b64)?;
        let payload_bytes = base64::decode(encrypted_payload)?;
        let iv_bytes = base64::decode(iv)?;

        let nonce = Nonce::from_slice(&iv_bytes);

        let decrypted_payload = cipher
            .decrypt(nonce, payload_bytes.as_ref())
            .expect("Failed to decrypt.");

        assert_eq!(&decrypted_payload, payload);

        Ok(())
    }
}
