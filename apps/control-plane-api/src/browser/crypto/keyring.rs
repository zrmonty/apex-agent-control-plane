use super::{
    CryptoError, ENVELOPE_VERSION, MAX_KEY_ID_BYTES, MAX_KEYS, MAX_PLAINTEXT_BYTES, TokenBinding,
    TokenEnvelope,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use std::fmt;
use zeroize::Zeroizing;

/// Explicitly configured 32-byte key with zeroizing ownership.
///
/// IDs are case-sensitive ASCII `[A-Za-z0-9._-]`, 1..=64 bytes. A retired key
/// has a positive, exclusive decryption deadline in Unix seconds. There is no
/// key generation, implicit default, or export of the secret key material.
pub struct TokenKey {
    key_id: String,
    material: Zeroizing<[u8; 32]>,
    decrypt_until_unix_seconds: Option<i64>,
}

impl TokenKey {
    /// Validate an active encryption/decryption key loaded by the caller.
    pub fn active(key_id: &str, material: Zeroizing<[u8; 32]>) -> Result<Self, CryptoError> {
        validate_key_id(key_id)?;
        Ok(Self {
            key_id: key_id.to_owned(),
            material,
            decrypt_until_unix_seconds: None,
        })
    }

    /// Validate a decryption-only key and its explicit, exclusive deadline.
    pub fn retired(
        key_id: &str,
        material: Zeroizing<[u8; 32]>,
        decrypt_until_unix_seconds: i64,
    ) -> Result<Self, CryptoError> {
        validate_key_id(key_id)?;
        if decrypt_until_unix_seconds <= 0 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            material,
            decrypt_until_unix_seconds: Some(decrypt_until_unix_seconds),
        })
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, CryptoError> {
        // The dependency's enabled `zeroize` feature also wipes its key copy
        // when this short-lived cipher is dropped.
        XChaCha20Poly1305::new_from_slice(self.material.as_ref())
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenKey([REDACTED])")
    }
}

/// Immutable keyring containing exactly one active key and at most three old keys.
/// Expired retired keys are inert; their presence does not disable the active key.
pub struct TokenKeyring {
    keys: Vec<TokenKey>,
    active_index: usize,
}

impl TokenKeyring {
    /// Require 1..=4 keys, unique IDs, and exactly one active key.
    pub fn new(keys: Vec<TokenKey>) -> Result<Self, CryptoError> {
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(CryptoError::InvalidKeyring);
        }
        let mut active_index = None;
        for (index, key) in keys.iter().enumerate() {
            if keys[..index].iter().any(|other| other.key_id == key.key_id) {
                return Err(CryptoError::InvalidKeyring);
            }
            if key.decrypt_until_unix_seconds.is_none() && active_index.replace(index).is_some() {
                return Err(CryptoError::InvalidKeyring);
            }
        }
        let active_index = active_index.ok_or(CryptoError::InvalidKeyring)?;
        Ok(Self { keys, active_index })
    }

    /// Seal at most 64 KiB using XChaCha20Poly1305 and a fresh fallible OS nonce.
    /// Reject a negative clock value or `now >= binding.absolute_expiry`.
    pub fn seal(
        &self,
        plaintext: &[u8],
        binding: &TokenBinding<'_>,
        now_unix_seconds: i64,
    ) -> Result<TokenEnvelope, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(CryptoError::InputTooLarge);
        }
        binding.check_at(now_unix_seconds)?;
        let key = self
            .keys
            .get(self.active_index)
            .ok_or(CryptoError::InvalidKeyring)?;
        let aad = binding.associated_data(ENVELOPE_VERSION, &key.key_id)?;
        let cipher = key.cipher()?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::EntropyUnavailable)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(TokenEnvelope {
            version: ENVELOPE_VERSION,
            key_id: key.key_id.clone(),
            nonce,
            ciphertext,
        })
    }

    /// Authenticate the exact binding and selected key, then return zeroizing
    /// bytes. Expired bindings/keys and any integrity failure return no plaintext.
    pub fn open(
        &self,
        envelope: &TokenEnvelope,
        binding: &TokenBinding<'_>,
        now_unix_seconds: i64,
    ) -> Result<SecretBytes, CryptoError> {
        envelope.validate()?;
        binding.check_at(now_unix_seconds)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id == envelope.key_id())
            .ok_or(CryptoError::UnknownKey)?;
        if key
            .decrypt_until_unix_seconds
            .is_some_and(|until| now_unix_seconds >= until)
        {
            return Err(CryptoError::ExpiredKey);
        }
        let aad = binding.associated_data(envelope.version(), envelope.key_id())?;
        let cipher = key.cipher()?;
        // XChaCha20Poly1305 verifies the tag before decrypting. Immediately
        // transfer the returned allocation into zeroizing, redacted ownership.
        let bytes = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(*envelope.nonce()),
                    Payload {
                        msg: envelope.ciphertext(),
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );
        Ok(SecretBytes { bytes })
    }
}

pub(super) fn validate_key_id(key_id: &str) -> Result<(), CryptoError> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_BYTES
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CryptoError::InvalidKey);
    }
    Ok(())
}

impl fmt::Debug for TokenKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenKeyring([REDACTED])")
    }
}

/// Decrypted bytes with zeroizing storage and redacted Debug.
/// No cloning, display, serialization, or conversion into an unprotected buffer.
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Explicit access for the provider-token consumer; never log these bytes.
    pub fn expose_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
