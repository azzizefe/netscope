// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Capture encryption — write a capture to disk sealed with a passphrase
//! (ROADMAP §5.4).
//!
//! The `.pcap.enc` container wraps *any* bytes (a serialized pcap, in practice)
//! in authenticated encryption so a capture that leaves a machine — an
//! incident bundle emailed to a colleague, a capture stored on a shared drive —
//! is unreadable without the passphrase and detectably tampered if altered.
//!
//! ## Format (`NSCPENC1`)
//!
//! ```text
//! magic        8   "NSCPENC1"
//! version      1   = 1
//! kdf          1   = 1 (Argon2id)
//! m_cost       4   Argon2 memory cost, KiB, little-endian
//! t_cost       4   Argon2 iterations, little-endian
//! p_cost       4   Argon2 parallelism, little-endian
//! salt_len     1
//! salt         salt_len
//! chunk_size   4   plaintext chunk size, little-endian
//! ── then one or more chunks until EOF ──
//! clen         4   ciphertext length (plaintext + 16-byte tag), little-endian
//! nonce        12  per-chunk random nonce
//! ciphertext   clen
//! ```
//!
//! A 256-bit key is derived from the passphrase and a random salt with
//! Argon2id; the parameters are stored in the header so decryption needs only
//! the passphrase. Each chunk is sealed with AES-256-GCM under a fresh random
//! nonce. The AEAD associated data binds every chunk to its **index** and a
//! **last-chunk flag**, so reordering, dropping, or truncating chunks fails
//! authentication — not just bit-flips inside a chunk.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};

const MAGIC: &[u8; 8] = b"NSCPENC1";
const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Plaintext bytes sealed per chunk. 1 MiB keeps the GCM tag overhead
/// negligible while bounding how much must be buffered to verify a chunk.
const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// Argon2id key-derivation parameters, stored in the header so a reader can
/// reproduce the key from the passphrase alone.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration count.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// Interactive-strength defaults (~19 MiB, 2 passes) — resistant to
    /// offline cracking without making an honest open feel slow.
    fn default() -> Self {
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Deliberately weak parameters for tests, so a roundtrip is instant.
    /// Never use for real captures.
    #[cfg(test)]
    fn fast() -> Self {
        Self {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn to_argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Fill `buf` with cryptographically secure random bytes.
fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| anyhow!("system RNG unavailable: {e}"))
}

fn derive_key(argon: &Argon2, passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Associated data binding a chunk to its position: 8-byte little-endian index
/// plus a last-chunk flag. Any reorder/drop/truncation changes what the reader
/// expects and fails the GCM tag check.
fn chunk_aad(index: u64, last: bool) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&index.to_le_bytes());
    aad[8] = u8::from(last);
    aad
}

/// Encrypt `plaintext` into the `.pcap.enc` container using `passphrase` and
/// the default (interactive-strength) KDF parameters.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    encrypt_with(
        plaintext,
        passphrase,
        KdfParams::default(),
        DEFAULT_CHUNK_SIZE,
    )
}

/// [`encrypt`] with explicit KDF parameters and chunk size (tests, tuning).
pub fn encrypt_with(
    plaintext: &[u8],
    passphrase: &str,
    kdf: KdfParams,
    chunk_size: u32,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    let chunk_size = chunk_size.max(1);

    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt)?;
    let argon = kdf.to_argon2()?;
    let key = derive_key(&argon, passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut out = Vec::with_capacity(plaintext.len() + plaintext.len() / 64 + 64);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&kdf.m_cost.to_le_bytes());
    out.extend_from_slice(&kdf.t_cost.to_le_bytes());
    out.extend_from_slice(&kdf.p_cost.to_le_bytes());
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&chunk_size.to_le_bytes());

    // An empty capture still gets one (empty) final chunk, so the reader always
    // sees an authenticated end-of-stream marker.
    let chunks = plaintext.chunks(chunk_size as usize);
    let total = plaintext.len().div_ceil(chunk_size as usize).max(1);
    let mut wrote = 0usize;
    let emit = |out: &mut Vec<u8>, data: &[u8], index: u64, last: bool| -> Result<()> {
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: data,
                    aad: &chunk_aad(index, last),
                },
            )
            .map_err(|_| anyhow!("chunk encryption failed"))?;
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(())
    };

    if plaintext.is_empty() {
        emit(&mut out, &[], 0, true)?;
    } else {
        for (i, chunk) in chunks.enumerate() {
            let last = i + 1 == total;
            emit(&mut out, chunk, i as u64, last)?;
            wrote += 1;
        }
        debug_assert_eq!(wrote, total);
    }
    Ok(out)
}

/// Decrypt a `.pcap.enc` container produced by [`encrypt`]. Fails on a wrong
/// passphrase, a corrupt header, or any tampering (a modified, reordered, or
/// truncated chunk), so a successful return means the bytes are authentic.
pub fn decrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut r = Reader { data, pos: 0 };
    let magic = r.take(8).context("file too short for header")?;
    if magic != MAGIC {
        bail!("not a netscope encrypted capture (bad magic)");
    }
    let version = r.u8().context("truncated header")?;
    if version != VERSION {
        bail!("unsupported .pcap.enc version {version}");
    }
    let kdf_id = r.u8().context("truncated header")?;
    if kdf_id != KDF_ARGON2ID {
        bail!("unsupported KDF id {kdf_id}");
    }
    let kdf = KdfParams {
        m_cost: r.u32().context("truncated header")?,
        t_cost: r.u32().context("truncated header")?,
        p_cost: r.u32().context("truncated header")?,
    };
    let salt_len = r.u8().context("truncated header")? as usize;
    let salt = r.take(salt_len).context("truncated salt")?.to_vec();
    let chunk_size = r.u32().context("truncated header")?;
    if chunk_size == 0 {
        bail!("invalid chunk size 0");
    }

    let argon = kdf.to_argon2()?;
    let key = derive_key(&argon, passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut plaintext = Vec::new();
    let mut index: u64 = 0;
    loop {
        let clen = r.u32().context("truncated chunk length")? as usize;
        let nonce = r.take(NONCE_LEN).context("truncated chunk nonce")?.to_vec();
        if clen < TAG_LEN {
            bail!("corrupt chunk (length below tag size)");
        }
        let ct = r.take(clen).context("truncated chunk body")?;
        let more = !r.at_end();

        // Whether this is the last chunk is authenticated: try `last = !more`
        // first (the normal case), and treat a failure as tampering.
        let last = !more;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ct,
                    aad: &chunk_aad(index, last),
                },
            )
            .map_err(|_| {
                anyhow!("authentication failed — wrong passphrase or the capture was tampered with")
            })?;
        plaintext.extend_from_slice(&pt);
        index += 1;
        if last {
            break;
        }
    }
    Ok(plaintext)
}

/// Does `data` start with the `.pcap.enc` magic?
pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// Minimal forward byte cursor over the container.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }
}

// --- Password hashing for local API-server accounts ---
//
// Distinct from the capture encryption above: this hashes short login passwords
// for the optional REST API's account store (`db::Database`). Argon2id with a
// random per-password salt, serialized as a standard PHC string
// (`$argon2id$v=19$m=...$salt$hash`) so the salt and parameters travel with the
// hash — `verify_password` needs only the stored string, and no fixed
// credentials are ever compiled into the binary or committed to the repo.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Hash a password with Argon2id and a fresh random salt, returning a PHC
/// string safe to store verbatim.
pub fn hash_password(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; SALT_LEN];
    random_bytes(&mut salt_bytes)?;
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow!("salt encoding failed: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verify `password` against a PHC string produced by [`hash_password`].
/// Returns `false` on any mismatch or malformed hash — never panics.
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(plaintext: &[u8]) {
        let enc = encrypt_with(plaintext, "correct horse", KdfParams::fast(), 64).unwrap();
        assert!(is_encrypted(&enc));
        let dec = decrypt(&enc, "correct horse").unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn roundtrip_various_sizes() {
        roundtrip(b"");
        roundtrip(b"a");
        roundtrip(b"exactly sixty-four bytes of capture data padded out here ok!!!!!"); // 64
        roundtrip(&[0xABu8; 200]); // several chunks at chunk_size 64
        roundtrip(&(0..=255u8).cycle().take(5000).collect::<Vec<_>>());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let enc = encrypt_with(b"secret capture", "hunter2", KdfParams::fast(), 64).unwrap();
        let err = decrypt(&enc, "hunter3").unwrap_err().to_string();
        assert!(err.contains("authentication failed"), "{err}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut enc = encrypt_with(&[7u8; 500], "pw", KdfParams::fast(), 64).unwrap();
        let last = enc.len() - 1;
        enc[last] ^= 0x01; // flip a bit in the final chunk's tag
        assert!(decrypt(&enc, "pw").is_err());
    }

    #[test]
    fn truncated_stream_fails() {
        // Drop the final chunk: the previous chunk was sealed with last=false,
        // so the reader reaching EOF expects last=true and authentication fails.
        let enc = encrypt_with(&[9u8; 200], "pw", KdfParams::fast(), 64).unwrap();
        // Header + at least two chunks exist; cut somewhere inside the tail.
        let cut = enc.len() - 40;
        let truncated = &enc[..cut];
        assert!(decrypt(truncated, "pw").is_err());
    }

    #[test]
    fn empty_passphrase_rejected() {
        assert!(encrypt(b"data", "").is_err());
    }

    #[test]
    fn foreign_bytes_are_not_encrypted() {
        assert!(!is_encrypted(b"\xd4\xc3\xb2\xa1")); // a plain pcap magic
        assert!(!is_encrypted(b"short"));
        assert!(is_encrypted(b"NSCPENC1 and then some"));
    }

    #[test]
    fn params_are_read_from_header() {
        // Encrypt with distinctive params; decrypt must succeed without being
        // told them (they come from the header).
        let kdf = KdfParams {
            m_cost: 16,
            t_cost: 3,
            p_cost: 1,
        };
        let enc = encrypt_with(b"parameterised", "pw", kdf, 8).unwrap();
        assert_eq!(decrypt(&enc, "pw").unwrap(), b"parameterised");
    }

    #[test]
    fn password_roundtrip_and_salt_uniqueness() {
        let h1 = hash_password("correct horse battery staple").unwrap();
        let h2 = hash_password("correct horse battery staple").unwrap();
        assert!(h1.starts_with("$argon2id$"), "{h1}");
        // Random salt ⇒ same password hashes differently, yet both verify.
        assert_ne!(h1, h2);
        assert!(verify_password("correct horse battery staple", &h1));
        assert!(verify_password("correct horse battery staple", &h2));
    }

    #[test]
    fn password_verify_rejects_wrong_and_malformed() {
        let hash = hash_password("s3cret").unwrap();
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("s3cret", "not-a-phc-string"));
        assert!(!verify_password("s3cret", ""));
    }
}
