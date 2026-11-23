//! Metadata-redacted and AES-256-GCM + PBKDF2-HMAC-SHA256 encrypted backup export/import with crash-safe recovery journal.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use eko::file::File;
use nago_rustls::rustls::crypto::SecureRandom;
use serde::{Deserialize, Serialize};

use crate::logwatch::acquire_exclusive_lock;
use crate::paths::{base64_decode, base64_encode, sha256_bytes};
use crate::policy::lookup_account_secret;
use crate::store::atomic_write_private;
use crate::{Accounts, Error, Paths, Result, Settings, Store, Vault, VERSION};

/// Current backup schema version.
pub const BACKUP_SCHEMA: u32 = 2;

/// PBKDF2-HMAC-SHA256 iteration count required for encrypted secret bundles.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Cipher identifier stored in [`EncryptedSecrets`].
pub const BACKUP_CIPHER_NAME: &str = "aes-256-gcm";

/// KDF identifier stored in [`EncryptedSecrets`].
pub const BACKUP_KDF_NAME: &str = "pbkdf2-hmac-sha256";

/// Additional authenticated data bound to every AES-256-GCM backup ciphertext.
const BACKUP_GCM_AAD: &[u8] = b"agy-swap-backup-v2";

/// Minimum passphrase length in Unicode scalar values for `--include-secrets`.
pub const MIN_PASSPHRASE_CHARS: usize = 8;

fn default_backup_cipher() -> String {
    BACKUP_CIPHER_NAME.to_string()
}

/// Encrypted vault secrets map envelope inside [`BackupBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecrets {
    #[serde(default = "default_backup_cipher")]
    pub cipher: String,
    pub kdf: String,
    pub iterations: u32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// Portable JSON backup archive supporting metadata-only and encrypted-secrets modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupBundle {
    pub schema: u32,
    pub version: String,
    pub created_at_unix: i64,
    pub contains_secrets: bool,
    pub accounts: Accounts,
    pub settings: Settings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_secrets: Option<EncryptedSecrets>,
}

/// Summary returned after importing a [`BackupBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub accounts_count: usize,
    pub secrets_restored: usize,
    pub merged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RestoreJournal {
    accounts_raw: Option<String>,
    settings_raw: Option<String>,
    vault_raw: Option<String>,
}

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    let mut i = 0usize;
    while i < 16 {
        let off = i * 4;
        w[i] = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        i += 1;
    }
    while i < 64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
        i += 1;
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    let mut r = 0usize;
    while r < 64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[r])
            .wrapping_add(w[r]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        r += 1;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn sha256_after_midstate_var(midstate: &[u32; 8], msg: &[u8]) -> [u8; 32] {
    let mut state = *midstate;
    let full = msg.len() / 64;
    let mut idx = 0usize;
    while idx < full {
        let mut blk = [0u8; 64];
        blk.copy_from_slice(&msg[idx * 64..(idx + 1) * 64]);
        sha256_compress(&mut state, &blk);
        idx += 1;
    }
    let rem = &msg[full * 64..];
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let total_bytes = 64u64.wrapping_add(msg.len() as u64);
    let bit_len = total_bytes.wrapping_mul(8);
    let pad_len = if rem.len() < 56 { 64 } else { 128 };
    tail[pad_len - 8..pad_len].copy_from_slice(&bit_len.to_be_bytes());
    let mut b0 = [0u8; 64];
    b0.copy_from_slice(&tail[..64]);
    sha256_compress(&mut state, &b0);
    if pad_len == 128 {
        let mut b1 = [0u8; 64];
        b1.copy_from_slice(&tail[64..128]);
        sha256_compress(&mut state, &b1);
    }
    let mut out = [0u8; 32];
    let mut w = 0usize;
    while w < 8 {
        out[w * 4..(w + 1) * 4].copy_from_slice(&state[w].to_be_bytes());
        w += 1;
    }
    out
}

fn sha256_after_midstate_32(midstate: &[u32; 8], msg32: &[u8; 32]) -> [u8; 32] {
    let mut state = *midstate;
    let mut blk = [0u8; 64];
    blk[..32].copy_from_slice(msg32);
    blk[32] = 0x80;
    // 64-byte key pad block + 32-byte digest = 96 bytes = 768 bits.
    blk[56..64].copy_from_slice(&768u64.to_be_bytes());
    sha256_compress(&mut state, &blk);
    let mut out = [0u8; 32];
    let mut w = 0usize;
    while w < 8 {
        out[w * 4..(w + 1) * 4].copy_from_slice(&state[w].to_be_bytes());
        w += 1;
    }
    out
}

/// Compute RFC 2898 PBKDF2-HMAC-SHA256 using precomputed SHA-256 `ipad`/`opad` midstates.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let mut key_block = [0u8; 64];
    if password.len() > 64 {
        let hashed = sha256_bytes(password);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..password.len()].copy_from_slice(password);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    let mut i = 0usize;
    while i < 64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
        i += 1;
    }

    let mut ipad_mid = SHA256_H0;
    sha256_compress(&mut ipad_mid, &ipad);
    let mut opad_mid = SHA256_H0;
    sha256_compress(&mut opad_mid, &opad);

    let iters = iterations.max(1);
    let mut salt_and_idx = Vec::with_capacity(salt.len() + 4);
    let mut block_num = 1u32;
    let mut offset = 0usize;

    while offset < out.len() {
        salt_and_idx.clear();
        salt_and_idx.extend_from_slice(salt);
        salt_and_idx.extend_from_slice(&block_num.to_be_bytes());

        let inner_0 = sha256_after_midstate_var(&ipad_mid, &salt_and_idx);
        let mut u = sha256_after_midstate_32(&opad_mid, &inner_0);
        let mut t = u;

        let mut round = 1u32;
        while round < iters {
            let inner = sha256_after_midstate_32(&ipad_mid, &u);
            u = sha256_after_midstate_32(&opad_mid, &inner);
            let mut j = 0usize;
            while j < 32 {
                t[j] ^= u[j];
                j += 1;
            }
            round += 1;
        }

        let take = (out.len() - offset).min(32);
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        block_num = block_num.wrapping_add(1);
    }
}

const fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        let mask = 0u8.wrapping_sub(b & 1);
        p ^= a & mask;
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

const fn gf256_inv(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }
    // x^254 in GF(2^8).
    let mut acc = 1u8;
    let mut base = x;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            acc = gf256_mul(acc, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    acc
}

const fn build_aes_sbox() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let y = gf256_inv(i as u8);
        table[i] =
            y ^ y.rotate_left(1) ^ y.rotate_left(2) ^ y.rotate_left(3) ^ y.rotate_left(4) ^ 0x63;
        i += 1;
    }
    table
}

const AES_SBOX: [u8; 256] = build_aes_sbox();
const AES_RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

#[inline]
const fn xtime(x: u8) -> u8 {
    let hi = x & 0x80;
    let shifted = x << 1;
    if hi != 0 {
        shifted ^ 0x1b
    } else {
        shifted
    }
}

fn aes256_expand_key(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut w = [[0u8; 4]; 60];
    let mut i = 0usize;
    while i < 8 {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        i += 1;
    }
    while i < 60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = [
                AES_SBOX[temp[1] as usize] ^ AES_RCON[(i / 8) - 1],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
                AES_SBOX[temp[0] as usize],
            ];
        } else if i % 8 == 4 {
            temp = [
                AES_SBOX[temp[0] as usize],
                AES_SBOX[temp[1] as usize],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
            ];
        }
        w[i] = [
            w[i - 8][0] ^ temp[0],
            w[i - 8][1] ^ temp[1],
            w[i - 8][2] ^ temp[2],
            w[i - 8][3] ^ temp[3],
        ];
        i += 1;
    }

    let mut rk = [[0u8; 16]; 15];
    let mut r = 0usize;
    while r < 15 {
        let mut c = 0usize;
        while c < 4 {
            rk[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            c += 1;
        }
        r += 1;
    }
    rk
}

fn aes256_encrypt_block(rk: &[[u8; 16]; 15], input: &[u8; 16]) -> [u8; 16] {
    let mut s = *input;
    let mut i = 0usize;
    while i < 16 {
        s[i] ^= rk[0][i];
        i += 1;
    }

    let mut r = 1usize;
    while r < 14 {
        let mut k = 0usize;
        while k < 16 {
            s[k] = AES_SBOX[s[k] as usize];
            k += 1;
        }
        // ShiftRows
        let t1 = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t1;

        s.swap(2, 10);
        s.swap(6, 14);

        let t3 = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t3;

        // MixColumns + AddRoundKey
        let mut c = 0usize;
        while c < 4 {
            let idx = 4 * c;
            let a0 = s[idx];
            let a1 = s[idx + 1];
            let a2 = s[idx + 2];
            let a3 = s[idx + 3];
            s[idx] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3 ^ rk[r][idx];
            s[idx + 1] = a0 ^ xtime(a1 ^ a2) ^ a2 ^ a3 ^ rk[r][idx + 1];
            s[idx + 2] = a0 ^ a1 ^ xtime(a2 ^ a3) ^ a3 ^ rk[r][idx + 2];
            s[idx + 3] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2 ^ rk[r][idx + 3];
            c += 1;
        }
        r += 1;
    }

    let mut k = 0usize;
    while k < 16 {
        s[k] = AES_SBOX[s[k] as usize];
        k += 1;
    }
    let t1 = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t1;
    s.swap(2, 10);
    s.swap(6, 14);
    let t3 = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t3;

    let mut j = 0usize;
    while j < 16 {
        s[j] ^= rk[14][j];
        j += 1;
    }
    s
}

fn ghash_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    let mut i = 0usize;
    while i < 128 {
        let bit = (x >> (127 - i)) & 1;
        let mask = 0u128.wrapping_sub(bit);
        z ^= v & mask;
        let lsb = v & 1;
        let r_mask = 0u128.wrapping_sub(lsb);
        v = (v >> 1) ^ (0xe1000000_00000000_00000000_00000000_u128 & r_mask);
        i += 1;
    }
    z
}

fn ghash(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut y = 0u128;
    for chunk in aad.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        y = ghash_mul(y ^ u128::from_be_bytes(blk), h);
    }
    for chunk in ciphertext.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        y = ghash_mul(y ^ u128::from_be_bytes(blk), h);
    }
    let mut len_blk = [0u8; 16];
    len_blk[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_blk[8..16].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_mul(y ^ u128::from_be_bytes(len_blk), h)
}

fn inc32(counter: &mut [u8; 16]) {
    let next = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]])
        .wrapping_add(1);
    counter[12..16].copy_from_slice(&next.to_be_bytes());
}

fn aes256_gctr(rk: &[[u8; 16]; 15], initial_cb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut cb = *initial_cb;
    for chunk in data.chunks(16) {
        let ks = aes256_encrypt_block(rk, &cb);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        inc32(&mut cb);
    }
    out
}

/// Encrypt `plaintext` with AES-256-GCM (96-bit nonce, 128-bit authentication tag appended).
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let rk = aes256_expand_key(key);
    let h = u128::from_be_bytes(aes256_encrypt_block(&rk, &[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut ctr = j0;
    inc32(&mut ctr);

    let mut ciphertext = aes256_gctr(&rk, &ctr, plaintext);
    let s = ghash(h, aad, &ciphertext);
    let tag_mask = u128::from_be_bytes(aes256_encrypt_block(&rk, &j0));
    let tag = (s ^ tag_mask).to_be_bytes();
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

/// Verify the 128-bit authentication tag in constant time and decrypt AES-256-GCM `ciphertext_and_tag`.
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_and_tag.len() < 16 {
        return Err(Error::Crypto(
            "ciphertext shorter than AES-256-GCM authentication tag".to_string(),
        ));
    }
    let ct_len = ciphertext_and_tag.len() - 16;
    let ciphertext = &ciphertext_and_tag[..ct_len];
    let actual_tag = &ciphertext_and_tag[ct_len..];

    let rk = aes256_expand_key(key);
    let h = u128::from_be_bytes(aes256_encrypt_block(&rk, &[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let s = ghash(h, aad, ciphertext);
    let tag_mask = u128::from_be_bytes(aes256_encrypt_block(&rk, &j0));
    let expected_tag = (s ^ tag_mask).to_be_bytes();

    let mut diff = 0u8;
    let mut i = 0usize;
    while i < 16 {
        diff |= expected_tag[i] ^ actual_tag[i];
        i += 1;
    }
    if diff != 0 {
        return Err(Error::Crypto(
            "wrong passphrase or corrupted backup".to_string(),
        ));
    }

    let mut ctr = j0;
    inc32(&mut ctr);
    Ok(aes256_gctr(&rk, &ctr, ciphertext))
}

fn fill_os_random(buf: &mut [u8]) -> Result<()> {
    if ps_rustcrypto::Provider.fill(buf).is_ok() {
        return Ok(());
    }
    let mut f = File::open("/dev/urandom")?;
    let mut offset = 0usize;
    while offset < buf.len() {
        let n = f.read(&mut buf[offset..])?;
        if n == 0 {
            return Err(Error::Crypto(
                "OS CSPRNG returned unexpected EOF".to_string(),
            ));
        }
        offset += n;
    }
    Ok(())
}

fn decrypt_secrets_envelope(
    envelope: &EncryptedSecrets,
    passphrase: &str,
) -> Result<BTreeMap<String, String>> {
    if !envelope.kdf.eq_ignore_ascii_case(BACKUP_KDF_NAME)
        && !envelope.kdf.eq_ignore_ascii_case("pbkdf2-sha256-600k")
    {
        return Err(Error::Crypto(format!(
            "unsupported backup KDF '{}'",
            envelope.kdf
        )));
    }
    if envelope.iterations < 10_000 || envelope.iterations > 5_000_000 {
        return Err(Error::Crypto(format!(
            "unsupported PBKDF2 iteration count {}",
            envelope.iterations
        )));
    }
    let salt = base64_decode(&envelope.salt_b64)
        .ok_or_else(|| Error::Crypto("invalid base64 salt in backup".to_string()))?;
    if salt.len() != 16 {
        return Err(Error::Crypto("invalid backup salt length".to_string()));
    }
    let nonce_vec = base64_decode(&envelope.nonce_b64)
        .ok_or_else(|| Error::Crypto("invalid base64 nonce in backup".to_string()))?;
    if nonce_vec.len() != 12 {
        return Err(Error::Crypto("invalid backup nonce length".to_string()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_vec);
    let ciphertext = base64_decode(&envelope.ciphertext_b64)
        .ok_or_else(|| Error::Crypto("invalid base64 ciphertext in backup".to_string()))?;

    let mut key = [0u8; 32];
    pbkdf2_hmac_sha256(passphrase.as_bytes(), &salt, envelope.iterations, &mut key);
    let plaintext = aes256_gcm_decrypt(&key, &nonce, &ciphertext, BACKUP_GCM_AAD)?;
    key.fill(0);

    serde_json::from_slice::<BTreeMap<String, String>>(&plaintext)
        .map_err(|e| Error::Crypto(format!("corrupted decrypted secrets map: {e}")))
}

/// Export accounts and settings into a [`BackupBundle`].
///
/// Metadata-only mode redacts all secrets and vault references. When `include_secrets` is `true`,
/// secrets are encrypted with AES-256-GCM under a key derived via 600,000-iteration PBKDF2-HMAC-SHA256.
pub fn export_backup(
    store: &Store,
    vault: &Vault,
    include_secrets: bool,
    passphrase: Option<&str>,
    now_unix: i64,
) -> Result<BackupBundle> {
    let mut accounts = store.load()?;
    let settings = store.load_settings()?;

    let encrypted_secrets = if include_secrets {
        let pass = passphrase.unwrap_or("");
        if pass.chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(Error::InvalidInput(format!(
                "passphrase must contain at least {MIN_PASSPHRASE_CHARS} characters"
            )));
        }
        let mut secrets_map: BTreeMap<String, String> = BTreeMap::new();
        for email in &accounts.order {
            if let Some(acc) = accounts.get(email) {
                if let Some((vault_key, secret)) = lookup_account_secret(vault, acc)? {
                    secrets_map.insert(vault_key, secret);
                }
            }
        }
        let plaintext =
            serde_json::to_vec(&secrets_map).map_err(|e| Error::Json(e.to_string()))?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        fill_os_random(&mut salt)?;
        fill_os_random(&mut nonce)?;

        let mut key = [0u8; 32];
        pbkdf2_hmac_sha256(pass.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);
        let ciphertext = aes256_gcm_encrypt(&key, &nonce, &plaintext, BACKUP_GCM_AAD);
        key.fill(0);

        Some(EncryptedSecrets {
            cipher: BACKUP_CIPHER_NAME.to_string(),
            kdf: BACKUP_KDF_NAME.to_string(),
            iterations: PBKDF2_ITERATIONS,
            salt_b64: base64_encode(&salt),
            nonce_b64: base64_encode(&nonce),
            ciphertext_b64: base64_encode(&ciphertext),
        })
    } else {
        None
    };

    // Redact all plaintext tokens and vault references in the public accounts map.
    for email in accounts.order.clone() {
        if let Some(acc) = accounts.get_mut(&email) {
            acc.legacy_token_data = None;
            acc.vault_ref = None;
        }
    }

    Ok(BackupBundle {
        schema: BACKUP_SCHEMA,
        version: VERSION.to_string(),
        created_at_unix: now_unix,
        contains_secrets: include_secrets,
        accounts,
        settings,
        encrypted_secrets,
    })
}

/// Export a [`BackupBundle`] and write it atomically (`0600`) to `out_path`.
pub fn export_backup_to_file(
    out_path: &str,
    store: &Store,
    vault: &Vault,
    include_secrets: bool,
    passphrase: Option<&str>,
    now_unix: i64,
) -> Result<BackupBundle> {
    let bundle = export_backup(store, vault, include_secrets, passphrase, now_unix)?;
    let mut encoded =
        serde_json::to_vec_pretty(&bundle).map_err(|e| Error::Json(e.to_string()))?;
    encoded.push(b'\n');
    atomic_write_private(out_path, &encoded)?;
    Ok(bundle)
}

/// Verify a [`BackupBundle`] (including passphrase decryption when `contains_secrets` is set).
pub fn verify_backup(bundle: &BackupBundle, passphrase: Option<&str>) -> Result<usize> {
    if bundle.schema == 0 || bundle.schema > BACKUP_SCHEMA {
        return Err(Error::InvalidInput(format!(
            "unsupported backup schema {}",
            bundle.schema
        )));
    }
    if bundle.contains_secrets {
        let env = bundle.encrypted_secrets.as_ref().ok_or_else(|| {
            Error::Crypto("backup claims contains_secrets without encrypted_secrets".to_string())
        })?;
        let pass = passphrase.unwrap_or("");
        if pass.is_empty() {
            return Err(Error::InvalidInput(
                "encrypted backup requires a passphrase".to_string(),
            ));
        }
        let map = decrypt_secrets_envelope(env, pass)?;
        Ok(map.len())
    } else {
        Ok(0)
    }
}

fn restore_journal_path(paths: &Paths) -> String {
    format!("{}/restore-journal.json", paths.config_dir)
}

fn restore_lock_path(paths: &Paths) -> String {
    format!("{}/restore-journal.lock", paths.config_dir)
}

fn read_optional_file(path: &str) -> Result<Option<String>> {
    if !eko::file::exists(path) {
        return Ok(None);
    }
    Ok(Some(eko::file::read_to_string(path)?))
}

fn restore_optional_file(path: &str, content: &Option<String>) -> Result<()> {
    match content {
        Some(raw) => atomic_write_private(path, raw.as_bytes()),
        None => {
            eko::file::remove_file(path);
            Ok(())
        }
    }
}

/// Replay an interrupted crash-recovery journal if one is present on disk.
pub fn recover_restore_journal(paths: &Paths) -> Result<bool> {
    let jpath = restore_journal_path(paths);
    if !eko::file::exists(&jpath) {
        return Ok(false);
    }
    let _guard = acquire_exclusive_lock(&restore_lock_path(paths))?;
    if !eko::file::exists(&jpath) {
        return Ok(false);
    }
    let raw = eko::file::read_to_string(&jpath)?;
    let journal: RestoreJournal =
        serde_json::from_str(&raw).map_err(|e| Error::Json(e.to_string()))?;
    restore_optional_file(&paths.accounts_file, &journal.accounts_raw)?;
    restore_optional_file(&paths.settings_file, &journal.settings_raw)?;
    restore_optional_file(&paths.vault_file, &journal.vault_raw)?;
    eko::file::remove_file(&jpath);
    Ok(true)
}

fn find_secret_for_email(
    secrets_map: &BTreeMap<String, String>,
    email: &str,
) -> Option<(String, String)> {
    let lower = email.trim().to_ascii_lowercase();
    let prefixed = format!("account:{lower}");
    if let Some(sec) = secrets_map.get(&prefixed) {
        return Some((prefixed, sec.clone()));
    }
    if let Some(sec) = secrets_map.get(&lower) {
        return Some((lower, sec.clone()));
    }
    if let Some(sec) = secrets_map.get(email) {
        return Some((email.to_string(), sec.clone()));
    }
    for (k, v) in secrets_map {
        if k.eq_ignore_ascii_case(&prefixed) || k.eq_ignore_ascii_case(&lower) {
            return Some((k.clone(), v.clone()));
        }
    }
    None
}

/// Import a [`BackupBundle`] into `store` and `vault` using a crash-safe recovery journal.
pub fn import_backup(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    bundle: &BackupBundle,
    passphrase: Option<&str>,
    merge: bool,
) -> Result<ImportSummary> {
    let _ = recover_restore_journal(paths)?;
    if bundle.schema == 0 || bundle.schema > BACKUP_SCHEMA {
        return Err(Error::InvalidInput(format!(
            "unsupported backup schema {}",
            bundle.schema
        )));
    }

    // Authenticate and decrypt before touching any on-disk state.
    let decrypted_secrets = if bundle.contains_secrets {
        let env = bundle.encrypted_secrets.as_ref().ok_or_else(|| {
            Error::Crypto("backup is missing encrypted_secrets payload".to_string())
        })?;
        let pass = passphrase.unwrap_or("");
        if pass.is_empty() {
            return Err(Error::InvalidInput(
                "encrypted backup requires a passphrase".to_string(),
            ));
        }
        Some(decrypt_secrets_envelope(env, pass)?)
    } else {
        None
    };

    let _guard = acquire_exclusive_lock(&restore_lock_path(paths))?;
    let jpath = restore_journal_path(paths);
    let journal = RestoreJournal {
        accounts_raw: read_optional_file(&paths.accounts_file)?,
        settings_raw: read_optional_file(&paths.settings_file)?,
        vault_raw: read_optional_file(&paths.vault_file)?,
    };
    let mut jbytes =
        serde_json::to_vec_pretty(&journal).map_err(|e| Error::Json(e.to_string()))?;
    jbytes.push(b'\n');
    atomic_write_private(&jpath, &jbytes)?;

    let apply_res = (|| -> Result<ImportSummary> {
        let mut existing = store.load()?;
        let mut secrets_restored = 0usize;

        if !merge {
            // Delete vault keys belonging to replaced accounts.
            for email in &existing.order {
                if let Some(acc) = existing.get(email) {
                    if let Some(ref vref) = acc.vault_ref {
                        let _ = vault.delete(vref);
                    }
                    let _ = vault.delete(&format!("account:{}", acc.email));
                }
            }
            existing.order.clear();
            existing.by_email.clear();
        }

        for email in &bundle.accounts.order {
            let Some(mut incoming) = bundle.accounts.get(email).cloned() else {
                continue;
            };
            incoming.legacy_token_data = None;

            if let Some(ref map) = decrypted_secrets {
                if let Some((vkey, secret)) = find_secret_for_email(map, &incoming.email) {
                    vault.set(&vkey, &secret)?;
                    incoming.vault_ref = Some(vkey);
                    secrets_restored += 1;
                }
            } else if merge {
                if let Some(prev) = existing.get(&incoming.email) {
                    if incoming.vault_ref.is_none() {
                        incoming.vault_ref = prev.vault_ref.clone();
                    }
                }
            }
            existing.upsert(incoming);
        }

        let next_settings = if merge {
            let mut merged = store.load_settings().unwrap_or_default();
            for (k, v) in &bundle.settings.aliases {
                merged.aliases.insert(k.clone(), v.clone());
            }
            for (k, v) in &bundle.settings.profiles {
                merged.profiles.insert(k.clone(), v.clone());
            }
            for b in &bundle.settings.bindings {
                if !merged.bindings.iter().any(|eb| eb.path == b.path) {
                    merged.bindings.push(b.clone());
                }
            }
            merged
        } else {
            bundle.settings.clone()
        };

        store.save(&mut existing)?;
        store.save_settings(&next_settings)?;
        Ok(ImportSummary {
            accounts_count: bundle.accounts.len(),
            secrets_restored,
            merged: merge,
        })
    })();

    match apply_res {
        Ok(summary) => {
            eko::file::remove_file(&jpath);
            Ok(summary)
        }
        Err(err) => {
            let _ = restore_optional_file(&paths.accounts_file, &journal.accounts_raw);
            let _ = restore_optional_file(&paths.settings_file, &journal.settings_raw);
            let _ = restore_optional_file(&paths.vault_file, &journal.vault_raw);
            eko::file::remove_file(&jpath);
            Err(err)
        }
    }
}

/// Read a [`BackupBundle`] JSON file from `in_path` and import it via [`import_backup`].
pub fn import_backup_from_file(
    in_path: &str,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    passphrase: Option<&str>,
    merge: bool,
) -> Result<ImportSummary> {
    let raw = eko::file::read_to_string(in_path)?;
    let bundle: BackupBundle =
        serde_json::from_str(&raw).map_err(|e| Error::Json(e.to_string()))?;
    import_backup(paths, store, vault, &bundle, passphrase, merge)
}
