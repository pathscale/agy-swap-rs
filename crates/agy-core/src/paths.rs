#[allow(unused_imports)]
use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paths {
    pub home: String,
    pub config_dir: String,
    pub accounts_file: String,
    pub accounts_lock: String,
    pub vault_file: String,
    pub vault_lock: String,
    pub settings_file: String,
    pub history_file: String,
    pub runtime_file: String,
    pub gemini_dir: String,
    pub agy_oauth_file: String,
    pub agy_log_dir: String,
    pub hub_reload_file: String,
}

pub fn clean_path_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed == "/" {
        return "/".to_string();
    }
    trimmed.trim_end_matches('/').to_string()
}

pub fn join_path(base: &str, rel: &str) -> String {
    let rel_clean = rel.trim_start_matches('/');
    if base.is_empty() {
        return rel_clean.to_string();
    }
    if rel_clean.is_empty() {
        return clean_path_str(base);
    }
    if base == "/" {
        format!("/{rel_clean}")
    } else {
        format!("{}/{rel_clean}", base.trim_end_matches('/'))
    }
}

impl Paths {
    pub fn detect() -> Result<Self> {
        let home = eko::env::var("HOME")
            .map(|v| clean_path_str(&v))
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Error::NotFound("HOME environment variable is not set".to_string()))?;
        let config_dir = eko::env::var("AGY_SWAP_CONFIG_DIR")
            .map(|v| clean_path_str(&v))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| join_path(&home, ".config/agy-swap-rs"));
        Ok(Self::from_home_and_config(&home, &config_dir))
    }

    pub fn from_home(home: &str) -> Self {
        let clean_home = clean_path_str(home);
        let config_dir = join_path(&clean_home, ".config/agy-swap-rs");
        Self::from_home_and_config(&clean_home, &config_dir)
    }

    pub fn from_home_and_config(home: &str, config_dir: &str) -> Self {
        let home = clean_path_str(home);
        let config_dir = clean_path_str(config_dir);
        let gemini_dir = join_path(&home, ".gemini");
        Self {
            accounts_file: join_path(&config_dir, "accounts.json"),
            accounts_lock: join_path(&config_dir, ".accounts.lock"),
            vault_file: join_path(&config_dir, "vault.json"),
            vault_lock: join_path(&config_dir, "vault.json.lock"),
            settings_file: join_path(&config_dir, "settings.json"),
            history_file: join_path(&config_dir, "history-v1.jsonl"),
            runtime_file: join_path(&config_dir, "runtime-state.json"),
            agy_oauth_file: join_path(&gemini_dir, "antigravity-cli/antigravity-oauth-token"),
            agy_log_dir: join_path(&gemini_dir, "antigravity-cli/log"),
            hub_reload_file: join_path(&gemini_dir, "antigravity-cli/cache/agy-swap-hub-reload"),
            home,
            config_dir,
            gemini_dir,
        }
    }

    pub fn ide_oauth_file(&self) -> String {
        join_path(&self.gemini_dir, "antigravity/antigravity-oauth-token")
    }

    pub fn jetski_oauth_file(&self) -> String {
        join_path(&self.gemini_dir, "jetski-standalone-oauth-token")
    }

    pub fn oauth_creds_file(&self) -> String {
        join_path(&self.gemini_dir, "oauth_creds.json")
    }

    pub fn google_accounts_file(&self) -> String {
        join_path(&self.gemini_dir, "google_accounts.json")
    }

    pub fn session_lock_file(&self) -> String {
        join_path(&self.config_dir, ".session.lock")
    }

    pub fn accounts_backup_file(&self) -> String {
        format!("{}.bak", self.accounts_file)
    }

    pub fn journal_dir(&self) -> String {
        join_path(&self.config_dir, "journals")
    }

    pub fn cli_log_file(&self) -> String {
        join_path(&self.gemini_dir, "antigravity-cli/cli.log")
    }
}

pub fn wall_unix_secs() -> i64 {
    eko::time::epoch_secs()
}

pub fn wall_unix_ns() -> i64 {
    let mut ts = eko::libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        eko::libc::clock_gettime(eko::libc::CLOCK_REALTIME, &mut ts);
    }
    ((ts.tv_sec as i128) * 1_000_000_000 + (ts.tv_nsec as i128)) as i64
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre: Option<String>,
}

impl SemVer {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self { major, minor, patch, pre: None }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let without_v = trimmed
            .strip_prefix('v')
            .or_else(|| trimmed.strip_prefix('V'))
            .unwrap_or(trimmed);
        let without_build = match without_v.split_once('+') {
            Some((head, _)) => head,
            None => without_v,
        };
        let (core_part, pre) = match without_build.split_once('-') {
            Some((head, tail)) => {
                if tail.is_empty() {
                    return Err(Error::InvalidInput(format!("empty prerelease in version {raw}")));
                }
                (head, Some(tail.to_string()))
            }
            None => (without_build, None),
        };
        let mut parts = core_part.split('.');
        let major_s = parts
            .next()
            .ok_or_else(|| Error::InvalidInput(format!("invalid version {raw}")))?;
        let minor_s = parts
            .next()
            .ok_or_else(|| Error::InvalidInput(format!("invalid version {raw}")))?;
        let patch_s = parts
            .next()
            .ok_or_else(|| Error::InvalidInput(format!("invalid version {raw}")))?;
        if parts.next().is_some() {
            return Err(Error::InvalidInput(format!("too many components in version {raw}")));
        }
        let parse_num = |s: &str| -> Result<u64> {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidInput(format!("invalid numeric component in {raw}")));
            }
            s.parse::<u64>()
                .map_err(|_| Error::InvalidInput(format!("version component overflow in {raw}")))
        };
        Ok(Self {
            major: parse_num(major_s)?,
            minor: parse_num(minor_s)?,
            patch: parse_num(patch_s)?,
            pre,
        })
    }

    pub fn compare_str(left: &str, right: &str) -> Result<Ordering> {
        Ok(Self::parse(left)?.cmp(&Self::parse(right)?))
    }
}

impl FromStr for SemVer {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

fn cmp_prerelease(left: &str, right: &str) -> Ordering {
    let mut l_iter = left.split('.');
    let mut r_iter = right.split('.');
    loop {
        match (l_iter.next(), r_iter.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                let a_num = !a.is_empty() && a.bytes().all(|c| c.is_ascii_digit());
                let b_num = !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit());
                let ord = match (a_num, b_num) {
                    (true, true) => match (a.parse::<u64>(), b.parse::<u64>()) {
                        (Ok(na), Ok(nb)) => na.cmp(&nb),
                        _ => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
                    },
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => a.cmp(b),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)) {
            Ordering::Equal => match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => cmp_prerelease(a, b),
            },
            ord => ord,
        }
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

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
    let mut round = 0usize;
    while round < 64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[round])
            .wrapping_add(w[round]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
        round += 1;
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

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let full_chunks = data.len() / 64;
    let mut idx = 0usize;
    while idx < full_chunks {
        let mut blk = [0u8; 64];
        blk.copy_from_slice(&data[idx * 64..(idx + 1) * 64]);
        sha256_compress(&mut state, &blk);
        idx += 1;
    }
    let rem = &data[full_chunks * 64..];
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let total_len = if rem.len() < 56 { 64 } else { 128 };
    tail[total_len - 8..total_len].copy_from_slice(&bit_len.to_be_bytes());
    let mut first = [0u8; 64];
    first.copy_from_slice(&tail[..64]);
    sha256_compress(&mut state, &first);
    if total_len == 128 {
        let mut second = [0u8; 64];
        second.copy_from_slice(&tail[64..128]);
        sha256_compress(&mut state, &second);
    }
    let mut out = [0u8; 32];
    let mut w_idx = 0usize;
    while w_idx < 8 {
        out[w_idx * 4..(w_idx + 1) * 4].copy_from_slice(&state[w_idx].to_be_bytes());
        w_idx += 1;
    }
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256_bytes(data))
}

pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0usize;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    let unpadded = match clean.iter().rposition(|&b| b != b'=') {
        Some(pos) => &clean[..=pos],
        None => return Some(Vec::new()),
    };
    if unpadded.contains(&b'=') || unpadded.len() % 4 == 1 {
        return None;
    }
    let val = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity((unpadded.len() * 3) / 4);
    let mut i = 0usize;
    while i + 4 <= unpadded.len() {
        let n = (val(unpadded[i])? << 18)
            | (val(unpadded[i + 1])? << 12)
            | (val(unpadded[i + 2])? << 6)
            | val(unpadded[i + 3])?;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
        i += 4;
    }
    let rem = unpadded.len() - i;
    if rem == 2 {
        let n = (val(unpadded[i])? << 18) | (val(unpadded[i + 1])? << 12);
        out.push(((n >> 16) & 0xff) as u8);
    } else if rem == 3 {
        let n = (val(unpadded[i])? << 18)
            | (val(unpadded[i + 1])? << 12)
            | (val(unpadded[i + 2])? << 6);
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
    }
    Some(out)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + (doe as i64) - 719468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

pub fn parse_rfc3339_unix(raw: &str) -> Option<i64> {
    let s = raw.trim().as_bytes();
    if s.len() < 19 || s[4] != b'-' || s[7] != b'-' || s[13] != b':' || s[16] != b':' {
        return None;
    }
    if !matches!(s[10], b'T' | b't' | b' ') {
        return None;
    }
    let parse_u32 = |slice: &[u8]| -> Option<u32> {
        if slice.is_empty() || !slice.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        core::str::from_utf8(slice).ok()?.parse::<u32>().ok()
    };
    let year = parse_u32(&s[0..4])? as i64;
    let month = parse_u32(&s[5..7])?;
    let day = parse_u32(&s[8..10])?;
    let hour = parse_u32(&s[11..13])?;
    let min = parse_u32(&s[14..16])?;
    let sec = parse_u32(&s[17..19])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    let mut pos = 19usize;
    if pos < s.len() && s[pos] == b'.' {
        pos += 1;
        let frac_start = pos;
        while pos < s.len() && s[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == frac_start {
            return None;
        }
    }
    let tz = &s[pos..];
    let offset_secs: i64 = if tz.is_empty() || tz == b"Z" || tz == b"z" {
        0
    } else if matches!(tz[0], b'+' | b'-') {
        let sign = if tz[0] == b'-' { -1i64 } else { 1i64 };
        let (tz_h, tz_m) = if tz.len() == 6 && tz[3] == b':' {
            (parse_u32(&tz[1..3])?, parse_u32(&tz[4..6])?)
        } else if tz.len() == 5 {
            (parse_u32(&tz[1..3])?, parse_u32(&tz[3..5])?)
        } else {
            return None;
        };
        if tz_h > 23 || tz_m > 59 {
            return None;
        }
        sign * ((tz_h as i64) * 3600 + (tz_m as i64) * 60)
    } else {
        return None;
    };
    let days = days_from_civil(year, month, day);
    Some(
        days * 86_400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec.min(59) as i64)
            - offset_secs,
    )
}

pub fn format_rfc3339_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let rem = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}
