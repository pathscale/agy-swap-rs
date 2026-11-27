//! OAuth 2.0 token parsing, redaction, refresh exchange, userinfo verification, and login flows.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use eko::path::Path;
use nago_rustls::rustls::crypto::SecureRandom;
use serde_json::{Map, Value};

use crate::http::{
    base64_decode_any, base64_encode_std, base64_encode_url_nopad, format_rfc3339_utc,
    parse_rfc3339_unix, url_encode_component, HttpClient, HttpResponse,
};
use crate::isolate::{spawn_interactive_tty, write_keyring_bypass_marker_2036};
use crate::model::{clean_text, normalize_email};
use crate::paths::{join_path, sha256_bytes, sha256_hex, wall_unix_ns, wall_unix_secs, Paths};
use crate::store::ensure_private_dir;
use crate::vault::keychain_get;
use crate::{Error, Result};

/// Prefix used by Go keyring and Antigravity vault token strings.
pub const KEYRING_PREFIX: &str = "go-keyring-base64:";
/// Google OAuth 2.0 token exchange endpoint.
pub const DEFAULT_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Google OAuth 2.0 interactive authorization endpoint.
pub const DEFAULT_OAUTH_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Google OAuth 2.0 verified userinfo endpoint.
pub const DEFAULT_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v1/userinfo";
/// Default OAuth scopes requested for Cloud Code Assist and identity lookup.
pub const DEFAULT_OAUTH_SCOPE: &str =
    "https://www.googleapis.com/auth/cloud-platform openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
/// Maximum accepted serialized OAuth token size in bytes.
pub const MAX_TOKEN_BYTES: usize = 1024 * 1024;
/// Safety window in seconds before token expiry when proactive refresh triggers.
pub const TOKEN_EXPIRY_BUFFER_SECS: i64 = 60;

/// Parsed OAuth credential bundle normalized to the Antigravity token envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBundle {
    pub raw_json: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_unix: Option<i64>,
    pub email_hint: Option<String>,
}

impl TokenBundle {
    /// Parse either a `go-keyring-base64:...` string or raw JSON (nested `{"token": ...}` or flat).
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > MAX_TOKEN_BYTES {
            return Err(Error::InvalidInput(
                "token exceeds maximum size limit".to_string(),
            ));
        }
        let mut envelope = decode_token_envelope(raw)?;
        let has_auth_method = envelope
            .get("auth_method")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());
        if !has_auth_method {
            envelope.insert(
                "auth_method".to_string(),
                Value::String("consumer".to_string()),
            );
        }
        let inner = envelope
            .get("token")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::InvalidInput("invalid OAuth token structure".to_string()))?;
        let access_token = get_str(inner, "access_token")
            .unwrap_or("")
            .trim()
            .to_string();
        let refresh_token = get_str(inner, "refresh_token")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        if access_token.is_empty() && refresh_token.is_none() {
            return Err(Error::InvalidInput(
                "OAuth token JSON is missing access_token".to_string(),
            ));
        }
        let expires_at_unix = extract_expiry_unix(inner).or_else(|| extract_expiry_unix(&envelope));
        let email_hint = extract_email_hint_from_envelope(&envelope);
        let raw_json = serde_json::to_string(&Value::Object(envelope))?;
        Ok(Self {
            raw_json,
            access_token,
            refresh_token,
            expires_at_unix,
            email_hint,
        })
    }

    /// Report whether the access token is missing or expires within `TOKEN_EXPIRY_BUFFER_SECS`.
    #[must_use]
    pub fn is_expired(&self, now_unix: i64) -> bool {
        if self.access_token.trim().is_empty() {
            return true;
        }
        match self.expires_at_unix {
            Some(exp) => exp <= now_unix.saturating_add(TOKEN_EXPIRY_BUFFER_SECS),
            None => false,
        }
    }

    /// Encode the normalized token JSON with the `go-keyring-base64:` prefix.
    #[must_use]
    pub fn to_keyring_string(&self) -> String {
        format!(
            "{KEYRING_PREFIX}{}",
            base64_encode_std(self.raw_json.as_bytes())
        )
    }

    /// Render flat `oauth_creds.json` representation used by Gemini and Antigravity surfaces.
    pub fn to_flat_credentials_json(&self) -> Result<String> {
        let parsed: Value = serde_json::from_str(&self.raw_json)?;
        let inner = parsed
            .get("token")
            .and_then(Value::as_object)
            .or_else(|| parsed.as_object())
            .ok_or_else(|| Error::InvalidInput("invalid token JSON object".to_string()))?;
        let mut creds = Map::new();
        creds.insert(
            "access_token".to_string(),
            Value::String(self.access_token.clone()),
        );
        creds.insert(
            "refresh_token".to_string(),
            Value::String(self.refresh_token.clone().unwrap_or_default()),
        );
        let scope = get_str(inner, "scope")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(DEFAULT_OAUTH_SCOPE);
        creds.insert("scope".to_string(), Value::String(scope.to_string()));
        let token_type = get_str(inner, "token_type")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("Bearer");
        creds.insert(
            "token_type".to_string(),
            Value::String(token_type.to_string()),
        );
        creds.insert(
            "id_token".to_string(),
            Value::String(get_str(inner, "id_token").unwrap_or("").to_string()),
        );
        let expiry_ms = self
            .expires_at_unix
            .map(|secs| secs.saturating_mul(1000))
            .or_else(|| value_i64(inner.get("expiry_date")))
            .unwrap_or(0);
        creds.insert("expiry_date".to_string(), Value::from(expiry_ms));
        Ok(serde_json::to_string_pretty(&Value::Object(creds))?)
    }
}

fn get_str<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn value_i64(val: Option<&Value>) -> Option<i64> {
    let v = val?;
    if let Some(i) = v.as_i64() {
        return Some(i);
    }
    if let Some(u) = v.as_u64() {
        return i64::try_from(u).ok();
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() && f >= (i64::MIN as f64) && f <= (i64::MAX as f64) {
            let i = f as i64;
            if (i as f64) == f {
                return Some(i);
            }
        }
    }
    None
}

fn value_f64(val: Option<&Value>) -> Option<f64> {
    let v = val?;
    if let Some(f) = v.as_f64() {
        if f.is_finite() {
            return Some(f);
        }
    }
    if let Some(i) = v.as_i64() {
        return Some(i as f64);
    }
    None
}

fn decode_token_envelope(raw: &str) -> Result<Map<String, Value>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidInput("empty OAuth token".to_string()));
    }
    let decoded_bytes = if let Some(b64) = trimmed.strip_prefix(KEYRING_PREFIX) {
        base64_decode_any(b64.trim()).ok_or_else(|| {
            Error::InvalidInput("invalid base64 payload in go-keyring-base64 token".to_string())
        })?
    } else {
        trimmed.as_bytes().to_vec()
    };
    let parsed: Value = serde_json::from_slice(&decoded_bytes)
        .map_err(|e| Error::InvalidInput(format!("invalid OAuth token JSON - {e}")))?;
    let Value::Object(obj) = parsed else {
        return Err(Error::InvalidInput(
            "OAuth token JSON must be an object".to_string(),
        ));
    };
    if obj.get("token").and_then(Value::as_object).is_some() {
        Ok(obj)
    } else {
        let mut wrapper = Map::new();
        wrapper.insert("token".to_string(), Value::Object(obj));
        Ok(wrapper)
    }
}

fn extract_expiry_unix(map: &Map<String, Value>) -> Option<i64> {
    if let Some(expiry_str) = get_str(map, "expiry") {
        if !expiry_str.trim().is_empty() {
            if let Some(ts) = parse_rfc3339_unix(expiry_str) {
                return Some(ts);
            }
        }
    }
    if let Some(raw_date) = value_i64(map.get("expiry_date")) {
        if raw_date > 0 {
            return Some(if raw_date >= 100_000_000_000 {
                raw_date / 1000
            } else {
                raw_date
            });
        }
    }
    if let Some(exp_at) = map.get("expires_at") {
        if let Some(s) = exp_at.as_str() {
            if let Some(ts) = parse_rfc3339_unix(s) {
                return Some(ts);
            }
        } else if let Some(n) = value_i64(Some(exp_at)) {
            if n > 0 {
                return Some(if n >= 100_000_000_000 { n / 1000 } else { n });
            }
        }
    }
    None
}

fn decode_jwt_claims(jwt: &str) -> Option<Map<String, Value>> {
    let trimmed = jwt.trim();
    let mut parts = trimmed.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _sig = parts.next()?;
    if parts.next().is_some() || payload.is_empty() {
        return None;
    }
    let bytes = base64_decode_any(payload)?;
    match serde_json::from_slice::<Value>(&bytes).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn extract_email_hint_from_envelope(envelope: &Map<String, Value>) -> Option<String> {
    let inner = envelope.get("token").and_then(Value::as_object);
    let id_token = inner
        .and_then(|m| get_str(m, "id_token"))
        .filter(|s| !s.trim().is_empty())
        .or_else(|| get_str(envelope, "id_token").filter(|s| !s.trim().is_empty()));
    if let Some(jwt) = id_token {
        let claims = decode_jwt_claims(jwt)?;
        let iss = get_str(&claims, "iss")?;
        let iss_ok = iss == "accounts.google.com" || iss == "https://accounts.google.com";
        let verified = claims.get("email_verified").and_then(Value::as_bool) == Some(true);
        if !iss_ok || !verified {
            return None;
        }
        return get_str(&claims, "email").and_then(normalize_email);
    }
    inner
        .and_then(|m| get_str(m, "email"))
        .or_else(|| get_str(envelope, "email"))
        .and_then(normalize_email)
}

/// Extract a local unverified email hint from a JWT `id_token` or token JSON envelope.
#[must_use]
pub fn extract_email_hint(raw_token: &str) -> Option<String> {
    let envelope = decode_token_envelope(raw_token).ok()?;
    extract_email_hint_from_envelope(&envelope)
}

/// Report whether `raw_token` either carries no email hint or matches `email`.
#[must_use]
pub fn token_matches_email(raw_token: &str, email: &str) -> bool {
    let Some(norm_target) = normalize_email(email) else {
        return false;
    };
    match extract_email_hint(raw_token) {
        Some(claimed) => claimed == norm_target,
        None => true,
    }
}

/// Report whether a raw token string is missing an access token or expired at `now_unix`.
#[must_use]
pub fn is_token_expired(raw_token: &str, now_unix: i64) -> bool {
    match TokenBundle::parse(raw_token) {
        Ok(bundle) => bundle.is_expired(now_unix),
        Err(_) => true,
    }
}

fn is_secret_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'+' | b'=')
}

fn is_jwt_segment_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=')
}

fn match_jwt_len(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"eyJ") {
        return None;
    }
    let mut i = 0usize;
    while i < bytes.len() && is_jwt_segment_byte(bytes[i]) {
        i += 1;
    }
    if i < 4 || i >= bytes.len() || bytes[i] != b'.' {
        return None;
    }
    i += 1;
    let p2_start = i;
    if !bytes[p2_start..].starts_with(b"eyJ") {
        return None;
    }
    while i < bytes.len() && is_jwt_segment_byte(bytes[i]) {
        i += 1;
    }
    if i - p2_start < 4 || i >= bytes.len() || bytes[i] != b'.' {
        return None;
    }
    i += 1;
    let p3_start = i;
    while i < bytes.len() && is_jwt_segment_byte(bytes[i]) {
        i += 1;
    }
    if i <= p3_start {
        return None;
    }
    Some(i)
}

fn match_json_secret_field(rest: &str) -> Option<(usize, usize)> {
    const KEYS: [&str; 6] = [
        "\"access_token\"",
        "\"refresh_token\"",
        "\"id_token\"",
        "\"client_secret\"",
        "\"token_data\"",
        "\"passphrase\"",
    ];
    let bytes = rest.as_bytes();
    for key in KEYS {
        if bytes.len() > key.len() && bytes[..key.len()].eq_ignore_ascii_case(key.as_bytes()) {
            let mut idx = key.len();
            while idx < bytes.len() && matches!(bytes[idx], b' ' | b'\t' | b'\r' | b'\n') {
                idx += 1;
            }
            if idx >= bytes.len() || bytes[idx] != b':' {
                continue;
            }
            idx += 1;
            while idx < bytes.len() && matches!(bytes[idx], b' ' | b'\t' | b'\r' | b'\n') {
                idx += 1;
            }
            if idx >= bytes.len() || bytes[idx] != b'"' {
                continue;
            }
            let val_quote_open = idx + 1;
            let mut end = val_quote_open;
            let mut escaped = false;
            while end < bytes.len() {
                let b = bytes[end];
                if escaped {
                    escaped = false;
                    end += 1;
                    continue;
                }
                if b == b'\\' {
                    escaped = true;
                    end += 1;
                    continue;
                }
                if b == b'"' {
                    return Some((val_quote_open, end));
                }
                end += 1;
            }
        }
    }
    None
}

fn match_query_secret_param(rest: &str, prev_byte: Option<u8>) -> Option<(usize, usize)> {
    if let Some(p) = prev_byte {
        if p.is_ascii_alphanumeric() || p == b'_' || p == b'-' {
            return None;
        }
    }
    const PARAMS: [&str; 5] = [
        "access_token=",
        "refresh_token=",
        "client_secret=",
        "id_token=",
        "code=",
    ];
    let bytes = rest.as_bytes();
    for param in PARAMS {
        if bytes.len() > param.len() && bytes[..param.len()].eq_ignore_ascii_case(param.as_bytes())
        {
            let start = param.len();
            let mut end = start;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(
                    bytes[end],
                    b'&' | b'"' | b'\'' | b'#' | b'>' | b')' | b']' | b'}'
                )
            {
                end += 1;
            }
            if end > start {
                return Some((start, end));
            }
        }
    }
    None
}

/// Redact OAuth access tokens, refresh tokens, client secrets, keyring blobs, and JWTs from text.
#[must_use]
pub fn redact_secrets(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let rest = &text[i..];
        let rest_bytes = &bytes[i..];
        let prev_byte = if i > 0 { Some(bytes[i - 1]) } else { None };

        if let Some((val_start, val_end)) = match_json_secret_field(rest) {
            out.push_str(&rest[..val_start]);
            out.push_str("[REDACTED]");
            out.push('"');
            i += val_end + 1;
            continue;
        }
        if let Some((val_start, val_end)) = match_query_secret_param(rest, prev_byte) {
            out.push_str(&rest[..val_start]);
            out.push_str("[REDACTED]");
            i += val_end;
            continue;
        }
        if rest_bytes.len() > KEYRING_PREFIX.len() && rest.starts_with(KEYRING_PREFIX) {
            let mut len = KEYRING_PREFIX.len();
            while len < rest_bytes.len() && is_secret_token_byte(rest_bytes[len]) {
                len += 1;
            }
            out.push_str("go-keyring-base64:[REDACTED]");
            i += len;
            continue;
        }
        if rest_bytes.len() > 7
            && rest_bytes[..7].eq_ignore_ascii_case(b"bearer ")
            && !prev_byte.is_some_and(|b| b.is_ascii_alphanumeric())
        {
            let mut len = 7usize;
            while len < rest_bytes.len() && rest_bytes[len] == b' ' {
                len += 1;
            }
            let tok_start = len;
            while len < rest_bytes.len() && is_secret_token_byte(rest_bytes[len]) {
                len += 1;
            }
            if len > tok_start {
                out.push_str("Bearer [REDACTED]");
                i += len;
                continue;
            }
        }
        let mut matched_prefix = false;
        for (prefix, replacement) in [
            ("ya29.", "ya29.[REDACTED]"),
            ("1//", "1//[REDACTED]"),
            ("GOCSPX-", "GOCSPX-[REDACTED]"),
        ] {
            if rest_bytes.len() > prefix.len()
                && rest.starts_with(prefix)
                && !prev_byte.is_some_and(|b| b.is_ascii_alphanumeric())
            {
                let mut len = prefix.len();
                while len < rest_bytes.len() && is_secret_token_byte(rest_bytes[len]) {
                    len += 1;
                }
                if len > prefix.len() {
                    out.push_str(replacement);
                    i += len;
                    matched_prefix = true;
                    break;
                }
            }
        }
        if matched_prefix {
            continue;
        }
        if !prev_byte.is_some_and(|b| b.is_ascii_alphanumeric()) {
            if let Some(jwt_len) = match_jwt_len(rest_bytes) {
                out.push_str("[REDACTED_JWT]");
                i += jwt_len;
                continue;
            }
        }
        if let Some(ch) = rest.chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

const PRIMARY_ID_TAG: &str = "bf00c418024ba6bf";
const PRIMARY_SECRET_TAG: &str = "1d2f041093fd95aa";
const SECONDARY_ID_TAG: &str = "69dee430c4e956f6";
const SECONDARY_SECRET_TAG: &str = "a2ddedc84850a9c4";

fn push_unique_str(list: &mut Vec<String>, candidate: &str) {
    if !list.iter().any(|existing| existing == candidate) {
        list.push(candidate.to_string());
    }
}

fn scan_chunk_for_oauth_params(buf: &[u8], ids: &mut Vec<String>, secrets: &mut Vec<String>) {
    const ID_SUFFIX: &[u8] = b".apps.googleusercontent.com";
    const SEC_PREFIX: &[u8] = b"GOCSPX-";
    let mut i = 0usize;
    while i < buf.len() {
        if i + 35 <= buf.len() && &buf[i..i + SEC_PREFIX.len()] == SEC_PREFIX {
            let tail = &buf[i + SEC_PREFIX.len()..i + 35];
            if tail
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                if let Ok(s) = core::str::from_utf8(&buf[i..i + 35]) {
                    push_unique_str(secrets, s);
                }
                i += 35;
                continue;
            }
        }
        if buf[i].is_ascii_digit() && (i == 0 || !buf[i - 1].is_ascii_digit()) {
            let mut d_end = i;
            while d_end < buf.len() && d_end - i < 16 && buf[d_end].is_ascii_digit() {
                d_end += 1;
            }
            let d_len = d_end - i;
            let rest_needed = 1 + 32 + ID_SUFFIX.len();
            if (10..=15).contains(&d_len) && d_end + rest_needed <= buf.len() && buf[d_end] == b'-'
            {
                let slug = &buf[d_end + 1..d_end + 33];
                let suf = &buf[d_end + 33..d_end + rest_needed];
                if suf == ID_SUFFIX
                    && slug
                        .iter()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                {
                    if let Ok(id_str) = core::str::from_utf8(&buf[i..d_end + rest_needed]) {
                        push_unique_str(ids, id_str);
                    }
                    i = d_end + rest_needed;
                    continue;
                }
            }
        }
        i += 1;
    }
}

fn discover_installed_agy_oauth_clients() -> (Vec<String>, Vec<String>) {
    let mut ids = Vec::new();
    let mut secrets = Vec::new();
    let agy_path = Paths::detect()
        .ok()
        .and_then(|p| resolve_unwrapped_agy_binary(&p))
        .or_else(|| {
            ["/opt/homebrew/bin/agy", "/usr/local/bin/agy"]
                .into_iter()
                .find(|c| is_executable_file(c))
                .map(ToString::to_string)
        });
    let Some(bin_path) = agy_path else {
        return (ids, secrets);
    };
    let Ok(mut file) = eko::file::File::open(&bin_path) else {
        return (ids, secrets);
    };
    const CHUNK: usize = 65_536;
    const OVERLAP: usize = 128;
    let mut window = vec![0u8; OVERLAP + CHUNK];
    let mut carry = 0usize;
    while let Ok(n) = file.read(&mut window[carry..carry + CHUNK]) {
        if n == 0 {
            break;
        }
        let total = carry + n;
        scan_chunk_for_oauth_params(&window[..total], &mut ids, &mut secrets);
        if total > OVERLAP {
            window.copy_within(total - OVERLAP..total, 0);
            carry = OVERLAP;
        } else {
            carry = total;
        }
    }
    (ids, secrets)
}

fn tag16(s: &str) -> String {
    let full = sha256_hex(s.as_bytes());
    full[..16].to_string()
}

fn match_secret_for_id(client_id: &str, secrets: &[String]) -> Option<String> {
    let id_tag = tag16(client_id);
    if id_tag == PRIMARY_ID_TAG {
        if let Some(sec) = secrets.iter().find(|s| tag16(s) == PRIMARY_SECRET_TAG) {
            return Some(sec.clone());
        }
    } else if id_tag == SECONDARY_ID_TAG {
        if let Some(sec) = secrets.iter().find(|s| tag16(s) == SECONDARY_SECRET_TAG) {
            return Some(sec.clone());
        }
    }
    secrets.first().cloned()
}

fn select_oauth_client(envelope: &Map<String, Value>) -> Result<(String, String)> {
    if let Some(env_id) = eko::env::var("AGY_SWAP_OAUTH_CLIENT_ID")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if let Some(env_secret) = eko::env::var("AGY_SWAP_OAUTH_CLIENT_SECRET")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return Ok((env_id, env_secret));
        }
        let (_, secrets) = discover_installed_agy_oauth_clients();
        let matched = match_secret_for_id(&env_id, &secrets).unwrap_or_default();
        return Ok((env_id, matched));
    }

    let inner = envelope.get("token").and_then(Value::as_object);
    if let Some(cid) = inner
        .and_then(|m| get_str(m, "client_id"))
        .or_else(|| get_str(envelope, "client_id"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(csec) = inner
            .and_then(|m| get_str(m, "client_secret"))
            .or_else(|| get_str(envelope, "client_secret"))
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok((cid.to_string(), csec.to_string()));
        }
        let (_, secrets) = discover_installed_agy_oauth_clients();
        if let Some(sec) = match_secret_for_id(cid, &secrets) {
            return Ok((cid.to_string(), sec));
        }
    }

    let (ids, secrets) = discover_installed_agy_oauth_clients();
    let id_token = inner
        .and_then(|m| get_str(m, "id_token"))
        .filter(|s| !s.trim().is_empty())
        .or_else(|| get_str(envelope, "id_token").filter(|s| !s.trim().is_empty()));
    if let Some(claims) = id_token.and_then(decode_jwt_claims) {
        match claims.get("aud") {
            Some(Value::String(aud)) => {
                if let Some(secret) = match_secret_for_id(aud, &secrets) {
                    return Ok((aud.clone(), secret));
                }
            }
            Some(Value::Array(items)) => {
                for item in items {
                    if let Some(aud) = item.as_str() {
                        if let Some(secret) = match_secret_for_id(aud, &secrets) {
                            return Ok((aud.to_string(), secret));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(primary_id) = ids.iter().find(|id| tag16(id) == PRIMARY_ID_TAG) {
        if let Some(sec) = match_secret_for_id(primary_id, &secrets) {
            return Ok((primary_id.clone(), sec));
        }
    }
    if let (Some(first_id), Some(first_sec)) = (ids.first(), secrets.first()) {
        return Ok((first_id.clone(), first_sec.clone()));
    }
    Err(Error::NotFound(
        "Antigravity CLI ('agy') not found for OAuth client discovery; install 'agy' or set AGY_SWAP_OAUTH_CLIENT_ID and AGY_SWAP_OAUTH_CLIENT_SECRET"
            .to_string(),
    ))
}

fn oauth_token_url() -> String {
    eko::env::var("AGY_SWAP_OAUTH_TOKEN_URL")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_OAUTH_TOKEN_URL.to_string())
}

fn userinfo_url() -> String {
    eko::env::var("AGY_SWAP_USERINFO_URL")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_USERINFO_URL.to_string())
}

fn oauth_auth_url() -> String {
    eko::env::var("AGY_SWAP_OAUTH_AUTH_URL")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_OAUTH_AUTH_URL.to_string())
}

pub(crate) fn parse_retry_after(resp: &HttpResponse) -> Option<u64> {
    resp.header("retry-after")
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
}

/// Exchange a refresh token for a fresh access token and return the updated `TokenBundle`.
pub fn refresh_access_token(http: &HttpClient, raw_token: &str) -> Result<TokenBundle> {
    let mut envelope = decode_token_envelope(raw_token)?;
    let (client_id, client_secret) = select_oauth_client(&envelope)?;
    let refresh_tok = envelope
        .get("token")
        .and_then(Value::as_object)
        .and_then(|m| get_str(m, "refresh_token"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| Error::Auth("refresh token is unavailable".to_string()))?;
    let form = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("refresh_token", refresh_tok.as_str()),
        ("grant_type", "refresh_token"),
    ];
    let resp = http.post_form(&oauth_token_url(), &form, &[])?;
    if !resp.is_success() {
        if resp.status == 429 {
            return Err(Error::RateLimited {
                retry_after_secs: parse_retry_after(&resp).unwrap_or(20),
            });
        }
        if resp.status == 400 || resp.status == 401 {
            return Err(Error::Auth(format!(
                "OAuth refresh failed (HTTP {})",
                resp.status
            )));
        }
        return Err(Error::Network(format!(
            "OAuth refresh failed (HTTP {})",
            resp.status
        )));
    }
    let body: Value = resp
        .json()
        .map_err(|_| Error::Auth("OAuth refresh returned invalid JSON".to_string()))?;
    let Some(result_obj) = body.as_object() else {
        return Err(Error::Auth(
            "OAuth refresh returned non-object JSON".to_string(),
        ));
    };
    let new_access = get_str(result_obj, "access_token")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Auth("OAuth refresh returned no access token".to_string()))?;
    let inner = envelope
        .get_mut("token")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::InvalidInput("invalid OAuth token envelope".to_string()))?;
    inner.insert(
        "access_token".to_string(),
        Value::String(new_access.to_string()),
    );
    for key in ["refresh_token", "id_token", "scope", "token_type"] {
        if let Some(val) = get_str(result_obj, key)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            inner.insert(key.to_string(), Value::String(val.to_string()));
        }
    }
    if let Some(secs) = value_f64(result_obj.get("expires_in")) {
        if secs > 0.0 && secs <= (365.0 * 86_400.0) {
            let expiry_unix = wall_unix_secs().saturating_add(secs as i64);
            inner.insert(
                "expiry".to_string(),
                Value::String(format_rfc3339_utc(expiry_unix)),
            );
            inner.insert(
                "expiry_date".to_string(),
                Value::from(expiry_unix.saturating_mul(1000)),
            );
        } else {
            inner.remove("expiry");
            inner.remove("expiry_date");
        }
    } else {
        inner.remove("expiry");
        inner.remove("expiry_date");
    }
    let updated_raw = serde_json::to_string(&Value::Object(envelope))?;
    TokenBundle::parse(&updated_raw)
}

/// Return a valid `TokenBundle` and whether it was refreshed over the network.
pub fn ensure_valid_token(
    http: &HttpClient,
    raw_token: &str,
    now_unix: i64,
) -> Result<(TokenBundle, bool)> {
    let bundle = TokenBundle::parse(raw_token)?;
    if !bundle.is_expired(now_unix) {
        return Ok((bundle, false));
    }
    let refreshed = refresh_access_token(http, raw_token)?;
    Ok((refreshed, true))
}

/// Query Google's `userinfo` endpoint and return `(verified_email, display_name)`.
pub fn fetch_verified_email(http: &HttpClient, access_token: &str) -> Result<(String, String)> {
    let trimmed = access_token.trim();
    if trimmed.is_empty() {
        return Err(Error::Auth("access token is empty".to_string()));
    }
    let auth = format!("Bearer {trimmed}");
    let resp = http.get(&userinfo_url(), &[("Authorization", auth.as_str())])?;
    if !resp.is_success() {
        if resp.status == 429 {
            return Err(Error::RateLimited {
                retry_after_secs: parse_retry_after(&resp).unwrap_or(20),
            });
        }
        if resp.status == 401 || resp.status == 403 {
            return Err(Error::Auth(format!(
                "Google userinfo rejected access token (HTTP {})",
                resp.status
            )));
        }
        return Err(Error::Network(format!(
            "Google userinfo failed (HTTP {})",
            resp.status
        )));
    }
    let info: Value = resp
        .json()
        .map_err(|_| Error::Auth("Google userinfo returned invalid JSON".to_string()))?;
    let Some(obj) = info.as_object() else {
        return Err(Error::Auth(
            "Google userinfo returned non-object JSON".to_string(),
        ));
    };
    let verified = obj.get("email_verified").and_then(Value::as_bool) == Some(true)
        || obj.get("verified_email").and_then(Value::as_bool) == Some(true);
    let email = get_str(obj, "email")
        .and_then(normalize_email)
        .ok_or_else(|| {
            Error::Auth("Google userinfo returned no valid account email".to_string())
        })?;
    if !verified {
        return Err(Error::Auth(
            "Google userinfo reported an unverified account email".to_string(),
        ));
    }
    let name = get_str(obj, "name")
        .map(clean_text)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Google User".to_string());
    Ok((email, name))
}

fn is_executable_file(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }
    match eko::file::metadata(trimmed) {
        Ok(meta) => !meta.is_dir() && (meta.mode() & 0o111) != 0,
        Err(_) => false,
    }
}

fn lookup_in_path(name: &str) -> Option<String> {
    if name.contains('/') {
        return is_executable_file(name).then(|| name.to_string());
    }
    let path_var = eko::env::var("PATH")?;
    for dir in path_var.split(':') {
        let dir_trim = dir.trim();
        if dir_trim.is_empty() {
            continue;
        }
        let candidate = join_path(dir_trim, name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Locate the Antigravity CLI (`agy`) binary across env overrides, `PATH`, and standard paths.
#[must_use]
pub fn resolve_agy_executable(paths: &Paths) -> Option<String> {
    if let Some(env_bin) = eko::env::var("AGY_SWAP_AGY_BIN")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if let Some(found) = lookup_in_path(&env_bin) {
            return Some(found);
        }
    }
    if let Some(found) = lookup_in_path("agy") {
        return Some(found);
    }
    let mut candidates = Vec::new();
    if !paths.home.trim().is_empty() {
        candidates.push(join_path(&paths.home, ".local/bin/agy"));
        candidates.push(join_path(&paths.home, ".local/libexec/agy"));
        candidates.push(join_path(&paths.home, ".gemini/bin/.agy.real"));
        candidates.push(join_path(&paths.home, ".gemini/bin/agy"));
        candidates.push(join_path(&paths.home, "bin/agy"));
    }
    candidates.push("/opt/homebrew/bin/agy".to_string());
    candidates.push("/usr/local/bin/agy".to_string());
    candidates.into_iter().find(|c| is_executable_file(c))
}

fn read_session_token_candidates(paths: &Paths) -> Option<TokenBundle> {
    let files = [
        paths.agy_oauth_file.clone(),
        paths.ide_oauth_file(),
        paths.jetski_oauth_file(),
        paths.oauth_creds_file(),
    ];
    let mut best: Option<TokenBundle> = None;
    for file in files {
        let Ok(bytes) = eko::file::read(&file) else {
            continue;
        };
        let Ok(text) = core::str::from_utf8(&bytes) else {
            continue;
        };
        let Ok(bundle) = TokenBundle::parse(text) else {
            continue;
        };
        if bundle.access_token.is_empty() {
            continue;
        }
        match &best {
            None => best = Some(bundle),
            Some(prev) => {
                if let (Some(p_exp), Some(c_exp)) = (prev.expires_at_unix, bundle.expires_at_unix) {
                    if c_exp > p_exp && prev.refresh_token == bundle.refresh_token {
                        best = Some(bundle);
                    }
                }
            }
        }
    }
    best
}

const GEMINI_KEYRING_SERVICE: &str = "gemini";
const GEMINI_KEYRING_ACCOUNT: &str = "antigravity";

fn symlink_best_effort(target: &str, link_path: &str) {
    unsafe extern "C" {
        fn symlink(
            target: *const eko::libc::c_char,
            linkpath: *const eko::libc::c_char,
        ) -> eko::libc::c_int;
    }
    if target.is_empty() || link_path.is_empty() || !eko::file::exists(target) {
        return;
    }
    if eko::file::symlink_metadata(link_path).is_ok() {
        return;
    }
    let src_c = Path::new(target).as_c();
    let dst_c = Path::new(link_path).as_c();
    unsafe {
        let _ = symlink(src_c.as_ptr().cast(), dst_c.as_ptr().cast());
    }
}

fn resolve_unwrapped_agy_binary(paths: &Paths) -> Option<String> {
    if let Some(env_bin) = eko::env::var("AGY_SWAP_AGY_BIN")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if let Some(found) = lookup_in_path(&env_bin) {
            return Some(found);
        }
    }
    if !paths.home.trim().is_empty() {
        for rel in [
            ".local/libexec/agy",
            ".gemini/bin/.agy.real",
            ".local/bin/.agy.real",
        ] {
            let cand = join_path(&paths.home, rel);
            if is_executable_file(&cand) {
                return Some(cand);
            }
        }
    }
    resolve_agy_executable(paths)
}

fn allow_keyring_import_fallback(paths: &Paths) -> bool {
    if let Some(mode) = eko::env::var("AGY_SWAP_SESSION_STORE") {
        if matches!(mode.trim().to_ascii_lowercase().as_str(), "keychain" | "os") {
            return true;
        }
    }
    if let Some(mirror) = eko::env::var("AGY_SWAP_MIRROR_OS_KEYRING") {
        match mirror.trim().to_ascii_lowercase().as_str() {
            "1" | "true" => return true,
            "0" | "false" => return false,
            _ => {}
        }
    }
    if eko::env::var("AGY_SWAP_CONFIG_DIR").is_some()
        || eko::env::var("AGY_SWAP_OFFLINE").as_deref() == Some("1")
    {
        return false;
    }
    !paths.home.is_empty()
        && !paths.home.contains("/tmp/")
        && !paths.home.contains("/var/folders/")
        && !paths.home.contains(".tmp")
}

/// Import the currently active OAuth session from `~/.gemini` surface files or OS keyring.
pub fn import_current_session(
    paths: &Paths,
    session: &crate::SessionManager,
) -> Result<TokenBundle> {
    if let Some(raw) = session.current_token() {
        if let Ok(bundle) = TokenBundle::parse(&raw) {
            if !bundle.access_token.trim().is_empty() {
                return Ok(bundle);
            }
        }
    }
    if let Some(bundle) = read_session_token_candidates(paths) {
        return Ok(bundle);
    }
    if allow_keyring_import_fallback(paths) {
        if let Ok(Some(raw)) = keychain_get(GEMINI_KEYRING_SERVICE, GEMINI_KEYRING_ACCOUNT) {
            if let Ok(bundle) = TokenBundle::parse(&raw) {
                if !bundle.access_token.trim().is_empty() {
                    return Ok(bundle);
                }
            }
        }
    }
    Err(Error::NotFound(
        "no active Antigravity OAuth session found in ~/.gemini or OS keyring".to_string(),
    ))
}

/// Launch `agy` interactively on the real TTY inside an isolated staging `HOME`, never touching `paths.gemini_dir`.
pub fn login_via_isolated_agy_tty(paths: &Paths) -> Result<TokenBundle> {
    let Some(agy_bin) = resolve_unwrapped_agy_binary(paths) else {
        return Err(Error::NotFound(
            "Antigravity CLI ('agy') was not found; run 'agy-swap-rs install-agy' or use browser login"
                .to_string(),
        ));
    };
    let pid = unsafe { eko::libc::getpid() };
    let ns = wall_unix_ns().unsigned_abs();
    let staging_root = join_path(&paths.config_dir, "login-staging");
    let staging_home = join_path(&staging_root, &format!("{pid}-{ns}"));
    let staging_gemini = join_path(&staging_home, ".gemini");
    let staging_cli_dir = join_path(&staging_gemini, "antigravity-cli");
    let staging_ide_dir = join_path(&staging_gemini, "antigravity");

    ensure_private_dir(&paths.config_dir)?;
    ensure_private_dir(&staging_root)?;
    ensure_private_dir(&staging_home)?;
    ensure_private_dir(&staging_gemini)?;
    ensure_private_dir(&staging_cli_dir)?;
    ensure_private_dir(&staging_ide_dir)?;

    if !paths.home.trim().is_empty() {
        for entry in [
            ".cargo",
            ".rustup",
            ".gitconfig",
            ".ssh",
            ".config",
            ".local",
            ".claude",
            ".bun",
            "Library",
        ] {
            symlink_best_effort(
                &join_path(&paths.home, entry),
                &join_path(&staging_home, entry),
            );
        }
    }
    if !paths.gemini_dir.trim().is_empty() {
        let staging_cfg = join_path(&staging_gemini, "config");
        let _ = ensure_private_dir(&staging_cfg);
        for cfg_file in [
            ".migrated",
            "GEMINI.md",
            "hooks.json",
            "ban-python-hook.ts",
            "mcp_config.json",
        ] {
            let src = join_path(&paths.gemini_dir, &format!("config/{cfg_file}"));
            let dst = join_path(&staging_cfg, cfg_file);
            if let Ok(bytes) = eko::file::read(&src) {
                let _ = crate::store::atomic_write_private(&dst, &bytes);
            }
        }
    }

    let _ = write_keyring_bypass_marker_2036(&staging_gemini);
    let _ = write_keyring_bypass_marker_2036(&staging_cli_dir);
    let _ = write_keyring_bypass_marker_2036(&staging_ide_dir);

    #[allow(unused_mut)]
    let mut env_overrides: Vec<(&str, &str)> = vec![
        ("HOME", staging_home.as_str()),
        ("WSL_INTEROP", "1"),
        ("AGY_SWAP_SKIP_SYNC", "1"),
    ];
    #[cfg(target_os = "linux")]
    {
        env_overrides.push(("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null"));
    }

    let run_res = spawn_interactive_tty(&agy_bin, &[], &env_overrides, None);
    let staging_paths = Paths::from_home_and_config(
        &staging_home,
        &join_path(&staging_home, ".config/agy-swap-rs"),
    );
    let captured = read_session_token_candidates(&staging_paths);
    let _ = eko::fs::remove_dir_all(&staging_home);

    let exit_code = run_res?;
    if let Some(bundle) = captured {
        return Ok(bundle);
    }
    Err(Error::Auth(format!(
        "'agy' exited (status {exit_code}) before saving a login credential"
    )))
}

/// Capture a fresh OAuth credential via PKCE account-chooser loopback (or isolated `agy` TTY when `AGY_SWAP_LOGIN_MODE=agy`).
pub fn login_via_agy_cli(paths: &Paths) -> Result<TokenBundle> {
    let timeout = eko::env::var("AGY_SWAP_LOGIN_TIMEOUT_SECS")
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(120);
    login_via_agy_cli_with_timeout(paths, timeout)
}

/// Capture a fresh OAuth credential with an explicit timeout in seconds (defaults to PKCE loopback unless `AGY_SWAP_LOGIN_MODE=agy`).
pub fn login_via_agy_cli_with_timeout(paths: &Paths, timeout_secs: u64) -> Result<TokenBundle> {
    if eko::env::var("AGY_SWAP_LOGIN_MODE")
        .map(|v| v.trim().eq_ignore_ascii_case("agy"))
        .unwrap_or(false)
    {
        return login_via_isolated_agy_tty(paths);
    }
    let open_browser = eko::env::var("AGY_SWAP_NO_BROWSER").as_deref() != Some("1");
    let http = HttpClient::new()?;
    login_via_pkce_loopback_with_timeout(&http, open_browser, timeout_secs)
}

fn parse_query_param(query: &str, wanted_key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == wanted_key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn try_open_browser(url: &str) {
    if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1:") {
        return;
    }
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(target_os = "macos"))]
    let opener = "xdg-open";
    let _ = eko::command::Command::new(opener)
        .arg(url.as_bytes())
        .spawn();
}

/// Perform an OAuth 2.0 Authorization Code + S256 PKCE loopback login flow.
pub fn login_via_pkce_loopback(http: &HttpClient) -> Result<TokenBundle> {
    login_via_pkce_loopback_with_timeout(http, true, 120)
}

/// Perform an OAuth 2.0 Authorization Code + S256 PKCE loopback login with custom options.
pub fn login_via_pkce_loopback_with_timeout(
    http: &HttpClient,
    open_browser: bool,
    timeout_secs: u64,
) -> Result<TokenBundle> {
    let mut verifier_bytes = [0u8; 32];
    let mut state_bytes = [0u8; 16];
    ps_rustcrypto::Provider
        .fill(&mut verifier_bytes)
        .map_err(|_| Error::Crypto("CSPRNG failure generating PKCE verifier".to_string()))?;
    ps_rustcrypto::Provider
        .fill(&mut state_bytes)
        .map_err(|_| Error::Crypto("CSPRNG failure generating OAuth state".to_string()))?;
    let code_verifier = base64_encode_url_nopad(&verifier_bytes);
    let code_challenge = base64_encode_url_nopad(&sha256_bytes(code_verifier.as_bytes()));
    let expected_state = base64_encode_url_nopad(&state_bytes);

    let listener = eko::net::TcpListener::bind_nonblocking(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/oauth-callback");
    let (client_id, client_secret) = select_oauth_client(&Map::new())?;
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt={}&state={}&code_challenge={}&code_challenge_method=S256",
        oauth_auth_url(),
        url_encode_component(&client_id),
        url_encode_component(&redirect_uri),
        url_encode_component(DEFAULT_OAUTH_SCOPE),
        url_encode_component("select_account consent"),
        url_encode_component(&expected_state),
        url_encode_component(&code_challenge),
    );
    if eko::env::var("AGY_SWAP_QUIET_LOGIN").as_deref() != Some("1") {
        let notice = format!("\nOpen this URL in your browser to sign in:\n  {auth_url}\n");
        eko::print::write_fd(2, notice.as_bytes());
    }
    if open_browser {
        try_open_browser(&auth_url);
    }

    let deadline = wall_unix_secs().saturating_add(timeout_secs.max(1) as i64);
    let mut auth_code: Option<String> = None;
    while wall_unix_secs() < deadline {
        let mut pfd = [eko::poll::PollFd {
            fd: listener.as_raw_fd(),
            events: eko::poll::POLLIN,
            revents: 0,
        }];
        let _ = eko::poll::poll(&mut pfd, 250);
        let Ok((stream, _peer)) = listener.accept() else {
            continue;
        };
        let mut req_buf = [0u8; 4096];
        let Ok(n) = stream.read(&mut req_buf) else {
            continue;
        };
        if n == 0 {
            continue;
        }
        let req_text = String::from_utf8_lossy(&req_buf[..n]);
        let first_line = req_text.lines().next().unwrap_or("");
        let path_and_query = first_line.split_whitespace().nth(1).unwrap_or("");
        let query = path_and_query.split_once('?').map(|(_, q)| q).unwrap_or("");
        if let Some(err_code) = parse_query_param(query, "error") {
            let _ = stream.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nAuthentication cancelled.\n",
            );
            return Err(Error::Auth(format!(
                "OAuth authorization failed - {err_code}"
            )));
        }
        let state_got = parse_query_param(query, "state").unwrap_or_default();
        let Some(code_got) = parse_query_param(query, "code").filter(|s| !s.is_empty()) else {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            continue;
        };
        if state_got != expected_state {
            let _ = stream.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nInvalid OAuth state.\n",
            );
            return Err(Error::Auth("OAuth callback state mismatch".to_string()));
        }
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nAuthentication complete. You may close this tab.\n",
        );
        let _ = stream.shutdown(eko::net::Shutdown::Both);
        auth_code = Some(code_got);
        break;
    }
    let code = auth_code.ok_or_else(|| {
        Error::Auth(format!(
            "timed out waiting for OAuth callback ({timeout_secs}s)"
        ))
    })?;
    let form = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", code.as_str()),
        ("code_verifier", code_verifier.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    let resp = http.post_form(&oauth_token_url(), &form, &[])?;
    if !resp.is_success() {
        return Err(Error::Auth(format!(
            "OAuth code exchange failed (HTTP {})",
            resp.status
        )));
    }
    let exchanged: Value = resp
        .json()
        .map_err(|_| Error::Auth("OAuth code exchange returned invalid JSON".to_string()))?;
    let Some(mut obj) = exchanged.as_object().cloned() else {
        return Err(Error::Auth(
            "OAuth code exchange returned non-object JSON".to_string(),
        ));
    };
    if let Some(secs) = value_f64(obj.get("expires_in")) {
        if secs > 0.0 && secs <= (365.0 * 86_400.0) {
            let expiry_unix = wall_unix_secs().saturating_add(secs as i64);
            obj.insert(
                "expiry".to_string(),
                Value::String(format_rfc3339_utc(expiry_unix)),
            );
            obj.insert(
                "expiry_date".to_string(),
                Value::from(expiry_unix.saturating_mul(1000)),
            );
        }
    }
    let mut wrapper = Map::new();
    wrapper.insert("token".to_string(), Value::Object(obj));
    TokenBundle::parse(&serde_json::to_string(&Value::Object(wrapper))?)
}
