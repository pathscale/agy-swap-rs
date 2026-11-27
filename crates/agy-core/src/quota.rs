//! Google Cloud Code Assist project onboarding, quota bucket parsing, and scheduled polling.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nago_rustls::rustls::crypto::SecureRandom;
use serde_json::{json, Map, Value};

use crate::http::{parse_rfc3339_unix, HttpClient, HttpResponse};
use crate::model::{clean_text, Account, Accounts, PoolQuota, PoolWindow, QuotaSnapshot};
use crate::oauth::{
    ensure_valid_token, parse_retry_after, redact_secrets, refresh_access_token,
    token_matches_email,
};
use crate::vault::Vault;
use crate::{Error, Result};

/// Default Cloud Code Assist v1internal RPC prefix.
pub const DEFAULT_CLOUD_CODE_API: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal:";
/// Project and plan tier cache TTL in seconds (15 minutes).
pub const PROJECT_MEMO_TTL_SECS: i64 = 15 * 60;
/// Polling cadence in seconds for the active account.
pub const ACTIVE_POLL_SECS: i64 = 20;
/// Polling cadence in seconds for standby accounts.
pub const STANDBY_POLL_SECS: i64 = 120;
/// Maximum exponential backoff ceiling in seconds (10 minutes).
pub const BACKOFF_MAX_SECS: i64 = 10 * 60;
/// Maximum horizon treated as a 5-hour window when only `resetTime` is present.
const FIVE_HOUR_MAX_HORIZON_SECS: i64 = 5 * 3600 + 600;

#[derive(Clone, Debug)]
struct ProjectMemo {
    project_id: String,
    plan_tier: Option<String>,
    cached_at_unix: i64,
}

#[derive(Clone, Debug, Default)]
struct BackoffState {
    wait_secs: i64,
    until_unix: i64,
}

#[derive(Clone, Debug)]
enum CloudCallError {
    Verify {
        url: String,
        message: String,
    },
    HttpStatus {
        method: &'static str,
        status: u16,
        retry_after: Option<u64>,
    },
    Transport(Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowKind {
    FiveHour,
    Weekly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PoolTarget {
    Gemini,
    ClaudeGpt,
    Argon,
    Extra(String),
}

/// Stateful Cloud Code Assist quota client with 15-minute project memo and 429/5xx backoff.
pub struct QuotaService {
    http: HttpClient,
    projects: BTreeMap<String, ProjectMemo>,
    backoffs: BTreeMap<String, BackoffState>,
    last_failed: BTreeMap<String, i64>,
}

impl QuotaService {
    /// Create a new `QuotaService` wrapping `http`.
    #[must_use]
    pub fn new(http: HttpClient) -> Self {
        Self {
            http,
            projects: BTreeMap::new(),
            backoffs: BTreeMap::new(),
            last_failed: BTreeMap::new(),
        }
    }

    /// Borrow the underlying `HttpClient`.
    #[must_use]
    pub fn http(&self) -> &HttpClient {
        &self.http
    }

    /// Return the UNIX timestamp until which `email` is backing off after 429 or 5xx, if any.
    #[must_use]
    pub fn backoff_until_unix(&self, email: &str) -> Option<i64> {
        let key = email.trim().to_ascii_lowercase();
        self.backoffs
            .get(&key)
            .map(|b| b.until_unix)
            .filter(|&u| u > 0)
    }

    /// Report whether `account` is due for a quota refresh at `now_unix`.
    #[must_use]
    pub fn is_due(&self, account: &Account, is_active: bool, now_unix: i64) -> bool {
        if account.disabled {
            return false;
        }
        let email_key = account.email.trim().to_ascii_lowercase();
        if let Some(backoff) = self.backoffs.get(&email_key) {
            if now_unix < backoff.until_unix {
                return false;
            }
        }
        let interval = if is_active {
            ACTIVE_POLL_SECS
        } else {
            STANDBY_POLL_SECS
        };
        if let Some(&failed_at) = self.last_failed.get(&email_key) {
            if now_unix >= failed_at && now_unix.saturating_sub(failed_at) < interval {
                return false;
            }
        }
        let Some(ref snap) = account.quota else {
            return true;
        };
        if snapshot_has_elapsed_reset(snap, now_unix) {
            return true;
        }
        now_unix.saturating_sub(snap.fetched_at_unix) >= interval
    }

    /// Refresh every due (or forced) account in `accounts` in slot order.
    pub fn refresh_all(
        &mut self,
        accounts: &mut Accounts,
        vault: &Vault,
        force: bool,
        now_unix: i64,
    ) -> Vec<(String, Result<()>)> {
        let emails = accounts.order.clone();
        let mut results = Vec::with_capacity(emails.len());
        for email in emails {
            let Some(account) = accounts.by_email.get_mut(&email) else {
                continue;
            };
            if account.disabled && !force {
                continue;
            }
            if !force && !self.is_due(account, false, now_unix) {
                results.push((email, Ok(())));
                continue;
            }
            let outcome = self.refresh_account(account, vault, now_unix).map(|_| ());
            results.push((email, outcome));
        }
        results
    }

    /// Refresh one `account`'s quota snapshot, persisting rotated tokens back into `vault`.
    pub fn refresh_account(
        &mut self,
        account: &mut Account,
        vault: &Vault,
        now_unix: i64,
    ) -> Result<QuotaSnapshot> {
        let email_key = account.email.trim().to_ascii_lowercase();
        let raw_token = match load_account_secret(account, vault) {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                account.verify_url = None;
                let msg = format!("no saved OAuth token for {}", account.email);
                account.last_error = Some(msg.clone());
                self.last_failed.insert(email_key, now_unix);
                return Err(Error::Auth(msg));
            }
            Err(err) => {
                account.last_error = Some(redact_secrets(&err.to_string()));
                self.last_failed.insert(email_key, now_unix);
                return Err(err);
            }
        };

        let (mut bundle, mut refreshed) = match ensure_valid_token(&self.http, &raw_token, now_unix)
        {
            Ok(pair) => pair,
            Err(err) => {
                if matches!(err, Error::Auth(_)) {
                    account.verify_url = None;
                }
                if matches!(err, Error::RateLimited { .. }) {
                    self.record_backoff(&email_key, now_unix, None);
                }
                account.last_error = Some(redact_secrets(&err.to_string()));
                self.last_failed.insert(email_key, now_unix);
                return Err(err);
            }
        };

        if !account.email.trim().is_empty()
            && !token_matches_email(&bundle.raw_json, &account.email)
        {
            account.verify_url = None;
            let msg = "refreshed token identity does not match account email".to_string();
            account.last_error = Some(msg.clone());
            self.last_failed.insert(email_key, now_unix);
            return Err(Error::Auth(msg));
        }

        if refreshed {
            persist_refreshed_token(account, vault, &bundle.raw_json)?;
        }

        let memo = self.remembered_project(&email_key, now_unix);
        let (project_id, plan_tier, was_remembered) = match memo {
            Some(m) => (m.project_id, m.plan_tier, true),
            None => {
                let mut load_res = self.cloud_post(
                    &bundle.access_token,
                    "loadCodeAssist",
                    &json!({ "metadata": { "ideType": "ANTIGRAVITY" } }),
                );
                if matches!(
                    load_res,
                    Err(CloudCallError::HttpStatus { status: 401, .. })
                ) && !refreshed
                    && bundle.refresh_token.is_some()
                {
                    if let Ok(next_bundle) = refresh_access_token(&self.http, &bundle.raw_json) {
                        if token_matches_email(&next_bundle.raw_json, &account.email) {
                            bundle = next_bundle;
                            refreshed = true;
                            persist_refreshed_token(account, vault, &bundle.raw_json)?;
                            load_res = self.cloud_post(
                                &bundle.access_token,
                                "loadCodeAssist",
                                &json!({ "metadata": { "ideType": "ANTIGRAVITY" } }),
                            );
                        }
                    }
                }
                let info = match load_res {
                    Ok(v) => v,
                    Err(cerr) => {
                        return Err(
                            self.handle_cloud_error(account, &email_key, now_unix, false, cerr)
                        );
                    }
                };
                if let Some((url, msg)) = eligibility_from_load(&info) {
                    return Err(self.handle_cloud_error(
                        account,
                        &email_key,
                        now_unix,
                        false,
                        CloudCallError::Verify { url, message: msg },
                    ));
                }
                let mut proj = extract_cloud_project(info.get("cloudaicompanionProject"));
                let mut onboarded_tier: Option<String> = None;
                if proj.is_empty() {
                    match self.onboard_project(&bundle.access_token, &info) {
                        Ok((p, t)) => {
                            proj = p;
                            onboarded_tier = t;
                        }
                        Err(cerr) => {
                            return Err(
                                self.handle_cloud_error(account, &email_key, now_unix, false, cerr)
                            );
                        }
                    }
                }
                if proj.is_empty() {
                    let err = Error::Network("Google returned no Code Assist project".to_string());
                    account.last_error = Some(err.to_string());
                    self.last_failed.insert(email_key, now_unix);
                    return Err(err);
                }
                let tier = extract_plan_tier(&info).or(onboarded_tier);
                (proj, tier, false)
            }
        };

        let proj_body = json!({ "project": project_id });
        let mut summary_res =
            self.cloud_post(&bundle.access_token, "retrieveUserQuotaSummary", &proj_body);
        if matches!(
            summary_res,
            Err(CloudCallError::HttpStatus { status: 401, .. })
        ) && !refreshed
            && bundle.refresh_token.is_some()
        {
            if let Ok(next_bundle) = refresh_access_token(&self.http, &bundle.raw_json) {
                if token_matches_email(&next_bundle.raw_json, &account.email) {
                    bundle = next_bundle;
                    persist_refreshed_token(account, vault, &bundle.raw_json)?;
                    summary_res = self.cloud_post(
                        &bundle.access_token,
                        "retrieveUserQuotaSummary",
                        &proj_body,
                    );
                }
            }
        }
        let summary_opt = match summary_res {
            Ok(val) => Some(val),
            Err(CloudCallError::HttpStatus {
                status: 404 | 501, ..
            }) => None,
            Err(cerr) => {
                self.projects.remove(&email_key);
                return Err(self.handle_cloud_error(account, &email_key, now_unix, true, cerr));
            }
        };

        let skew_secs = self.http.clock_skew_secs();
        let mut snapshot = QuotaSnapshot {
            fetched_at_unix: now_unix,
            project_id: Some(project_id.clone()),
            plan_tier: plan_tier.clone(),
            gemini: PoolQuota::new("Gemini"),
            claude_gpt: PoolQuota::new("Claude/GPT"),
            argon: None,
            extra_pools: Vec::new(),
        };

        let mut parsed_any = false;
        if let Some(ref summary) = summary_opt {
            parsed_any |= merge_quota_payload(&mut snapshot, summary, now_unix, skew_secs);
        }

        let need_flat = summary_opt.is_none()
            || (!snapshot.gemini.five_hour.is_known() && !snapshot.gemini.weekly.is_known());
        if need_flat {
            match self.cloud_post(&bundle.access_token, "retrieveUserQuota", &proj_body) {
                Ok(flat_val) => {
                    parsed_any |=
                        merge_quota_payload(&mut snapshot, &flat_val, now_unix, skew_secs);
                }
                Err(cerr) if summary_opt.is_none() => {
                    self.projects.remove(&email_key);
                    return Err(self.handle_cloud_error(account, &email_key, now_unix, true, cerr));
                }
                Err(_) => {}
            }
        }

        if !snapshot.gemini.five_hour.is_known() && !snapshot.gemini.weekly.is_known() {
            if let Ok(models_val) =
                self.cloud_post(&bundle.access_token, "fetchAvailableModels", &proj_body)
            {
                parsed_any |=
                    merge_available_models(&mut snapshot, &models_val, now_unix, skew_secs);
            }
        }

        if !parsed_any {
            self.projects.remove(&email_key);
            account.verify_url = None;
            let err = Error::Network("Google returned no usable quota buckets".to_string());
            account.last_error = Some(err.to_string());
            self.last_failed.insert(email_key, now_unix);
            return Err(err);
        }

        if !was_remembered {
            self.projects.insert(
                email_key.clone(),
                ProjectMemo {
                    project_id,
                    plan_tier,
                    cached_at_unix: now_unix,
                },
            );
        }
        self.backoffs.remove(&email_key);
        self.last_failed.remove(&email_key);
        account.verify_url = None;
        account.last_error = None;
        account.quota = Some(snapshot.clone());
        Ok(snapshot)
    }

    fn remembered_project(&self, email_key: &str, now_unix: i64) -> Option<ProjectMemo> {
        let memo = self.projects.get(email_key)?;
        if now_unix >= memo.cached_at_unix
            && now_unix.saturating_sub(memo.cached_at_unix) < PROJECT_MEMO_TTL_SECS
        {
            Some(memo.clone())
        } else {
            None
        }
    }

    fn record_backoff(&mut self, email_key: &str, now_unix: i64, retry_after: Option<u64>) {
        let state = self.backoffs.entry(email_key.to_string()).or_default();
        state.wait_secs = if state.wait_secs <= 0 {
            ACTIVE_POLL_SECS
        } else {
            state.wait_secs.saturating_mul(2).min(BACKOFF_MAX_SECS)
        };
        if let Some(ra) = retry_after {
            let hinted = (ra.min(BACKOFF_MAX_SECS as u64) as i64).max(ACTIVE_POLL_SECS);
            if hinted > state.wait_secs {
                state.wait_secs = hinted;
            }
        }
        let jitter = if state.wait_secs < BACKOFF_MAX_SECS {
            let quarter = (state.wait_secs / 4).max(0);
            if quarter > 0 {
                (random_u32() as i64).rem_euclid(quarter + 1)
            } else {
                0
            }
        } else {
            0
        };
        state.until_unix = now_unix.saturating_add(state.wait_secs.saturating_sub(jitter));
    }

    fn handle_cloud_error(
        &mut self,
        account: &mut Account,
        email_key: &str,
        now_unix: i64,
        eligibility_passed: bool,
        cerr: CloudCallError,
    ) -> Error {
        self.last_failed.insert(email_key.to_string(), now_unix);
        match cerr {
            CloudCallError::Verify { url, message } => {
                self.projects.remove(email_key);
                account.verify_url = Some(url.clone());
                let clean_msg = if message.is_empty() {
                    format!("Google verification required for {}", account.email)
                } else {
                    redact_secrets(&message)
                };
                account.last_error = Some(clean_msg);
                Error::VerifyRequired {
                    email: account.email.clone(),
                    url,
                }
            }
            CloudCallError::HttpStatus {
                method,
                status,
                retry_after,
            } => {
                if eligibility_passed || status == 401 {
                    account.verify_url = None;
                }
                if status == 429 || status >= 500 {
                    self.record_backoff(email_key, now_unix, retry_after);
                }
                let err = if status == 429 {
                    Error::RateLimited {
                        retry_after_secs: retry_after.unwrap_or(20),
                    }
                } else if status == 401 || status == 403 {
                    Error::Auth(format!("{method} rejected request (HTTP {status})"))
                } else {
                    Error::Network(format!("{method} failed (HTTP {status})"))
                };
                account.last_error = Some(redact_secrets(&err.to_string()));
                err
            }
            CloudCallError::Transport(err) => {
                if eligibility_passed || matches!(err, Error::Auth(_)) {
                    account.verify_url = None;
                }
                account.last_error = Some(redact_secrets(&err.to_string()));
                err
            }
        }
    }

    fn onboard_project(
        &self,
        access_token: &str,
        info: &Value,
    ) -> core::result::Result<(String, Option<String>), CloudCallError> {
        let Some(tier_id) = allowed_tier_id(info) else {
            return Ok((String::new(), None));
        };
        let mut op = self.cloud_post(
            access_token,
            "onboardUser",
            &json!({
                "tierId": tier_id,
                "metadata": { "ideType": "ANTIGRAVITY" }
            }),
        )?;
        let poll_ms = eko::env::var("AGY_SWAP_ONBOARD_POLL_MS")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(500);
        for _ in 0..5 {
            if op.get("done").and_then(Value::as_bool) == Some(true) {
                break;
            }
            let Some(op_name) = op
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
            else {
                break;
            };
            if poll_ms > 0 {
                eko::sleep_ms(poll_ms);
            }
            op = self.cloud_get_operation(access_token, &op_name)?;
        }
        if let Some(op_err) = op.get("error").and_then(Value::as_object) {
            if let Some((url, message)) = eligibility_from_operation_error(op_err) {
                return Err(CloudCallError::Verify { url, message });
            }
            let msg = op_err
                .get("message")
                .and_then(Value::as_str)
                .map(clean_text)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "onboardUser failed".to_string());
            return Err(CloudCallError::Transport(Error::Network(msg)));
        }
        let project_id = extract_cloud_project(
            op.get("response")
                .and_then(|r| r.get("cloudaicompanionProject")),
        );
        let tier_label = Some(tier_display_name(&tier_id, ""));
        Ok((project_id, tier_label))
    }

    fn cloud_post(
        &self,
        access_token: &str,
        method: &'static str,
        payload: &Value,
    ) -> core::result::Result<Value, CloudCallError> {
        let body = serde_json::to_vec(payload)
            .map_err(|e| CloudCallError::Transport(Error::Json(e.to_string())))?;
        let url = cloud_method_url(&cloud_base_url(), method);
        let auth = format!("Bearer {}", access_token.trim());
        let resp = self
            .http
            .post_json(&url, &body, &[("Authorization", auth.as_str())])
            .map_err(CloudCallError::Transport)?;
        decode_cloud_response(method, resp)
    }

    fn cloud_get_operation(
        &self,
        access_token: &str,
        operation_name: &str,
    ) -> core::result::Result<Value, CloudCallError> {
        let url = cloud_operation_url(&cloud_base_url(), operation_name)
            .map_err(CloudCallError::Transport)?;
        let auth = format!("Bearer {}", access_token.trim());
        let resp = self
            .http
            .get(&url, &[("Authorization", auth.as_str())])
            .map_err(CloudCallError::Transport)?;
        decode_cloud_response("getOperation", resp)
    }
}

fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    if ps_rustcrypto::Provider.fill(&mut bytes).is_ok() {
        u32::from_le_bytes(bytes)
    } else {
        (eko::time::epoch_secs() as u32).wrapping_mul(2_654_435_761)
    }
}

fn load_account_secret(account: &Account, vault: &Vault) -> Result<Option<String>> {
    let primary = account.secret_key();
    if let Some(secret) = vault.get(&primary)? {
        if !secret.trim().is_empty() {
            return Ok(Some(secret));
        }
    }
    let fallback_key = format!("account:{}", account.email);
    if fallback_key != primary {
        if let Some(secret) = vault.get(&fallback_key)? {
            if !secret.trim().is_empty() {
                return Ok(Some(secret));
            }
        }
    }
    if !account.email.trim().is_empty() && account.email != primary {
        if let Some(secret) = vault.get(&account.email)? {
            if !secret.trim().is_empty() {
                return Ok(Some(secret));
            }
        }
    }
    if let Some(ref legacy) = account.legacy_token_data {
        if !legacy.trim().is_empty() {
            return Ok(Some(legacy.clone()));
        }
    }
    Ok(None)
}

fn persist_refreshed_token(account: &mut Account, vault: &Vault, raw_json: &str) -> Result<()> {
    let key = account.secret_key();
    vault.set(&key, raw_json)?;
    account.vault_ref = Some(key);
    account.legacy_token_data = None;
    Ok(())
}

fn cloud_base_url() -> String {
    for var in [
        "AGY_SWAP_CLOUD_CODE_URL",
        "AGY_SWAP_CLOUD_API_URL",
        "AGY_SWAP_QUOTA_API_URL",
    ] {
        if let Some(val) = eko::env::var(var)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return val;
        }
    }
    DEFAULT_CLOUD_CODE_API.to_string()
}

fn cloud_method_url(base: &str, method: &str) -> String {
    let trimmed = base.trim();
    if trimmed.ends_with(':') {
        format!("{trimmed}{method}")
    } else if trimmed.ends_with("/v1internal") {
        format!("{trimmed}:{method}")
    } else {
        format!("{}/v1internal:{method}", trimmed.trim_end_matches('/'))
    }
}

fn cloud_operation_url(base: &str, name: &str) -> Result<String> {
    let trimmed = name.trim().trim_start_matches('/');
    if trimmed.is_empty()
        || trimmed.contains("..")
        || trimmed.contains(['?', '#', '\\'])
        || !trimmed.starts_with("operations/")
    {
        return Err(Error::InvalidInput(
            "invalid Cloud Code operation name".to_string(),
        ));
    }
    let stripped = base.trim().trim_end_matches(':');
    if let Some(idx) = stripped.rfind("/v1internal") {
        Ok(format!(
            "{}/{trimmed}",
            &stripped[..idx + "/v1internal".len()]
        ))
    } else {
        Ok(format!(
            "{}/v1internal/{trimmed}",
            stripped.trim_end_matches('/')
        ))
    }
}

fn decode_cloud_response(
    method: &'static str,
    resp: HttpResponse,
) -> core::result::Result<Value, CloudCallError> {
    if !resp.is_success() {
        if let Some((url, message)) = eligibility_from_error_body(resp.status, &resp.body) {
            return Err(CloudCallError::Verify { url, message });
        }
        return Err(CloudCallError::HttpStatus {
            method,
            status: resp.status,
            retry_after: parse_retry_after(&resp),
        });
    }
    let val: Value = resp
        .json()
        .map_err(|e| CloudCallError::Transport(Error::Json(e.to_string())))?;
    if !val.is_object() {
        return Err(CloudCallError::Transport(Error::Json(
            "Cloud Code response must be a JSON object".to_string(),
        )));
    }
    Ok(val)
}

fn verification_reason(reason: &str) -> bool {
    let upper = reason.to_ascii_uppercase();
    upper.contains("VALIDATION") || upper.contains("VERIF")
}

fn verification_text(reason: &str, message: &str) -> bool {
    if verification_reason(reason) {
        return true;
    }
    let lower = message.to_ascii_lowercase();
    lower.contains("verify") || lower.contains("validation") || lower.contains("appeal")
}

/// Validate that `raw` is an `https://` URL on `google.com`, `*.google.com`, or `*.google`.
#[must_use]
pub fn safe_google_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() < 9 || !trimmed.as_bytes()[..8].eq_ignore_ascii_case(b"https://") {
        return None;
    }
    let rest = &trimmed[8..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return None;
    }
    let host = authority
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority)
        .to_ascii_lowercase();
    let is_google_com = host == "google.com" || host.ends_with(".google.com");
    let is_dot_google = host.ends_with(".google") && host.len() > ".google".len();
    if !is_google_com && !is_dot_google {
        return None;
    }
    Some(format!("https://{rest}"))
}

fn first_non_empty<'a>(items: &[Option<&'a str>]) -> Option<&'a str> {
    items
        .iter()
        .copied()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
}

fn eligibility_from_error_body(status: u16, body: &[u8]) -> Option<(String, String)> {
    if status != 400 && status != 403 {
        return None;
    }
    let parsed: Value = serde_json::from_slice(body).ok()?;
    let details = parsed
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(Value::as_array)?;
    for item in details {
        let Some(detail) = item.as_object() else {
            continue;
        };
        if let Some(ty) = detail.get("@type").and_then(Value::as_str) {
            if !ty.is_empty() && !ty.ends_with("/google.rpc.ErrorInfo") {
                continue;
            }
        }
        let reason = detail.get("reason").and_then(Value::as_str).unwrap_or("");
        let meta = detail.get("metadata").and_then(Value::as_object);
        let raw_link = first_non_empty(&[
            meta.and_then(|m| m.get("validation_url"))
                .and_then(Value::as_str),
            meta.and_then(|m| m.get("appeal_url"))
                .and_then(Value::as_str),
            meta.and_then(|m| m.get("validationUrl"))
                .and_then(Value::as_str),
            meta.and_then(|m| m.get("appealUrl"))
                .and_then(Value::as_str),
        ]);
        let message = meta
            .and_then(|m| m.get("uiMessage"))
            .and_then(Value::as_str)
            .map(clean_text)
            .unwrap_or_default();
        if raw_link.is_none() && !verification_text(reason, &message) {
            continue;
        }
        let checked_url = raw_link.and_then(safe_google_url).unwrap_or_default();
        return Some((checked_url, message));
    }
    None
}

fn eligibility_from_operation_error(op_err: &Map<String, Value>) -> Option<(String, String)> {
    let wrapped = json!({ "error": Value::Object(op_err.clone()) });
    let bytes = serde_json::to_vec(&wrapped).ok()?;
    eligibility_from_error_body(403, &bytes)
}

fn allowed_tier_id(info: &Value) -> Option<String> {
    let tiers = info.get("allowedTiers").and_then(Value::as_array)?;
    for item in tiers {
        if item
            .get("id")
            .and_then(Value::as_str)
            .map(clean_text)
            .as_deref()
            == Some("free-tier")
        {
            return Some("free-tier".to_string());
        }
    }
    for item in tiers {
        if item.get("isDefault").and_then(Value::as_bool) == Some(true) {
            if let Some(id) = item
                .get("id")
                .and_then(Value::as_str)
                .map(clean_text)
                .filter(|s| !s.is_empty())
            {
                return Some(id);
            }
        }
    }
    None
}

fn eligibility_from_load(info: &Value) -> Option<(String, String)> {
    let has_project = !extract_cloud_project(info.get("cloudaicompanionProject")).is_empty();
    let has_tier = info.get("currentTier").and_then(Value::as_object).is_some()
        || info.get("paidTier").and_then(Value::as_object).is_some();
    if (has_project && has_tier) || allowed_tier_id(info).is_some() {
        return None;
    }
    let ineligible = info.get("ineligibleTiers").and_then(Value::as_array)?;
    let check_tier = |tier: &Map<String, Value>| -> Option<(String, String)> {
        let raw_link = first_non_empty(&[
            tier.get("validationUrl").and_then(Value::as_str),
            tier.get("appealUrl").and_then(Value::as_str),
        ]);
        let message = first_non_empty(&[
            tier.get("reasonMessage").and_then(Value::as_str),
            tier.get("validationErrorMessage").and_then(Value::as_str),
        ])
        .map(clean_text)
        .unwrap_or_default();
        let reason = tier.get("reasonCode").and_then(Value::as_str).unwrap_or("");
        if raw_link.is_none() && !verification_text(reason, &message) {
            return None;
        }
        let checked_url = raw_link.and_then(safe_google_url).unwrap_or_default();
        Some((checked_url, message))
    };
    for item in ineligible {
        if let Some(tier) = item.as_object() {
            let tid = tier
                .get("tierId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if tid.is_empty() || tid == "free-tier" {
                if let Some(hit) = check_tier(tier) {
                    return Some(hit);
                }
            }
        }
    }
    for item in ineligible {
        if let Some(tier) = item.as_object() {
            if let Some(hit) = check_tier(tier) {
                return Some(hit);
            }
        }
    }
    None
}

fn extract_cloud_project(raw: Option<&Value>) -> String {
    let Some(v) = raw else {
        return String::new();
    };
    if let Some(s) = v.as_str() {
        return s.trim().to_string();
    }
    if let Some(obj) = v.as_object() {
        if let Some(s) = obj.get("id").and_then(Value::as_str) {
            return s.trim().to_string();
        }
    }
    String::new()
}

fn tier_display_name(tier_id: &str, fallback_name: &str) -> String {
    match tier_id.trim() {
        "free-tier" => "Free".to_string(),
        "g1-pro-tier" => "Google AI Pro".to_string(),
        "g1-ultra-tier" => "Google AI Ultra".to_string(),
        "g1-ultra-lite-tier" => "Google AI Ultra Lite".to_string(),
        other => {
            let cleaned_name = clean_text(fallback_name);
            if !cleaned_name.is_empty() {
                cleaned_name
            } else {
                clean_text(other)
            }
        }
    }
}

fn extract_plan_tier(info: &Value) -> Option<String> {
    for key in ["paidTier", "currentTier"] {
        if let Some(tier_obj) = info.get(key).and_then(Value::as_object) {
            let tid = tier_obj
                .get("id")
                .and_then(Value::as_str)
                .map(clean_text)
                .unwrap_or_default();
            let tname = tier_obj.get("name").and_then(Value::as_str).unwrap_or("");
            if !tid.is_empty() || !tname.trim().is_empty() {
                let label = tier_display_name(&tid, tname);
                if !label.is_empty() {
                    return Some(label);
                }
            }
        }
    }
    if let Some(plan_obj) = info.get("planInfo").and_then(Value::as_object) {
        if let Some(pt) = plan_obj
            .get("planType")
            .and_then(Value::as_str)
            .map(clean_text)
            .filter(|s| !s.is_empty())
        {
            return Some(pt);
        }
    }
    None
}

fn snapshot_has_elapsed_reset(snap: &QuotaSnapshot, now_unix: i64) -> bool {
    for pool in snap.all_pools() {
        for win in [&pool.five_hour, &pool.weekly] {
            if let Some(rst) = win.reset_at_unix {
                if rst > 0 && rst <= now_unix {
                    return true;
                }
            }
        }
    }
    false
}

fn valid_quota_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn sanitize_extra_pool_name(raw_id: &str, raw_window: &str) -> Option<String> {
    let mut lower = raw_id.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }
    if !raw_window.is_empty() {
        let suffix = format!("-{}", raw_window.to_ascii_lowercase());
        if let Some(stripped) = lower.strip_suffix(&suffix) {
            lower = stripped.to_string();
        }
    }
    for known_suffix in [
        "-5h", "-5hr", "-short", "-weekly", "-7d", "-1w", "-monthly", "-daily",
    ] {
        if let Some(stripped) = lower.strip_suffix(known_suffix) {
            lower = stripped.to_string();
            break;
        }
    }
    let mut out = String::with_capacity(lower.len());
    let mut prev_under = false;
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
            prev_under = false;
        } else if !out.is_empty() && !prev_under && matches!(ch, '-' | '.' | '_' | ' ' | '/') {
            out.push('_');
            prev_under = true;
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    valid_quota_id(&trimmed).then_some(trimmed)
}

fn classify_pool_target(bucket_id: &str, group_name: &str, window: &str) -> Option<PoolTarget> {
    let bid = bucket_id.trim().to_ascii_lowercase();
    if !bid.is_empty() {
        if bid.starts_with("gemini-argon") || bid.starts_with("argon") || bid.contains("-argon") {
            return Some(PoolTarget::Argon);
        }
        if bid.starts_with("gemini-") || bid == "gemini" {
            return Some(PoolTarget::Gemini);
        }
        if bid.starts_with("3p-")
            || bid.starts_with("claude-")
            || bid.starts_with("gpt-")
            || bid.starts_with("anthropic-")
            || bid.starts_with("openai-")
            || bid.starts_with("third_party")
            || bid.starts_with("third-party")
            || bid == "claude_gpt"
        {
            return Some(PoolTarget::ClaudeGpt);
        }
        if let Some(extra) = sanitize_extra_pool_name(&bid, window) {
            return Some(PoolTarget::Extra(extra));
        }
    }
    let glower = group_name.trim().to_ascii_lowercase();
    if glower.contains("argon") {
        Some(PoolTarget::Argon)
    } else if glower.contains("gemini") {
        Some(PoolTarget::Gemini)
    } else if glower.contains("claude") || glower.contains("gpt") || glower.contains("third") {
        Some(PoolTarget::ClaudeGpt)
    } else {
        sanitize_extra_pool_name(&glower, window).map(PoolTarget::Extra)
    }
}

fn classify_window(
    raw_window: &str,
    bucket_id: &str,
    reset_at_unix: Option<i64>,
    now_unix: i64,
) -> WindowKind {
    let w = raw_window.trim().to_ascii_lowercase();
    match w.as_str() {
        "5h" | "5hr" | "5_hour" | "5-hour" | "five_hour" | "short" | "hourly" | "daily" => {
            return WindowKind::FiveHour;
        }
        "weekly" | "7d" | "1w" | "week" | "long" | "monthly" => {
            return WindowKind::Weekly;
        }
        _ => {}
    }
    let bid = bucket_id.trim().to_ascii_lowercase();
    if bid.ends_with("-5h") || bid.ends_with("-5hr") || bid.ends_with("-short") {
        return WindowKind::FiveHour;
    }
    if bid.ends_with("-weekly") || bid.ends_with("-7d") || bid.ends_with("-1w") {
        return WindowKind::Weekly;
    }
    if let Some(rst) = reset_at_unix {
        if rst.saturating_sub(now_unix) <= FIVE_HOUR_MAX_HORIZON_SECS {
            return WindowKind::FiveHour;
        }
        return WindowKind::Weekly;
    }
    WindowKind::FiveHour
}

fn extract_remaining_pct(bucket: &Map<String, Value>, default_zero_if_reset: bool) -> Option<f64> {
    if let Some(frac) = bucket
        .get("remainingFraction")
        .or_else(|| bucket.get("remaining_fraction"))
        .and_then(Value::as_f64)
    {
        if frac.is_finite() {
            return Some((frac.clamp(0.0, 1.0)) * 100.0);
        }
    }
    if let Some(pct) = bucket
        .get("remainingPercent")
        .or_else(|| bucket.get("remaining_pct"))
        .and_then(Value::as_f64)
    {
        if pct.is_finite() {
            return Some(pct.clamp(0.0, 100.0));
        }
    }
    if bucket.get("exhausted").and_then(Value::as_bool) == Some(true) || default_zero_if_reset {
        return Some(0.0);
    }
    None
}

fn parse_shifted_reset(bucket: &Map<String, Value>, skew_secs: i64) -> Option<i64> {
    let raw = bucket
        .get("resetTime")
        .or_else(|| bucket.get("reset_at"))
        .and_then(Value::as_str)?;
    parse_rfc3339_unix(raw).map(|ts| ts.saturating_sub(skew_secs))
}

fn merge_window(slot: &mut PoolWindow, candidate: PoolWindow, now_unix: i64) {
    let Some(cand_pct) = candidate.remaining_pct else {
        return;
    };
    let Some(cur_pct) = slot.remaining_pct else {
        *slot = candidate;
        return;
    };
    let cur_expired = slot.reset_at_unix.is_some_and(|r| r <= now_unix);
    let cand_expired = candidate.reset_at_unix.is_some_and(|r| r <= now_unix);
    let replace = match (cur_expired, cand_expired) {
        (true, false) => true,
        (false, true) => false,
        _ => {
            if cand_pct < cur_pct {
                true
            } else if cand_pct - cur_pct < 1e-9 {
                match (slot.reset_at_unix, candidate.reset_at_unix) {
                    (None, Some(_)) => true,
                    (Some(cur_r), Some(cand_r)) => cand_r > cur_r,
                    _ => false,
                }
            } else {
                false
            }
        }
    };
    if replace {
        *slot = candidate;
    }
}

fn apply_bucket_to_snapshot(
    snap: &mut QuotaSnapshot,
    target: PoolTarget,
    win_kind: WindowKind,
    win: PoolWindow,
    now_unix: i64,
) {
    let pool_mut: &mut PoolQuota = match target {
        PoolTarget::Gemini => &mut snap.gemini,
        PoolTarget::ClaudeGpt => &mut snap.claude_gpt,
        PoolTarget::Argon => snap
            .argon
            .get_or_insert_with(|| PoolQuota::new("Gemini 4 Argon")),
        PoolTarget::Extra(name) => {
            if let Some(idx) = snap
                .extra_pools
                .iter()
                .position(|p| p.name.eq_ignore_ascii_case(&name))
            {
                &mut snap.extra_pools[idx]
            } else {
                snap.extra_pools.push(PoolQuota::new(name));
                let last = snap.extra_pools.len() - 1;
                &mut snap.extra_pools[last]
            }
        }
    };
    match win_kind {
        WindowKind::FiveHour => merge_window(&mut pool_mut.five_hour, win, now_unix),
        WindowKind::Weekly => merge_window(&mut pool_mut.weekly, win, now_unix),
    }
}

/// Merge a `retrieveUserQuotaSummary` or `retrieveUserQuota` JSON payload into `snap`.
pub fn merge_quota_payload(
    snap: &mut QuotaSnapshot,
    payload: &Value,
    now_unix: i64,
    skew_secs: i64,
) -> bool {
    let mut any = false;
    if let Some(groups) = payload.get("groups").and_then(Value::as_array) {
        for group_val in groups {
            let Some(group) = group_val.as_object() else {
                continue;
            };
            let group_name = group
                .get("displayName")
                .or_else(|| group.get("name"))
                .or_else(|| group.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(buckets) = group.get("buckets").and_then(Value::as_array) else {
                continue;
            };
            let mut group_pool: Option<PoolTarget> = None;
            for b_val in buckets {
                let Some(bucket) = b_val.as_object() else {
                    continue;
                };
                if bucket.get("disabled").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                let bid = bucket
                    .get("bucketId")
                    .or_else(|| bucket.get("modelId"))
                    .or_else(|| bucket.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let raw_win = bucket.get("window").and_then(Value::as_str).unwrap_or("");
                if group_pool.is_none() {
                    group_pool = classify_pool_target(bid, group_name, raw_win);
                }
                let Some(pct) = extract_remaining_pct(bucket, false) else {
                    continue;
                };
                let reset_at = parse_shifted_reset(bucket, skew_secs);
                let Some(target) =
                    classify_pool_target(bid, group_name, raw_win).or_else(|| group_pool.clone())
                else {
                    continue;
                };
                let win_kind = classify_window(raw_win, bid, reset_at, now_unix);
                apply_bucket_to_snapshot(
                    snap,
                    target,
                    win_kind,
                    PoolWindow::new(Some(pct), reset_at),
                    now_unix,
                );
                any = true;
            }
        }
    }
    if let Some(buckets) = payload.get("buckets").and_then(Value::as_array) {
        for b_val in buckets {
            let Some(bucket) = b_val.as_object() else {
                continue;
            };
            if bucket.get("disabled").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let bid = bucket
                .get("bucketId")
                .or_else(|| bucket.get("modelId"))
                .or_else(|| bucket.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let raw_win = bucket.get("window").and_then(Value::as_str).unwrap_or("");
            let group_hint = bucket
                .get("displayName")
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(pct) = extract_remaining_pct(bucket, false) else {
                continue;
            };
            let reset_at = parse_shifted_reset(bucket, skew_secs);
            let Some(target) = classify_pool_target(bid, group_hint, raw_win) else {
                continue;
            };
            let win_kind = classify_window(raw_win, bid, reset_at, now_unix);
            apply_bucket_to_snapshot(
                snap,
                target,
                win_kind,
                PoolWindow::new(Some(pct), reset_at),
                now_unix,
            );
            any = true;
        }
    }
    any
}

fn merge_available_models(
    snap: &mut QuotaSnapshot,
    payload: &Value,
    now_unix: i64,
    skew_secs: i64,
) -> bool {
    let Some(models) = payload.get("models").and_then(Value::as_object) else {
        return false;
    };
    let had_gemini = snap.gemini.five_hour.is_known() || snap.gemini.weekly.is_known();
    let had_claude = snap.claude_gpt.five_hour.is_known() || snap.claude_gpt.weekly.is_known();
    let mut any = false;
    for (model_id, entry_val) in models {
        let Some(info) = entry_val
            .as_object()
            .and_then(|e| e.get("quotaInfo"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        let Some(reset_at) = parse_shifted_reset(info, skew_secs) else {
            continue;
        };
        let Some(pct) = extract_remaining_pct(info, true) else {
            continue;
        };
        let Some(target) = classify_pool_target(model_id, "", "") else {
            continue;
        };
        if (matches!(target, PoolTarget::Gemini) && had_gemini)
            || (matches!(target, PoolTarget::ClaudeGpt) && had_claude)
        {
            continue;
        }
        let win_kind = classify_window("", model_id, Some(reset_at), now_unix);
        apply_bucket_to_snapshot(
            snap,
            target,
            win_kind,
            PoolWindow::new(Some(pct), Some(reset_at)),
            now_unix,
        );
        any = true;
    }
    any
}
