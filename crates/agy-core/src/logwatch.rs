//! Live Antigravity CLI log tailer, historical log cooldown scanner, and idempotent failover coordinator.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use eko::file::File;
use eko::path::Path;
use serde::{Deserialize, Serialize};

use crate::policy::{
    evaluate_pool_failover, lookup_account_secret, select_next, PoolFailoverPolicy, RankingPolicy,
    SwitchMode,
};
use crate::store::atomic_write_private;
use crate::{
    Accounts, Error, HistoryEntry, ModelFamily, Paths, Result, SessionManager, Store, Vault,
};

/// Default cooldown duration in seconds applied to an exhausted family/account on 429 failover.
pub const DEFAULT_FAILOVER_COOLDOWN_SECS: i64 = 1800;

/// Default deduplication window in seconds so burst 429 lines trigger only one rotation.
pub const DEFAULT_FAILOVER_DEDUPE_SECS: i64 = 30;

/// Maximum bytes read from a single log growth step to bound memory in `#![no_std]`.
const MAX_TAIL_STEP_BYTES: usize = 256 * 1024;

/// Persisted state machine state for live failover coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchRuntimeState {
    Idle,
    Switching,
    Ready,
    NoAccount,
}

impl Default for SwitchRuntimeState {
    fn default() -> Self {
        Self::Idle
    }
}

impl SwitchRuntimeState {
    /// Canonical snake_case representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Switching => "switching",
            Self::Ready => "ready",
            Self::NoAccount => "no_account",
        }
    }
}

impl fmt::Display for SwitchRuntimeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persisted runtime status stored in `paths.runtime_file` under an exclusive `flock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchRuntime {
    #[serde(default)]
    pub state: SwitchRuntimeState,
    #[serde(default)]
    pub active_email: Option<String>,
    #[serde(default)]
    pub last_switch_unix: i64,
    #[serde(default)]
    pub last_trigger: Option<String>,
    #[serde(default)]
    pub restart_agy_needed: bool,
}

impl Default for SwitchRuntime {
    fn default() -> Self {
        Self {
            state: SwitchRuntimeState::Idle,
            active_email: None,
            last_switch_unix: 0,
            last_trigger: None,
            restart_agy_needed: false,
        }
    }
}

/// Result returned by [`rotate_after_failure`] and [`poll_logs_once`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverResult {
    pub outcome: String,
    pub previous: Option<String>,
    pub switched_to: Option<String>,
    pub restart_needed: bool,
}

/// Structured quota exhaustion event parsed from a single Antigravity CLI log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogQuotaEvent {
    pub kind: String,
    pub path: String,
    pub family: Option<ModelFamily>,
    pub reset_secs: Option<u64>,
    pub email_hint: Option<String>,
    pub line: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TailCursorStore {
    #[serde(default)]
    initialized: bool,
    #[serde(default)]
    offsets: BTreeMap<String, u64>,
}

pub(crate) fn acquire_exclusive_lock(lock_path: &str) -> Result<File> {
    if let Some(parent) = Path::new(lock_path).parent().and_then(|p| p.to_str()) {
        if !parent.is_empty() {
            eko::file::create_dir_all(parent)?;
        }
    }
    let file = File::append(lock_path)?;
    let _ = file.set_permissions_mode(0o600);
    file.lock_exclusive(false)?;
    Ok(file)
}

fn runtime_lock_path(paths: &Paths) -> String {
    format!("{}.lock", paths.runtime_file)
}

fn cursor_store_path(paths: &Paths) -> String {
    format!("{}/logwatch-cursors.json", paths.config_dir)
}

fn read_runtime_unlocked(paths: &Paths) -> Result<SwitchRuntime> {
    if !eko::file::exists(&paths.runtime_file) {
        return Ok(SwitchRuntime::default());
    }
    let raw = eko::file::read_to_string(&paths.runtime_file)?;
    if raw.trim().is_empty() {
        return Ok(SwitchRuntime::default());
    }
    Ok(serde_json::from_str::<SwitchRuntime>(&raw).unwrap_or_default())
}

fn write_runtime_unlocked(paths: &Paths, runtime: &SwitchRuntime) -> Result<()> {
    let mut encoded =
        serde_json::to_vec_pretty(runtime).map_err(|e| Error::Json(e.to_string()))?;
    encoded.push(b'\n');
    atomic_write_private(&paths.runtime_file, &encoded)
}

/// Load the persisted [`SwitchRuntime`] from `paths.runtime_file` under an exclusive lock.
pub fn load_runtime(paths: &Paths) -> Result<SwitchRuntime> {
    if !eko::file::exists(&paths.config_dir) && !eko::file::exists(&paths.runtime_file) {
        return Ok(SwitchRuntime::default());
    }
    let _guard = acquire_exclusive_lock(&runtime_lock_path(paths))?;
    read_runtime_unlocked(paths)
}

/// Persist `runtime` atomically (`0600`) to `paths.runtime_file` under an exclusive lock.
pub fn save_runtime(paths: &Paths, runtime: &SwitchRuntime) -> Result<()> {
    let _guard = acquire_exclusive_lock(&runtime_lock_path(paths))?;
    write_runtime_unlocked(paths, runtime)
}

/// Clear `restart_agy_needed` and reset transient switch state after the operator restarts `agy`.
pub fn ack_restart(paths: &Paths) -> Result<SwitchRuntime> {
    let _guard = acquire_exclusive_lock(&runtime_lock_path(paths))?;
    let mut runtime = read_runtime_unlocked(paths)?;
    runtime.restart_agy_needed = false;
    if runtime.state == SwitchRuntimeState::Ready {
        runtime.state = SwitchRuntimeState::Idle;
    }
    write_runtime_unlocked(paths, &runtime)?;
    Ok(runtime)
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    if n.len() > h.len() {
        return false;
    }
    let limit = h.len() - n.len();
    let mut i = 0;
    while i <= limit {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return true;
        }
        i += 1;
    }
    false
}

/// Parse a human reset hint such as `"Resets in 2h 15m 10s"` or `"45m"` into whole seconds.
pub fn parse_reset_duration_secs(text: &str) -> Option<u64> {
    let scope = if let Some(idx) = find_ascii_ci(text, "resets in") {
        &text[idx + "resets in".len()..]
    } else {
        text
    };
    let bytes = scope.as_bytes();
    let mut i = 0;
    let mut total: u64 = 0;
    let mut matched = false;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b',') {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            if matched {
                break;
            }
            i += 1;
            continue;
        }
        let Ok(num_str) = core::str::from_utf8(&bytes[start..i]) else {
            break;
        };
        let Ok(val) = num_str.parse::<u64>() else {
            break;
        };
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        if i == unit_start {
            break;
        }
        let unit = &scope[unit_start..i];
        let mult = if unit.eq_ignore_ascii_case("d")
            || unit.eq_ignore_ascii_case("day")
            || unit.eq_ignore_ascii_case("days")
        {
            86_400
        } else if unit.eq_ignore_ascii_case("h")
            || unit.eq_ignore_ascii_case("hr")
            || unit.eq_ignore_ascii_case("hrs")
            || unit.eq_ignore_ascii_case("hour")
            || unit.eq_ignore_ascii_case("hours")
        {
            3_600
        } else if unit.eq_ignore_ascii_case("m")
            || unit.eq_ignore_ascii_case("min")
            || unit.eq_ignore_ascii_case("mins")
            || unit.eq_ignore_ascii_case("minute")
            || unit.eq_ignore_ascii_case("minutes")
        {
            60
        } else if unit.eq_ignore_ascii_case("s")
            || unit.eq_ignore_ascii_case("sec")
            || unit.eq_ignore_ascii_case("secs")
            || unit.eq_ignore_ascii_case("second")
            || unit.eq_ignore_ascii_case("seconds")
        {
            1
        } else {
            if matched {
                break;
            }
            continue;
        };
        total = total.saturating_add(val.saturating_mul(mult));
        matched = true;
    }

    if matched && total > 0 {
        Some(total)
    } else {
        None
    }
}

fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return None;
    }
    let limit = h.len() - n.len();
    let mut i = 0;
    while i <= limit {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn infer_family_from_line(line: &str) -> Option<ModelFamily> {
    if contains_ascii_case_insensitive(line, "argon") {
        Some(ModelFamily::Argon)
    } else if contains_ascii_case_insensitive(line, "claude")
        || contains_ascii_case_insensitive(line, "sonnet")
        || contains_ascii_case_insensitive(line, "opus")
        || contains_ascii_case_insensitive(line, "haiku")
    {
        Some(ModelFamily::Claude)
    } else if contains_ascii_case_insensitive(line, "gpt-")
        || contains_ascii_case_insensitive(line, "gpt_")
        || contains_ascii_case_insensitive(line, "openai")
    {
        Some(ModelFamily::Gpt)
    } else if contains_ascii_case_insensitive(line, "gemini") {
        Some(ModelFamily::Gemini)
    } else {
        None
    }
}

fn extract_email_hint(line: &str) -> Option<String> {
    for token in line.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';')
    }) {
        let trimmed = token.trim_matches(':');
        if let Some(at) = trimmed.find('@') {
            let local = &trimmed[..at];
            let domain = &trimmed[at + 1..];
            if !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && trimmed.len() <= 254
            {
                return Some(trimmed.to_ascii_lowercase());
            }
        }
    }
    None
}

/// Parse a single log line for Antigravity individual or weekly quota exhaustion signatures.
pub fn parse_quota_log_line(line: &str) -> Option<LogQuotaEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let has_resource_exhausted = contains_ascii_case_insensitive(trimmed, "RESOURCE_EXHAUSTED");
    let has_individual = contains_ascii_case_insensitive(trimmed, "Individual quota reached");
    let has_weekly = contains_ascii_case_insensitive(trimmed, "Weekly quota reached")
        || contains_ascii_case_insensitive(trimmed, "weekly limit reached")
        || (has_resource_exhausted
            && contains_ascii_case_insensitive(trimmed, "weekly")
            && contains_ascii_case_insensitive(trimmed, "quota"));
    let has_429_quota = has_resource_exhausted
        && (contains_ascii_case_insensitive(trimmed, "code 429")
            || contains_ascii_case_insensitive(trimmed, "quota reached")
            || contains_ascii_case_insensitive(trimmed, "Resets in"));

    let kind = if has_weekly {
        "weekly_quota_exhausted"
    } else if has_individual || has_429_quota {
        "individual_quota_exhausted"
    } else {
        return None;
    };

    Some(LogQuotaEvent {
        kind: kind.to_string(),
        path: String::new(),
        family: infer_family_from_line(trimmed),
        reset_secs: parse_reset_duration_secs(trimmed),
        email_hint: extract_email_hint(trimmed),
        line: trimmed.to_string(),
    })
}

fn collect_watched_log_files(paths: &Paths) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push_unique = |candidate: String| {
        if !candidate.is_empty() && !out.iter().any(|p| p == &candidate) {
            out.push(candidate);
        }
    };

    let dirs = [
        paths.agy_log_dir.clone(),
        format!("{}/antigravity-cli/log", paths.gemini_dir),
        format!("{}/.gemini/antigravity-cli/log", paths.home),
    ];
    for dir in &dirs {
        if dir.trim().is_empty() || !eko::file::exists(dir) {
            continue;
        }
        if let Ok(meta) = eko::file::metadata(dir) {
            if meta.is_file() {
                push_unique(dir.clone());
                continue;
            }
            if meta.is_dir() {
                if let Ok(entries) = eko::fs::read_dir(dir) {
                    let mut names: Vec<String> = entries
                        .into_iter()
                        .filter_map(|p| p.to_str().map(ToString::to_string))
                        .filter(|p| p.ends_with(".log"))
                        .collect();
                    names.sort();
                    for name in names {
                        push_unique(name);
                    }
                }
            }
        }
    }

    let direct_files = [
        format!("{}/antigravity-cli/cli.log", paths.gemini_dir),
        format!("{}/.gemini/antigravity-cli/cli.log", paths.home),
    ];
    for fpath in &direct_files {
        if !fpath.trim().is_empty() && eko::file::exists(fpath) {
            if let Ok(meta) = eko::file::metadata(fpath) {
                if meta.is_file() {
                    push_unique(fpath.clone());
                }
            }
        }
    }

    out
}

fn load_tail_cursors_unlocked(paths: &Paths) -> TailCursorStore {
    let cpath = cursor_store_path(paths);
    if !eko::file::exists(&cpath) {
        return TailCursorStore::default();
    }
    let Ok(raw) = eko::file::read_to_string(&cpath) else {
        return TailCursorStore::default();
    };
    serde_json::from_str::<TailCursorStore>(&raw).unwrap_or_default()
}

fn save_tail_cursors_unlocked(paths: &Paths, cursors: &TailCursorStore) -> Result<()> {
    let cpath = cursor_store_path(paths);
    let mut encoded =
        serde_json::to_vec_pretty(cursors).map_err(|e| Error::Json(e.to_string()))?;
    encoded.push(b'\n');
    atomic_write_private(&cpath, &encoded)
}

/// Seed log tail cursors at current EOF across all existing CLI logs so historical errors are skipped.
pub fn init_log_cursors_at_eof(paths: &Paths) -> Result<()> {
    let _guard = acquire_exclusive_lock(&runtime_lock_path(paths))?;
    let mut cursors = load_tail_cursors_unlocked(paths);
    for log_path in collect_watched_log_files(paths) {
        if let Ok(meta) = eko::file::metadata(&log_path) {
            cursors.offsets.insert(log_path, meta.len());
        }
    }
    cursors.initialized = true;
    save_tail_cursors_unlocked(paths, &cursors)
}

/// Scan recent CLI logs for unexpired 429 reset hints and apply cooldowns to matching accounts.
pub fn scan_log_cooldowns(paths: &Paths, accounts: &mut Accounts, now_unix: i64) -> usize {
    let mut updated = 0usize;
    for log_path in collect_watched_log_files(paths) {
        let Ok(mut file) = File::open(&log_path) else {
            continue;
        };
        let Ok(len) = file.len() else {
            continue;
        };
        let Ok(meta) = file.metadata() else {
            continue;
        };
        let mtime = meta.modified_secs();
        if now_unix.saturating_sub(mtime) > 7 * 86_400 {
            continue;
        }
        let start = len.saturating_sub(MAX_TAIL_STEP_BYTES as u64);
        if start > 0 && file.seek(start).is_err() {
            continue;
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            continue;
        }
        let text = String::from_utf8_lossy(&buf);
        for line in text.lines() {
            let Some(ev) = parse_quota_log_line(line) else {
                continue;
            };
            let Some(ref email_hint) = ev.email_hint else {
                continue;
            };
            let reset_delta = ev
                .reset_secs
                .map(|s| s.min(7 * 86_400) as i64)
                .unwrap_or(DEFAULT_FAILOVER_COOLDOWN_SECS);
            let until_unix = mtime.saturating_add(reset_delta);
            if until_unix <= now_unix {
                continue;
            }
            if let Some(acc) = accounts.get_mut(email_hint) {
                let key = cooldown_key_for_family(ev.family);
                let prev = acc.cooldowns.get(&key).copied().unwrap_or(0);
                if until_unix > prev {
                    acc.cooldowns.insert(key, until_unix);
                    updated += 1;
                }
            }
        }
    }
    updated
}

fn cooldown_key_for_family(family: Option<ModelFamily>) -> String {
    match family {
        Some(ModelFamily::Gemini) => "gemini".to_string(),
        Some(ModelFamily::Claude) => "claude".to_string(),
        Some(ModelFamily::Gpt) => "gpt".to_string(),
        Some(ModelFamily::Argon) => "argon".to_string(),
        None => "all".to_string(),
    }
}

fn extract_pool_policy_from_settings(store: &Store) -> PoolFailoverPolicy {
    let Ok(settings) = store.load_settings() else {
        return PoolFailoverPolicy::default();
    };
    let Ok(val) = serde_json::to_value(&settings) else {
        return PoolFailoverPolicy::default();
    };
    for field in [
        "pool_failover",
        "pool_failover_policy",
        "failover_policy",
        "quota_policy",
    ] {
        if let Some(sub) = val.get(field) {
            if let Ok(parsed) = serde_json::from_value::<PoolFailoverPolicy>(sub.clone()) {
                return parsed;
            }
        }
    }
    PoolFailoverPolicy::default()
}

fn append_failover_history(store: &Store, email: &str, reason: &str, now_unix: i64) {
    let payload = serde_json::json!({
        "schema": 1,
        "at": format!("{}", now_unix),
        "at_unix": now_unix,
        "timestamp_unix": now_unix,
        "timestamp": now_unix,
        "ts_unix": now_unix,
        "kind": "failover",
        "email": email,
        "detail": reason,
        "message": reason,
    });
    if let Ok(entry) = serde_json::from_value::<HistoryEntry>(payload) {
        let _ = store.append_history(&entry);
    }
}

/// Coordinate an idempotent failover rotation after a quota or rate-limit failure.
#[allow(clippy::too_many_arguments)]
pub fn rotate_after_failure(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    switch_mode: SwitchMode,
    reason: &str,
    family: Option<ModelFamily>,
    cooldown_secs: i64,
    dedupe_secs: i64,
    force_switch: bool,
    now_unix: i64,
) -> Result<FailoverResult> {
    let _guard = acquire_exclusive_lock(&runtime_lock_path(paths))?;
    let mut runtime = read_runtime_unlocked(paths)?;

    if dedupe_secs > 0
        && runtime.state == SwitchRuntimeState::Ready
        && runtime.last_switch_unix > 0
        && now_unix >= runtime.last_switch_unix
        && (now_unix - runtime.last_switch_unix) <= dedupe_secs
    {
        return Ok(FailoverResult {
            outcome: "already_switched".to_string(),
            previous: session
                .current_email()
                .or_else(|| runtime.active_email.clone()),
            switched_to: runtime.active_email.clone(),
            restart_needed: runtime.restart_agy_needed,
        });
    }

    runtime.state = SwitchRuntimeState::Switching;
    runtime.last_trigger = Some(reason.to_string());
    let _ = write_runtime_unlocked(paths, &runtime);

    let mut accounts = store.load()?;
    let previous_email = session
        .current_email()
        .or_else(|| runtime.active_email.clone());

    let effective_cooldown = if cooldown_secs > 0 {
        cooldown_secs
    } else {
        DEFAULT_FAILOVER_COOLDOWN_SECS
    };

    if let Some(ref prev) = previous_email {
        let resolved_prev = accounts
            .resolve(prev)
            .map(ToString::to_string)
            .unwrap_or_else(|| prev.clone());
        if let Some(acc) = accounts.get_mut(&resolved_prev) {
            acc.cooldowns.insert(
                cooldown_key_for_family(family),
                now_unix.saturating_add(effective_cooldown),
            );
            acc.last_error = Some(reason.to_string());
        }
        store.save(&mut accounts)?;
    }

    let pool_policy = extract_pool_policy_from_settings(store);
    let threshold_pct = if pool_policy.enabled {
        pool_policy.threshold_pct
    } else {
        10
    };

    let mut chosen: Option<(String, String)> = None;
    let mut cursor = previous_email.clone();
    let max_attempts = accounts.len().max(1);
    for _ in 0..max_attempts {
        let Some(candidate_email) = select_next(
            &accounts,
            cursor.as_deref(),
            family,
            RankingPolicy::RoundRobin,
            threshold_pct,
            now_unix,
        ) else {
            break;
        };
        if previous_email
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case(&candidate_email))
            .unwrap_or(false)
        {
            break;
        }
        if let Some(acc) = accounts.get(&candidate_email) {
            let pool_ok = if pool_policy.enabled && !pool_policy.checked_pools.is_empty() {
                evaluate_pool_failover(acc, &pool_policy, now_unix).replacement_usable
            } else {
                true
            };
            if pool_ok {
                if let Some((_, token)) = lookup_account_secret(vault, acc)? {
                    chosen = Some((acc.email.clone(), token));
                    break;
                }
            }
        }
        cursor = Some(candidate_email);
    }

    let Some((target_email, token)) = chosen else {
        runtime.state = SwitchRuntimeState::NoAccount;
        runtime.active_email = previous_email.clone();
        write_runtime_unlocked(paths, &runtime)?;
        return Ok(FailoverResult {
            outcome: "no_account".to_string(),
            previous: previous_email,
            switched_to: None,
            restart_needed: false,
        });
    };

    if switch_mode == SwitchMode::Auto || force_switch {
        session.switch_to(&target_email, &token)?;
        runtime.state = SwitchRuntimeState::Ready;
        runtime.active_email = Some(target_email.clone());
        runtime.last_switch_unix = now_unix;
        runtime.last_trigger = Some(reason.to_string());
        runtime.restart_agy_needed = true;
        write_runtime_unlocked(paths, &runtime)?;
        append_failover_history(store, &target_email, reason, now_unix);
        Ok(FailoverResult {
            outcome: "switched".to_string(),
            previous: previous_email,
            switched_to: Some(target_email),
            restart_needed: true,
        })
    } else {
        runtime.state = SwitchRuntimeState::Idle;
        runtime.active_email = previous_email.clone();
        write_runtime_unlocked(paths, &runtime)?;
        Ok(FailoverResult {
            outcome: "switch_required".to_string(),
            previous: previous_email,
            switched_to: Some(target_email),
            restart_needed: false,
        })
    }
}

/// Poll watched Antigravity CLI log files once from their persisted byte offsets.
pub fn poll_logs_once(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    switch_mode: SwitchMode,
    force_switch: bool,
    now_unix: i64,
) -> Result<Option<FailoverResult>> {
    let files = collect_watched_log_files(paths);
    let mut detected_event: Option<LogQuotaEvent> = None;
    let mut saw_new_session_log = false;

    {
        let _guard = acquire_exclusive_lock(&runtime_lock_path(paths))?;
        let mut cursors = load_tail_cursors_unlocked(paths);
        if !cursors.initialized {
            for fpath in &files {
                if let Ok(meta) = eko::file::metadata(fpath) {
                    cursors.offsets.insert(fpath.clone(), meta.len());
                }
            }
            cursors.initialized = true;
            save_tail_cursors_unlocked(paths, &cursors)?;
            return Ok(None);
        }

        for fpath in &files {
            let Ok(mut file) = File::open(fpath) else {
                continue;
            };
            let Ok(file_len) = file.len() else {
                continue;
            };
            let known_before = cursors.offsets.contains_key(fpath);
            if !known_before && fpath.ends_with(".log") && !fpath.ends_with("/cli.log") {
                saw_new_session_log = true;
            }
            let mut offset = cursors.offsets.get(fpath).copied().unwrap_or(0);
            if file_len < offset {
                offset = 0;
            }
            if file_len == offset {
                cursors.offsets.insert(fpath.clone(), offset);
                continue;
            }
            if file_len.saturating_sub(offset) > MAX_TAIL_STEP_BYTES as u64 {
                offset = file_len.saturating_sub(MAX_TAIL_STEP_BYTES as u64);
            }
            if file.seek(offset).is_err() {
                continue;
            }
            let mut chunk = Vec::new();
            if file.read_to_end(&mut chunk).is_err() {
                continue;
            }
            let complete_len = match chunk.iter().rposition(|b| *b == b'\n') {
                Some(idx) => idx + 1,
                None => continue,
            };
            let consumed_slice = &chunk[..complete_len];
            let new_offset = offset.saturating_add(complete_len as u64);
            cursors.offsets.insert(fpath.clone(), new_offset);

            let text = String::from_utf8_lossy(consumed_slice);
            for line in text.lines() {
                if let Some(mut ev) = parse_quota_log_line(line) {
                    ev.path = fpath.clone();
                    detected_event = Some(ev);
                }
            }
        }

        save_tail_cursors_unlocked(paths, &cursors)?;
        if saw_new_session_log && detected_event.is_none() {
            let mut runtime = read_runtime_unlocked(paths)?;
            if runtime.restart_agy_needed {
                runtime.restart_agy_needed = false;
                if runtime.state == SwitchRuntimeState::Ready {
                    runtime.state = SwitchRuntimeState::Idle;
                }
                let _ = write_runtime_unlocked(paths, &runtime);
            }
        }
    }

    let Some(ev) = detected_event else {
        return Ok(None);
    };

    let cooldown_secs = ev
        .reset_secs
        .map(|s| s.min(7 * 86_400) as i64)
        .unwrap_or(DEFAULT_FAILOVER_COOLDOWN_SECS);

    let res = rotate_after_failure(
        paths,
        store,
        vault,
        session,
        switch_mode,
        &ev.kind,
        ev.family,
        cooldown_secs,
        DEFAULT_FAILOVER_DEDUPE_SECS,
        force_switch,
        now_unix,
    )?;
    Ok(Some(res))
}
