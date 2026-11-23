//! Account ranking, profile routing, directory bindings, and dynamic pool failover policy.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    Account, Accounts, Error, ModelFamily, PoolQuota, PoolWindow, QuotaSnapshot, Result,
    SessionManager, Vault,
};

/// Default freshness horizon in seconds for ranking quota snapshots.
pub const DEFAULT_FRESH_QUOTA_SECS: i64 = 1800;

/// Account selection strategy when multiple accounts are eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RankingPolicy {
    /// Keep the active or primary account while it remains healthy.
    Sticky,
    /// Pick the candidate with the highest remaining quota percentage.
    Balanced,
    /// Rotate deterministically after the active account in slot order.
    #[serde(alias = "round_robin", alias = "roundrobin")]
    RoundRobin,
}

impl Default for RankingPolicy {
    fn default() -> Self {
        Self::Sticky
    }
}

impl RankingPolicy {
    /// Canonical kebab-case representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sticky => "sticky",
            Self::Balanced => "balanced",
            Self::RoundRobin => "round-robin",
        }
    }

    /// Parse a policy name case-insensitively.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("sticky") {
            Some(Self::Sticky)
        } else if trimmed.eq_ignore_ascii_case("balanced") {
            Some(Self::Balanced)
        } else if trimmed.eq_ignore_ascii_case("round-robin")
            || trimmed.eq_ignore_ascii_case("round_robin")
            || trimmed.eq_ignore_ascii_case("roundrobin")
        {
            Some(Self::RoundRobin)
        } else {
            None
        }
    }
}

impl fmt::Display for RankingPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RankingPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| {
            Error::InvalidInput(format!(
                "invalid ranking policy '{}': expected sticky, balanced, or round-robin",
                s.trim()
            ))
        })
    }
}

/// Enforcement behavior when a directory binding matches the working directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindMode {
    /// Print or report the recommended account without switching.
    Recommend,
    /// Prompt the operator before switching.
    Prompt,
    /// Automatically switch the active session before launching.
    Auto,
}

impl Default for BindMode {
    fn default() -> Self {
        Self::Prompt
    }
}

impl BindMode {
    /// Canonical lowercase representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recommend => "recommend",
            Self::Prompt => "prompt",
            Self::Auto => "auto",
        }
    }

    /// Parse a bind mode case-insensitively.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("recommend") {
            Some(Self::Recommend)
        } else if trimmed.eq_ignore_ascii_case("prompt") {
            Some(Self::Prompt)
        } else if trimmed.eq_ignore_ascii_case("auto") {
            Some(Self::Auto)
        } else {
            None
        }
    }
}

impl fmt::Display for BindMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BindMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| {
            Error::InvalidInput(format!(
                "invalid bind mode '{}': expected recommend, prompt, or auto",
                s.trim()
            ))
        })
    }
}

/// Global or command-level session failover mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwitchMode {
    /// Report recommended switches without rewriting active session files.
    Manual,
    /// Automatically switch active session credentials on failover.
    Auto,
}

impl Default for SwitchMode {
    fn default() -> Self {
        Self::Manual
    }
}

impl SwitchMode {
    /// Canonical lowercase representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Auto => "auto",
        }
    }

    /// Parse a switch mode case-insensitively.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("manual") {
            Some(Self::Manual)
        } else if trimmed.eq_ignore_ascii_case("auto") {
            Some(Self::Auto)
        } else {
            None
        }
    }
}

impl fmt::Display for SwitchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SwitchMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| {
            Error::InvalidInput(format!(
                "invalid switch mode '{}': expected manual or auto",
                s.trim()
            ))
        })
    }
}

/// Combinator for multi-pool failover evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoolMatchMode {
    /// Fail over when any checked pool is exhausted; replacement must have all checked pools available.
    #[serde(alias = "ANY")]
    Any,
    /// Fail over only when all checked pools are exhausted; replacement needs any checked pool available.
    #[serde(alias = "ALL")]
    All,
}

impl Default for PoolMatchMode {
    fn default() -> Self {
        Self::Any
    }
}

impl PoolMatchMode {
    /// Canonical lowercase representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::All => "all",
        }
    }

    /// Parse `any` or `all` case-insensitively.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("any") {
            Some(Self::Any)
        } else if trimmed.eq_ignore_ascii_case("all") {
            Some(Self::All)
        } else {
            None
        }
    }
}

impl fmt::Display for PoolMatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PoolMatchMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| {
            Error::InvalidInput(format!(
                "invalid pool match mode '{}': expected any or all",
                s.trim()
            ))
        })
    }
}

/// Cross-account and cross-family route resolution preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteStrategy {
    /// Prefer switching accounts to preserve the requested model family before falling back to another family.
    #[serde(alias = "same_family_first")]
    SameFamilyFirst,
    /// Prefer falling back to another model family on the active account before switching accounts.
    #[serde(alias = "same_account_first")]
    SameAccountFirst,
    /// Never substitute another model family; switch accounts or report `no_route`.
    #[serde(alias = "strict_family")]
    StrictFamily,
}

impl Default for RouteStrategy {
    fn default() -> Self {
        Self::SameFamilyFirst
    }
}

impl RouteStrategy {
    /// Canonical kebab-case representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SameFamilyFirst => "same-family-first",
            Self::SameAccountFirst => "same-account-first",
            Self::StrictFamily => "strict-family",
        }
    }

    /// Parse a route strategy case-insensitively.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("same-family-first")
            || trimmed.eq_ignore_ascii_case("same_family_first")
        {
            Some(Self::SameFamilyFirst)
        } else if trimmed.eq_ignore_ascii_case("same-account-first")
            || trimmed.eq_ignore_ascii_case("same_account_first")
        {
            Some(Self::SameAccountFirst)
        } else if trimmed.eq_ignore_ascii_case("strict-family")
            || trimmed.eq_ignore_ascii_case("strict_family")
        {
            Some(Self::StrictFamily)
        } else {
            None
        }
    }
}

impl fmt::Display for RouteStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RouteStrategy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| {
            Error::InvalidInput(format!(
                "invalid route strategy '{}': expected same-family-first, same-account-first, or strict-family",
                s.trim()
            ))
        })
    }
}

/// Named routing profile with a primary account, optional model family, and ordered reserves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub primary: String,
    #[serde(default)]
    pub family: Option<ModelFamily>,
    #[serde(default)]
    pub policy: RankingPolicy,
    #[serde(default)]
    pub reserves: Vec<String>,
    #[serde(default = "default_threshold_pct")]
    pub threshold_pct: u8,
}

const fn default_threshold_pct() -> u8 {
    10
}

const fn default_max_age_secs() -> u64 {
    1800
}

/// Workspace directory prefix bound to a named routing profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryBinding {
    pub path: String,
    pub profile: String,
    #[serde(default)]
    pub mode: BindMode,
}

/// Dynamic pool-aware failover policy inspired by `agy-cli-manager`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolFailoverPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub match_mode: PoolMatchMode,
    #[serde(default)]
    pub checked_pools: Vec<String>,
    #[serde(default = "default_threshold_pct")]
    pub threshold_pct: u8,
    #[serde(default = "default_max_age_secs")]
    pub max_age_secs: u64,
}

impl Default for PoolFailoverPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            match_mode: PoolMatchMode::Any,
            checked_pools: Vec::new(),
            threshold_pct: default_threshold_pct(),
            max_age_secs: default_max_age_secs(),
        }
    }
}

/// Tri-state health of a single named pool under [`PoolFailoverPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoolState {
    /// Cached snapshot is fresh and remaining quota exceeds the configured threshold.
    Available,
    /// Cached snapshot is fresh and remaining quota is at or below the configured threshold.
    Exhausted,
    /// Snapshot is missing, stale, or lacks an unexpired window for this pool.
    Unknown,
}

/// Result of evaluating an account's cached quota snapshot against [`PoolFailoverPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolFailoverEval {
    pub pools: BTreeMap<String, PoolState>,
    pub snapshot_fresh: bool,
    pub failover_triggered: bool,
    pub replacement_usable: bool,
}

/// Ranked account recommendation and full candidate breakdown `(email, score_pct, eligible)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub selected_email: Option<String>,
    pub reason: String,
    pub candidates: Vec<(String, f64, bool)>,
}

/// Outcome of resolving a model-family route across active and standby accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub outcome: String,
    pub active_email: Option<String>,
    pub recommended_email: Option<String>,
    pub selected_family: ModelFamily,
    pub switched: bool,
}

/// Collect all known pool names discovered across `accounts` in deterministic order.
pub fn discover_pool_names(accounts: &Accounts) -> Vec<String> {
    let mut names = vec!["gemini".to_string(), "claude_gpt".to_string()];
    for email in &accounts.order {
        let Some(acc) = accounts.get(email) else {
            continue;
        };
        let Some(ref snap) = acc.quota else {
            continue;
        };
        if snap.argon.is_some() && !names.iter().any(|n| n.eq_ignore_ascii_case("argon")) {
            names.push("argon".to_string());
        }
        for extra in &snap.extra_pools {
            let trimmed = extra.name.trim();
            if !trimmed.is_empty() && !names.iter().any(|n| n.eq_ignore_ascii_case(trimmed)) {
                names.push(trimmed.to_string());
            }
        }
    }
    names
}

fn window_fresh_pct(win: &PoolWindow, fetched_at_unix: i64, now_unix: i64) -> Option<f64> {
    let pct = win.remaining_pct?;
    if !pct.is_finite() {
        return None;
    }
    if let Some(reset_at) = win.reset_at_unix {
        if reset_at <= now_unix && fetched_at_unix < reset_at {
            // Window already reset after the snapshot was taken; cached exhaustion is stale.
            return None;
        }
    }
    Some(pct.clamp(0.0, 100.0))
}

fn pool_fresh_effective_pct(pool: &PoolQuota, fetched_at_unix: i64, now_unix: i64) -> Option<f64> {
    let five = window_fresh_pct(&pool.five_hour, fetched_at_unix, now_unix);
    let week = window_fresh_pct(&pool.weekly, fetched_at_unix, now_unix);
    match (five, week) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn find_named_pool<'a>(snap: &'a QuotaSnapshot, query: &str) -> Option<&'a PoolQuota> {
    let q = query.trim();
    if q.eq_ignore_ascii_case("gemini") || snap.gemini.name.eq_ignore_ascii_case(q) {
        return Some(&snap.gemini);
    }
    if q.eq_ignore_ascii_case("claude_gpt")
        || q.eq_ignore_ascii_case("claude-gpt")
        || q.eq_ignore_ascii_case("claude/gpt")
        || q.eq_ignore_ascii_case("claude")
        || q.eq_ignore_ascii_case("gpt")
        || snap.claude_gpt.name.eq_ignore_ascii_case(q)
    {
        return Some(&snap.claude_gpt);
    }
    if q.eq_ignore_ascii_case("argon") || q.eq_ignore_ascii_case("gemini-4-argon") {
        return snap.argon.as_ref();
    }
    if let Some(ref argon) = snap.argon {
        if argon.name.eq_ignore_ascii_case(q) {
            return Some(argon);
        }
    }
    snap.extra_pools.iter().find(|p| p.name.eq_ignore_ascii_case(q))
}

/// Evaluate an account's cached quota pools under `ANY` vs `ALL` semantics.
///
/// Stale or missing snapshots yield [`PoolState::Unknown`] and never count as proving
/// either exhaustion or replacement availability.
pub fn evaluate_pool_failover(
    account: &Account,
    policy: &PoolFailoverPolicy,
    now_unix: i64,
) -> PoolFailoverEval {
    let mut pools = BTreeMap::new();
    if !policy.enabled || policy.checked_pools.is_empty() {
        return PoolFailoverEval {
            pools,
            snapshot_fresh: account.quota.is_some(),
            failover_triggered: false,
            replacement_usable: true,
        };
    }

    let Some(ref snap) = account.quota else {
        for name in &policy.checked_pools {
            pools.insert(name.clone(), PoolState::Unknown);
        }
        return PoolFailoverEval {
            pools,
            snapshot_fresh: false,
            failover_triggered: false,
            replacement_usable: false,
        };
    };

    let age_secs = if now_unix > snap.fetched_at_unix {
        (now_unix - snap.fetched_at_unix) as u64
    } else {
        0
    };
    let snapshot_fresh = policy.max_age_secs == 0 || age_secs <= policy.max_age_secs;

    for name in &policy.checked_pools {
        let state = if !snapshot_fresh {
            PoolState::Unknown
        } else if let Some(pool) = find_named_pool(snap, name) {
            match pool_fresh_effective_pct(pool, snap.fetched_at_unix, now_unix) {
                Some(pct) if pct <= f64::from(policy.threshold_pct) => PoolState::Exhausted,
                Some(_) => PoolState::Available,
                None => PoolState::Unknown,
            }
        } else {
            PoolState::Unknown
        };
        pools.insert(name.clone(), state);
    }

    let (failover_triggered, replacement_usable) = match policy.match_mode {
        PoolMatchMode::Any => {
            let triggered = pools.values().any(|s| *s == PoolState::Exhausted);
            let usable = pools.values().all(|s| *s == PoolState::Available);
            (triggered, usable)
        }
        PoolMatchMode::All => {
            let triggered = !pools.is_empty() && pools.values().all(|s| *s == PoolState::Exhausted);
            let usable = pools.values().any(|s| *s == PoolState::Available);
            (triggered, usable)
        }
    };

    PoolFailoverEval {
        pools,
        snapshot_fresh,
        failover_triggered,
        replacement_usable,
    }
}

fn effective_account_threshold(
    account: &Account,
    base_threshold_pct: u8,
    profile: Option<&Profile>,
) -> u8 {
    let mut pct = base_threshold_pct;
    if let Some(prof) = profile {
        if prof.threshold_pct > pct {
            pct = prof.threshold_pct;
        }
    }
    if let Some(acc_reserve) = account.reserve_threshold_pct {
        if acc_reserve > pct {
            pct = acc_reserve;
        }
    }
    pct.min(100)
}

fn account_fresh_score(
    account: &Account,
    family: Option<ModelFamily>,
    now_unix: i64,
) -> Option<f64> {
    let snap = account.quota.as_ref()?;
    let age = now_unix.saturating_sub(snap.fetched_at_unix);
    if age > DEFAULT_FRESH_QUOTA_SECS {
        return None;
    }
    match family {
        Some(ModelFamily::Gemini) => {
            pool_fresh_effective_pct(&snap.gemini, snap.fetched_at_unix, now_unix)
        }
        Some(ModelFamily::Claude) | Some(ModelFamily::Gpt) => {
            pool_fresh_effective_pct(&snap.claude_gpt, snap.fetched_at_unix, now_unix)
        }
        Some(ModelFamily::Argon) => snap
            .argon
            .as_ref()
            .and_then(|p| pool_fresh_effective_pct(p, snap.fetched_at_unix, now_unix)),
        None => {
            let gem = pool_fresh_effective_pct(&snap.gemini, snap.fetched_at_unix, now_unix);
            let cg = pool_fresh_effective_pct(&snap.claude_gpt, snap.fetched_at_unix, now_unix);
            match (gem, cg) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => account.family_pct(None),
            }
        }
    }
}

fn evaluate_candidate(
    account: &Account,
    family: Option<ModelFamily>,
    threshold_pct: u8,
    profile: Option<&Profile>,
    now_unix: i64,
) -> (f64, bool, bool) {
    if account.disabled || account.verify_url.is_some() || account.is_cooled_down(family, now_unix) {
        return (0.0, false, false);
    }
    let req_pct = f64::from(effective_account_threshold(account, threshold_pct, profile));
    if let Some(pct) = account_fresh_score(account, family, now_unix) {
        let ok = if req_pct <= 0.0 { pct > 0.0 } else { pct > req_pct };
        (pct, ok, true)
    } else if let Some(pct) = account.family_pct(family) {
        let ok = if req_pct <= 0.0 { pct > 0.0 } else { pct > req_pct };
        (pct, false, ok)
    } else {
        (50.0, false, true)
    }
}

/// Rank accounts and recommend the best target under `policy` and optional `profile`.
pub fn recommend(
    accounts: &Accounts,
    active_email: Option<&str>,
    family: Option<ModelFamily>,
    policy: RankingPolicy,
    threshold_pct: u8,
    profile: Option<&Profile>,
    now_unix: i64,
) -> Recommendation {
    let effective_family = family.or_else(|| profile.and_then(|p| p.family));
    let effective_policy = profile.map(|p| p.policy).unwrap_or(policy);

    if accounts.is_empty() {
        return Recommendation {
            selected_email: None,
            reason: "no accounts configured".to_string(),
            candidates: Vec::new(),
        };
    }

    let mut candidates = Vec::with_capacity(accounts.len());
    let mut fresh_eligible: Vec<(String, f64)> = Vec::new();
    let mut fallback_uncooled: Vec<String> = Vec::new();

    for email in &accounts.order {
        let Some(acc) = accounts.get(email) else {
            continue;
        };
        let (score, is_fresh_ok, can_fallback) =
            evaluate_candidate(acc, effective_family, threshold_pct, profile, now_unix);
        candidates.push((email.clone(), score, is_fresh_ok));
        if is_fresh_ok {
            fresh_eligible.push((email.clone(), score));
        } else if can_fallback {
            fallback_uncooled.push(email.clone());
        }
    }

    if let Some(prof) = profile {
        if fresh_eligible
            .iter()
            .any(|(e, _)| e.eq_ignore_ascii_case(&prof.primary))
        {
            let chosen = accounts
                .resolve(&prof.primary)
                .map(ToString::to_string)
                .unwrap_or_else(|| prof.primary.clone());
            return Recommendation {
                selected_email: Some(chosen),
                reason: format!("profile '{}' primary account is healthy", prof.name),
                candidates,
            };
        }
        for reserve in &prof.reserves {
            if let Some((matched, _)) = fresh_eligible
                .iter()
                .find(|(e, _)| e.eq_ignore_ascii_case(reserve))
            {
                return Recommendation {
                    selected_email: Some(matched.clone()),
                    reason: format!("profile '{}' reserve failover", prof.name),
                    candidates,
                };
            }
        }
    }

    if !fresh_eligible.is_empty() {
        match effective_policy {
            RankingPolicy::Sticky => {
                if let Some(active) = active_email {
                    if let Some((matched, _)) = fresh_eligible
                        .iter()
                        .find(|(e, _)| e.eq_ignore_ascii_case(active))
                    {
                        return Recommendation {
                            selected_email: Some(matched.clone()),
                            reason: "sticky policy kept healthy active account".to_string(),
                            candidates,
                        };
                    }
                }
                let mut best = fresh_eligible[0].clone();
                for item in &fresh_eligible[1..] {
                    if item.1 > best.1 {
                        best = item.clone();
                    }
                }
                return Recommendation {
                    selected_email: Some(best.0),
                    reason: "sticky policy switched to highest remaining quota".to_string(),
                    candidates,
                };
            }
            RankingPolicy::Balanced => {
                let mut best = fresh_eligible[0].clone();
                for item in &fresh_eligible[1..] {
                    if item.1 > best.1 {
                        best = item.clone();
                    }
                }
                return Recommendation {
                    selected_email: Some(best.0),
                    reason: "balanced policy selected highest remaining quota".to_string(),
                    candidates,
                };
            }
            RankingPolicy::RoundRobin => {
                let chosen = pick_round_robin(&accounts.order, &fresh_eligible, active_email);
                return Recommendation {
                    selected_email: Some(chosen),
                    reason: "round-robin policy selected next eligible slot".to_string(),
                    candidates,
                };
            }
        }
    }

    if !fallback_uncooled.is_empty() {
        if let Some(prof) = profile {
            if let Some(found) = fallback_uncooled
                .iter()
                .find(|e| e.eq_ignore_ascii_case(&prof.primary))
            {
                return Recommendation {
                    selected_email: Some(found.clone()),
                    reason: format!("profile '{}' primary selected (quota unverified)", prof.name),
                    candidates,
                };
            }
        }
        if effective_policy == RankingPolicy::Sticky {
            if let Some(active) = active_email {
                if let Some(found) = fallback_uncooled
                    .iter()
                    .find(|e| e.eq_ignore_ascii_case(active))
                {
                    return Recommendation {
                        selected_email: Some(found.clone()),
                        reason: "active account retained (quota unverified)".to_string(),
                        candidates,
                    };
                }
            }
        }
        let pairs: Vec<(String, f64)> = fallback_uncooled
            .iter()
            .map(|e| (e.clone(), 50.0))
            .collect();
        let chosen = pick_round_robin(&accounts.order, &pairs, active_email);
        return Recommendation {
            selected_email: Some(chosen),
            reason: "fallback to uncooled standby (quota unverified)".to_string(),
            candidates,
        };
    }

    Recommendation {
        selected_email: None,
        reason: "all accounts are exhausted, cooling down, disabled, or awaiting verification"
            .to_string(),
        candidates,
    }
}

fn pick_round_robin(
    order: &[String],
    eligible: &[(String, f64)],
    active_email: Option<&str>,
) -> String {
    if let Some(active) = active_email {
        if let Some(pos) = order.iter().position(|e| e.eq_ignore_ascii_case(active)) {
            let total = order.len();
            for step in 1..=total {
                let candidate = &order[(pos + step) % total];
                if let Some((matched, _)) = eligible
                    .iter()
                    .find(|(e, _)| e.eq_ignore_ascii_case(candidate))
                {
                    return matched.clone();
                }
            }
        }
    }
    eligible[0].0.clone()
}

/// Select the next account for explicit rotation (`agy-swap next` or failover).
pub fn select_next(
    accounts: &Accounts,
    active_email: Option<&str>,
    family: Option<ModelFamily>,
    policy: RankingPolicy,
    threshold_pct: u8,
    now_unix: i64,
) -> Option<String> {
    if accounts.is_empty() {
        return None;
    }

    let mut fresh_other: Vec<(String, f64)> = Vec::new();
    let mut fresh_active: Option<String> = None;
    let mut fallback_other: Vec<(String, f64)> = Vec::new();
    let mut fallback_active: Option<String> = None;

    for email in &accounts.order {
        let Some(acc) = accounts.get(email) else {
            continue;
        };
        let (score, is_fresh_ok, can_fallback) =
            evaluate_candidate(acc, family, threshold_pct, None, now_unix);
        let is_active = active_email
            .map(|a| a.eq_ignore_ascii_case(email))
            .unwrap_or(false);
        if is_fresh_ok {
            if is_active {
                fresh_active = Some(email.clone());
            } else {
                fresh_other.push((email.clone(), score));
            }
        } else if can_fallback {
            if is_active {
                fallback_active = Some(email.clone());
            } else {
                fallback_other.push((email.clone(), score));
            }
        }
    }

    if !fresh_other.is_empty() {
        return match policy {
            RankingPolicy::Balanced => {
                let mut best = fresh_other[0].clone();
                for item in &fresh_other[1..] {
                    if item.1 > best.1 {
                        best = item.clone();
                    }
                }
                Some(best.0)
            }
            RankingPolicy::Sticky | RankingPolicy::RoundRobin => {
                Some(pick_round_robin(&accounts.order, &fresh_other, active_email))
            }
        };
    }

    if !fallback_other.is_empty() {
        return Some(pick_round_robin(
            &accounts.order,
            &fallback_other,
            active_email,
        ));
    }

    fresh_active.or(fallback_active)
}

pub(crate) fn lookup_account_secret(
    vault: &Vault,
    account: &Account,
) -> Result<Option<(String, String)>> {
    if let Some(ref vref) = account.vault_ref {
        let trimmed = vref.trim();
        if !trimmed.is_empty() {
            if let Some(secret) = vault.get(trimmed)? {
                if !secret.trim().is_empty() {
                    return Ok(Some((trimmed.to_string(), secret)));
                }
            }
        }
    }
    let prefixed = format!("account:{}", account.email.trim().to_ascii_lowercase());
    if let Some(secret) = vault.get(&prefixed)? {
        if !secret.trim().is_empty() {
            return Ok(Some((prefixed, secret)));
        }
    }
    let raw_email = account.email.trim();
    if !raw_email.is_empty() {
        if let Some(secret) = vault.get(raw_email)? {
            if !secret.trim().is_empty() {
                return Ok(Some((raw_email.to_string(), secret)));
            }
        }
        let lower = raw_email.to_ascii_lowercase();
        if lower != raw_email {
            if let Some(secret) = vault.get(&lower)? {
                if !secret.trim().is_empty() {
                    return Ok(Some((lower, secret)));
                }
            }
        }
    }
    if let Some(ref legacy) = account.legacy_token_data {
        if !legacy.trim().is_empty() {
            return Ok(Some((prefixed, legacy.clone())));
        }
    }
    Ok(None)
}

fn family_fallback_chain(preferred: ModelFamily) -> [ModelFamily; 4] {
    match preferred {
        ModelFamily::Claude => [
            ModelFamily::Claude,
            ModelFamily::Gpt,
            ModelFamily::Gemini,
            ModelFamily::Argon,
        ],
        ModelFamily::Gpt => [
            ModelFamily::Gpt,
            ModelFamily::Claude,
            ModelFamily::Gemini,
            ModelFamily::Argon,
        ],
        ModelFamily::Gemini => [
            ModelFamily::Gemini,
            ModelFamily::Claude,
            ModelFamily::Gpt,
            ModelFamily::Argon,
        ],
        ModelFamily::Argon => [
            ModelFamily::Argon,
            ModelFamily::Gemini,
            ModelFamily::Claude,
            ModelFamily::Gpt,
        ],
    }
}

fn account_usable_for_route(
    account: &Account,
    vault: &Vault,
    family: ModelFamily,
    threshold_pct: u8,
    now_unix: i64,
) -> Result<Option<(f64, bool, String)>> {
    let Some((_, token)) = lookup_account_secret(vault, account)? else {
        return Ok(None);
    };
    let (score, is_fresh_ok, can_fallback) =
        evaluate_candidate(account, Some(family), threshold_pct, None, now_unix);
    if is_fresh_ok {
        Ok(Some((score, true, token)))
    } else if can_fallback {
        Ok(Some((score, false, token)))
    } else {
        Ok(None)
    }
}

fn best_standby_for_family(
    accounts: &Accounts,
    vault: &Vault,
    active_email: Option<&str>,
    family: ModelFamily,
    threshold_pct: u8,
    now_unix: i64,
) -> Result<Option<(String, String)>> {
    let mut best_fresh: Option<(String, f64, String)> = None;
    let mut first_fallback: Option<(String, String)> = None;

    for email in &accounts.order {
        if active_email
            .map(|a| a.eq_ignore_ascii_case(email))
            .unwrap_or(false)
        {
            continue;
        }
        let Some(acc) = accounts.get(email) else {
            continue;
        };
        let Some((score, is_fresh, token)) =
            account_usable_for_route(acc, vault, family, threshold_pct, now_unix)?
        else {
            continue;
        };
        if is_fresh {
            match best_fresh {
                Some((_, best_score, _)) if score <= best_score => {}
                _ => best_fresh = Some((email.clone(), score, token)),
            }
        } else if first_fallback.is_none() {
            first_fallback = Some((email.clone(), token));
        }
    }

    if let Some((email, _, token)) = best_fresh {
        Ok(Some((email, token)))
    } else {
        Ok(first_fallback)
    }
}

/// Resolve the best `(account, family)` route and optionally apply session switching.
#[allow(clippy::too_many_arguments)]
pub fn resolve_route(
    accounts: &Accounts,
    vault: &Vault,
    session: &SessionManager,
    preferred_family: ModelFamily,
    strategy: RouteStrategy,
    switch_mode: SwitchMode,
    threshold_pct: u8,
    force_switch: bool,
    now_unix: i64,
) -> Result<RouteDecision> {
    let current_active = session.current_email();
    let active_ref = current_active.as_deref();

    if !force_switch {
        if let Some(active) = active_ref {
            if let Some(acc) = accounts.get(active) {
                if account_usable_for_route(acc, vault, preferred_family, threshold_pct, now_unix)?
                    .is_some()
                {
                    return Ok(RouteDecision {
                        outcome: "active_ready".to_string(),
                        active_email: Some(acc.email.clone()),
                        recommended_email: Some(acc.email.clone()),
                        selected_family: preferred_family,
                        switched: false,
                    });
                }
            }
        }
    }

    let chain = family_fallback_chain(preferred_family);
    let can_switch = switch_mode == SwitchMode::Auto || force_switch;

    let apply_standby = |target_email: String,
                         token: String,
                         fam: ModelFamily,
                         switched_outcome: &str|
     -> Result<RouteDecision> {
        if can_switch {
            session.switch_to(&target_email, &token)?;
            Ok(RouteDecision {
                outcome: switched_outcome.to_string(),
                active_email: Some(target_email.clone()),
                recommended_email: Some(target_email),
                selected_family: fam,
                switched: true,
            })
        } else {
            Ok(RouteDecision {
                outcome: "switch_required".to_string(),
                active_email: current_active.clone(),
                recommended_email: Some(target_email),
                selected_family: fam,
                switched: false,
            })
        }
    };

    match strategy {
        RouteStrategy::StrictFamily => {
            if let Some((target_email, token)) = best_standby_for_family(
                accounts,
                vault,
                active_ref,
                preferred_family,
                threshold_pct,
                now_unix,
            )? {
                return apply_standby(target_email, token, preferred_family, "account_switch");
            }
        }
        RouteStrategy::SameAccountFirst => {
            if !force_switch {
                if let Some(active) = active_ref {
                    if let Some(acc) = accounts.get(active) {
                        for &alt_family in &chain[1..] {
                            if account_usable_for_route(
                                acc,
                                vault,
                                alt_family,
                                threshold_pct,
                                now_unix,
                            )?
                            .is_some()
                            {
                                return Ok(RouteDecision {
                                    outcome: "family_fallback".to_string(),
                                    active_email: Some(acc.email.clone()),
                                    recommended_email: Some(acc.email.clone()),
                                    selected_family: alt_family,
                                    switched: false,
                                });
                            }
                        }
                    }
                }
            }
            if let Some((target_email, token)) = best_standby_for_family(
                accounts,
                vault,
                active_ref,
                preferred_family,
                threshold_pct,
                now_unix,
            )? {
                return apply_standby(target_email, token, preferred_family, "account_switch");
            }
            for &alt_family in &chain[1..] {
                if let Some((target_email, token)) = best_standby_for_family(
                    accounts,
                    vault,
                    active_ref,
                    alt_family,
                    threshold_pct,
                    now_unix,
                )? {
                    return apply_standby(
                        target_email,
                        token,
                        alt_family,
                        "account_and_family_fallback",
                    );
                }
            }
        }
        RouteStrategy::SameFamilyFirst => {
            if let Some((target_email, token)) = best_standby_for_family(
                accounts,
                vault,
                active_ref,
                preferred_family,
                threshold_pct,
                now_unix,
            )? {
                return apply_standby(target_email, token, preferred_family, "account_switch");
            }
            if !force_switch {
                if let Some(active) = active_ref {
                    if let Some(acc) = accounts.get(active) {
                        for &alt_family in &chain[1..] {
                            if account_usable_for_route(
                                acc,
                                vault,
                                alt_family,
                                threshold_pct,
                                now_unix,
                            )?
                            .is_some()
                            {
                                return Ok(RouteDecision {
                                    outcome: "family_fallback".to_string(),
                                    active_email: Some(acc.email.clone()),
                                    recommended_email: Some(acc.email.clone()),
                                    selected_family: alt_family,
                                    switched: false,
                                });
                            }
                        }
                    }
                }
            }
            for &alt_family in &chain[1..] {
                if let Some((target_email, token)) = best_standby_for_family(
                    accounts,
                    vault,
                    active_ref,
                    alt_family,
                    threshold_pct,
                    now_unix,
                )? {
                    return apply_standby(
                        target_email,
                        token,
                        alt_family,
                        "account_and_family_fallback",
                    );
                }
            }
        }
    }

    Ok(RouteDecision {
        outcome: "no_route".to_string(),
        active_email: current_active,
        recommended_email: None,
        selected_family: preferred_family,
        switched: false,
    })
}

fn normalize_dir_components(path: &str) -> Vec<&str> {
    path.trim()
        .split(['/', '\\'])
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .collect()
}

/// Match the most specific [`DirectoryBinding`] whose path is an ancestor or exact match of `dir`.
pub fn match_binding_for_dir<'a>(
    bindings: &'a [DirectoryBinding],
    dir: &str,
) -> Option<&'a DirectoryBinding> {
    let target_parts = normalize_dir_components(dir);
    let target_is_abs = dir.trim_start().starts_with('/');
    let mut best: Option<(&'a DirectoryBinding, usize)> = None;

    for binding in bindings {
        let bind_trimmed = binding.path.trim();
        if bind_trimmed.is_empty() {
            continue;
        }
        let bind_is_abs = bind_trimmed.starts_with('/');
        if bind_is_abs != target_is_abs {
            continue;
        }
        let bind_parts = normalize_dir_components(bind_trimmed);
        if bind_parts.len() > target_parts.len() {
            continue;
        }
        let prefix_ok = bind_parts
            .iter()
            .zip(target_parts.iter())
            .all(|(a, b)| a == b);
        if prefix_ok {
            let depth = bind_parts.len();
            match best {
                Some((_, best_depth)) if depth <= best_depth => {}
                _ => best = Some((binding, depth)),
            }
        }
    }

    best.map(|(b, _)| b)
}
