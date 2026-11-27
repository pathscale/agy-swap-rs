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
use core::fmt;
use core::str::FromStr;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::paths::{parse_rfc3339_unix, wall_unix_secs};
use crate::{Error, Result};

pub fn normalize_email(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_ascii_lowercase();
    let (local, domain) = cleaned.split_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || cleaned.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some(cleaned)
}

pub fn clean_text(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c == ' ' || c == '\t' || !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFamily {
    Gemini,
    Claude,
    Gpt,
    Argon,
}

impl ModelFamily {
    pub const ALL: [ModelFamily; 4] = [Self::Gemini, Self::Claude, Self::Gpt, Self::Argon];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gemini => "gemini",
            Self::Claude => "claude",
            Self::Gpt => "gpt",
            Self::Argon => "argon",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Gemini => "Gemini",
            Self::Claude => "Claude",
            Self::Gpt => "GPT",
            Self::Argon => "Argon",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "gemini" => Some(Self::Gemini),
            "claude" | "claude_gpt" | "claude-gpt" | "claude/gpt" | "other" | "third-party" => {
                Some(Self::Claude)
            }
            "gpt" | "openai" => Some(Self::Gpt),
            "argon" | "gemini-4-argon" => Some(Self::Argon),
            _ => None,
        }
    }

    pub fn from_model_label(label: &str) -> Option<Self> {
        let lower = label.to_ascii_lowercase();
        if lower.contains("argon") {
            Some(Self::Argon)
        } else if lower.contains("gemini") || lower.contains("flash") {
            Some(Self::Gemini)
        } else if lower.contains("claude")
            || lower.contains("anthropic")
            || lower.contains("sonnet")
            || lower.contains("opus")
        {
            Some(Self::Claude)
        } else if lower.contains("gpt") || lower.contains("openai") {
            Some(Self::Gpt)
        } else {
            None
        }
    }
}

impl fmt::Display for ModelFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ModelFamily {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::InvalidInput(format!("unknown model family: {s}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Badge {
    Ready,
    Low,
    Critical,
    GeminiOnly,
    ClaudeGptOnly,
    Limited,
    NoToken,
    Verify,
}

impl Badge {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Low => "LOW",
            Self::Critical => "CRITICAL",
            Self::GeminiOnly => "GEMINI ONLY",
            Self::ClaudeGptOnly => "CLAUDE/GPT ONLY",
            Self::Limited => "LIMITED",
            Self::NoToken => "NO TOKEN",
            Self::Verify => "VERIFY",
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.label()
    }

    pub const fn is_usable(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Low | Self::Critical | Self::GeminiOnly | Self::ClaudeGptOnly
        )
    }
}

impl fmt::Display for Badge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PoolWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_at_unix: Option<i64>,
}

impl PoolWindow {
    pub const fn new(remaining_pct: Option<f64>, reset_at_unix: Option<i64>) -> Self {
        Self {
            remaining_pct,
            reset_at_unix,
        }
    }

    pub fn is_known(&self) -> bool {
        self.remaining_pct.is_some()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PoolQuota {
    pub name: String,
    #[serde(default)]
    pub five_hour: PoolWindow,
    #[serde(default)]
    pub weekly: PoolWindow,
}

impl PoolQuota {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            five_hour: PoolWindow::default(),
            weekly: PoolWindow::default(),
        }
    }

    pub fn effective_pct(&self) -> Option<f64> {
        let sanitize = |v: f64| -> Option<f64> {
            if v.is_finite() {
                Some(v.clamp(0.0, 100.0))
            } else {
                None
            }
        };
        match (
            self.five_hour.remaining_pct.and_then(sanitize),
            self.weekly.remaining_pct.and_then(sanitize),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    pub fn next_reset_unix(&self) -> Option<i64> {
        match (self.five_hour.reset_at_unix, self.weekly.reset_at_unix) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QuotaSnapshot {
    pub fetched_at_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_tier: Option<String>,
    #[serde(default)]
    pub gemini: PoolQuota,
    #[serde(default)]
    pub claude_gpt: PoolQuota,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon: Option<PoolQuota>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_pools: Vec<PoolQuota>,
}

impl QuotaSnapshot {
    pub fn empty(fetched_at_unix: i64) -> Self {
        Self {
            fetched_at_unix,
            project_id: None,
            plan_tier: None,
            gemini: PoolQuota::new("Gemini"),
            claude_gpt: PoolQuota::new("Claude/GPT"),
            argon: None,
            extra_pools: Vec::new(),
        }
    }

    pub fn pool_by_name(&self, name: &str) -> Option<&PoolQuota> {
        let lower = name.trim().to_ascii_lowercase();
        match lower.as_str() {
            "gemini" => Some(&self.gemini),
            "claude_gpt" | "claude-gpt" | "claude/gpt" | "claude" | "gpt" | "third-party"
            | "other" => Some(&self.claude_gpt),
            "argon" | "gemini-4-argon" | "gemini 4 argon" => self.argon.as_ref(),
            _ => self
                .extra_pools
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(name.trim())),
        }
    }

    pub fn all_pools(&self) -> Vec<&PoolQuota> {
        let mut out = Vec::new();
        if self.gemini.effective_pct().is_some() || !self.gemini.name.is_empty() {
            out.push(&self.gemini);
        }
        if self.claude_gpt.effective_pct().is_some() || !self.claude_gpt.name.is_empty() {
            out.push(&self.claude_gpt);
        }
        if let Some(argon) = &self.argon {
            out.push(argon);
        }
        for extra in &self.extra_pools {
            out.push(extra);
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub email: String,
    #[serde(default = "default_account_name")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, alias = "secret_ref", skip_serializing_if = "Option::is_none")]
    pub vault_ref: Option<String>,
    #[serde(default, alias = "token_data", skip_serializing_if = "Option::is_none")]
    pub legacy_token_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cooldowns: BTreeMap<String, i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_threshold_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<QuotaSnapshot>,
}

fn default_account_name() -> String {
    "Google User".to_string()
}

impl Account {
    pub fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        let raw_email = email.into();
        let email =
            normalize_email(&raw_email).unwrap_or_else(|| raw_email.trim().to_ascii_lowercase());
        let cleaned_name = clean_text(&name.into());
        let name = if cleaned_name.is_empty() {
            default_account_name()
        } else {
            cleaned_name
        };
        Self {
            email,
            name,
            aliases: Vec::new(),
            tags: Vec::new(),
            vault_ref: None,
            legacy_token_data: None,
            verify_url: None,
            last_error: None,
            disabled: false,
            cooldowns: BTreeMap::new(),
            reserve_threshold_pct: None,
            quota: None,
        }
    }

    pub fn secret_key(&self) -> String {
        self.vault_ref
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("account:{}", self.email))
    }

    pub fn is_cooled_down(&self, family: Option<ModelFamily>, now_unix: i64) -> bool {
        let active_key = |k: &str| self.cooldowns.get(k).copied().unwrap_or(0) > now_unix;
        if active_key("all") || active_key("*") {
            return true;
        }
        match family {
            Some(fam) => {
                if active_key(fam.as_str()) {
                    return true;
                }
                if matches!(fam, ModelFamily::Claude | ModelFamily::Gpt)
                    && (active_key("claude")
                        || active_key("gpt")
                        || active_key("claude_gpt")
                        || active_key("claude-gpt")
                        || active_key("other"))
                {
                    return true;
                }
                self.cooldowns.iter().any(|(k, &until)| {
                    until > now_unix && ModelFamily::from_model_label(k) == Some(fam)
                })
            }
            None => {
                let gem = self.is_cooled_down(Some(ModelFamily::Gemini), now_unix);
                let cg = self.is_cooled_down(Some(ModelFamily::Claude), now_unix);
                gem && cg
            }
        }
    }

    pub fn family_pct(&self, family: Option<ModelFamily>) -> Option<f64> {
        let q = self.quota.as_ref()?;
        match family {
            Some(ModelFamily::Gemini) => q.gemini.effective_pct(),
            Some(ModelFamily::Claude) | Some(ModelFamily::Gpt) => q.claude_gpt.effective_pct(),
            Some(ModelFamily::Argon) => q.argon.as_ref().and_then(PoolQuota::effective_pct),
            None => match (q.gemini.effective_pct(), q.claude_gpt.effective_pct()) {
                (Some(g), Some(c)) => Some(g.min(c)),
                (Some(g), None) => Some(g),
                (None, Some(c)) => Some(c),
                (None, None) => q
                    .argon
                    .as_ref()
                    .and_then(PoolQuota::effective_pct)
                    .or_else(|| {
                        q.extra_pools
                            .iter()
                            .filter_map(PoolQuota::effective_pct)
                            .reduce(f64::min)
                    }),
            },
        }
    }

    pub fn badge(&self, has_token: bool, now_unix: i64) -> Badge {
        if self.verify_url.is_some() {
            return Badge::Verify;
        }
        let token_present = has_token
            || self
                .legacy_token_data
                .as_deref()
                .is_some_and(|t| !t.trim().is_empty());
        if !token_present {
            return Badge::NoToken;
        }
        if self.disabled || self.is_cooled_down(None, now_unix) {
            return Badge::Limited;
        }
        let gem_cooled = self.is_cooled_down(Some(ModelFamily::Gemini), now_unix);
        let cg_cooled = self.is_cooled_down(Some(ModelFamily::Claude), now_unix)
            || self.is_cooled_down(Some(ModelFamily::Gpt), now_unix);
        let classify_pct = |pct: f64| -> Badge {
            if pct <= 0.0 {
                Badge::Limited
            } else if pct <= 10.0 {
                Badge::Critical
            } else if pct <= 30.0 {
                Badge::Low
            } else {
                Badge::Ready
            }
        };
        if let Some(q) = &self.quota {
            let gem_pct = if gem_cooled {
                Some(0.0)
            } else {
                q.gemini.effective_pct()
            };
            let cg_pct = if cg_cooled {
                Some(0.0)
            } else {
                q.claude_gpt.effective_pct()
            };
            match (gem_pct, cg_pct) {
                (Some(g), Some(c)) => match (g > 0.0, c > 0.0) {
                    (false, false) => Badge::Limited,
                    (true, false) => Badge::GeminiOnly,
                    (false, true) => Badge::ClaudeGptOnly,
                    (true, true) => classify_pct(g.min(c)),
                },
                (Some(g), None) => {
                    if g <= 0.0 {
                        Badge::Limited
                    } else if cg_cooled {
                        Badge::GeminiOnly
                    } else {
                        classify_pct(g)
                    }
                }
                (None, Some(c)) => {
                    if c <= 0.0 {
                        Badge::Limited
                    } else if gem_cooled {
                        Badge::ClaudeGptOnly
                    } else {
                        classify_pct(c)
                    }
                }
                (None, None) => {
                    if cg_cooled {
                        Badge::GeminiOnly
                    } else if gem_cooled {
                        Badge::ClaudeGptOnly
                    } else if let Some(pct) = self.family_pct(None) {
                        classify_pct(pct)
                    } else {
                        Badge::Ready
                    }
                }
            }
        } else if cg_cooled {
            Badge::GeminiOnly
        } else if gem_cooled {
            Badge::ClaudeGptOnly
        } else {
            Badge::Ready
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Accounts {
    pub order: Vec<String>,
    pub by_email: BTreeMap<String, Account>,
    pub revision_ns: i64,
    pub revision_hash: String,
}

impl Accounts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Account)> {
        self.order
            .iter()
            .filter_map(|email| self.by_email.get(email).map(|acc| (email.as_str(), acc)))
    }

    pub fn get(&self, email: &str) -> Option<&Account> {
        if let Some(acc) = self.by_email.get(email) {
            return Some(acc);
        }
        let norm = normalize_email(email)?;
        self.by_email.get(&norm)
    }

    pub fn get_mut(&mut self, email: &str) -> Option<&mut Account> {
        if self.by_email.contains_key(email) {
            return self.by_email.get_mut(email);
        }
        let norm = normalize_email(email)?;
        self.by_email.get_mut(&norm)
    }

    pub fn upsert(&mut self, mut account: Account) {
        let email = normalize_email(&account.email)
            .unwrap_or_else(|| account.email.trim().to_ascii_lowercase());
        account.email = email.clone();
        if clean_text(&account.name).is_empty() {
            account.name = default_account_name();
        }
        if !self.by_email.contains_key(&email) {
            self.order.push(email.clone());
        }
        self.by_email.insert(email, account);
    }

    pub fn remove(&mut self, email: &str) -> Option<Account> {
        let target = if self.by_email.contains_key(email) {
            email.to_string()
        } else {
            normalize_email(email)?
        };
        let removed = self.by_email.remove(&target)?;
        self.order.retain(|e| e != &target);
        Some(removed)
    }

    pub fn resolve<'a>(&'a self, selector: &str) -> Option<&'a str> {
        let sel = selector.trim();
        if sel.is_empty() {
            return None;
        }
        for email in &self.order {
            if email.eq_ignore_ascii_case(sel) && self.by_email.contains_key(email) {
                return Some(email.as_str());
            }
        }
        if sel.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(slot) = sel.parse::<usize>() {
                if slot >= 1 && slot <= self.order.len() {
                    let email = &self.order[slot - 1];
                    if self.by_email.contains_key(email) {
                        return Some(email.as_str());
                    }
                }
            }
        }
        let mut alias_hit: Option<&'a str> = None;
        for email in &self.order {
            if let Some(acc) = self.by_email.get(email) {
                if acc.aliases.iter().any(|a| a.eq_ignore_ascii_case(sel)) {
                    if alias_hit.is_some() {
                        return None;
                    }
                    alias_hit = Some(email.as_str());
                }
            }
        }
        if alias_hit.is_some() {
            return alias_hit;
        }
        let mut name_hit: Option<&'a str> = None;
        for email in &self.order {
            if let Some(acc) = self.by_email.get(email) {
                if acc.name.eq_ignore_ascii_case(sel) {
                    if name_hit.is_some() {
                        return None;
                    }
                    name_hit = Some(email.as_str());
                }
            }
        }
        name_hit
    }

    pub fn resolve_with_settings<'a>(
        &'a self,
        selector: &str,
        settings: &Settings,
    ) -> Option<&'a str> {
        let mut cur = selector.trim();
        if cur.is_empty() {
            return None;
        }
        let mut hops = 0usize;
        while hops < 8 {
            if let Some(next) = settings.aliases.get(cur) {
                cur = next.as_str();
                hops += 1;
                continue;
            }
            if let Some(profile) = settings.profiles.get(cur) {
                cur = profile.primary.as_str();
                hops += 1;
                continue;
            }
            break;
        }
        self.resolve(cur)
    }

    pub fn decode_ordered_json(bytes: &[u8]) -> Result<Self> {
        let trimmed = core::str::from_utf8(bytes)
            .map_err(|_| Error::Json("accounts.json is not valid UTF-8".to_string()))?
            .trim();
        if trimmed.is_empty() {
            return Ok(Self::new());
        }
        serde_json::from_str(trimmed).map_err(Error::from)
    }

    pub fn encode_ordered_json(&self) -> Result<Vec<u8>> {
        let mut out = serde_json::to_vec_pretty(self)?;
        out.push(b'\n');
        Ok(out)
    }
}

fn convert_go_quota_snapshot(raw: &serde_json::Value) -> Option<QuotaSnapshot> {
    let obj = raw.as_object()?;
    let fetched_at_unix = obj
        .get("observed_at")
        .and_then(|v| v.as_str())
        .and_then(parse_rfc3339_unix)
        .unwrap_or(0);
    let plan_tier = obj
        .get("tier")
        .and_then(|t| t.as_object())
        .and_then(|t| t.get("name").or_else(|| t.get("id")))
        .and_then(|v| v.as_str())
        .map(clean_text)
        .filter(|s| !s.is_empty());
    let mut snap = QuotaSnapshot::empty(fetched_at_unix);
    snap.plan_tier = plan_tier;
    if let Some(groups) = obj.get("groups").and_then(|g| g.as_array()) {
        for grp in groups {
            let Some(gobj) = grp.as_object() else {
                continue;
            };
            let gid = gobj.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let gname = gobj.get("name").and_then(|v| v.as_str()).unwrap_or(gid);
            let mut pool = PoolQuota::new(clean_text(gname));
            if let Some(buckets) = gobj.get("buckets").and_then(|b| b.as_array()) {
                for bkt in buckets {
                    let Some(bobj) = bkt.as_object() else {
                        continue;
                    };
                    let win = bobj.get("window").and_then(|v| v.as_str()).unwrap_or("");
                    let pct = bobj
                        .get("remaining_fraction")
                        .and_then(|v| v.as_f64())
                        .map(|f| (f * 100.0).clamp(0.0, 100.0));
                    let reset = bobj
                        .get("reset_at")
                        .and_then(|v| v.as_str())
                        .and_then(parse_rfc3339_unix);
                    match win {
                        "5h" | "short" => pool.five_hour = PoolWindow::new(pct, reset),
                        "weekly" => pool.weekly = PoolWindow::new(pct, reset),
                        _ => {}
                    }
                }
            }
            match gid {
                "gemini" => {
                    pool.name = "Gemini".to_string();
                    snap.gemini = pool;
                }
                "third-party" | "claude_gpt" | "claude-gpt" => {
                    pool.name = "Claude/GPT".to_string();
                    snap.claude_gpt = pool;
                }
                "argon" => {
                    pool.name = "Argon".to_string();
                    snap.argon = Some(pool);
                }
                _ if !gid.is_empty() => snap.extra_pools.push(pool),
                _ => {}
            }
        }
    }
    Some(snap)
}

fn upgrade_account_from_value(
    key: &str,
    raw: serde_json::Value,
) -> core::result::Result<Account, String> {
    let obj = raw
        .as_object()
        .ok_or_else(|| "accounts.json entry must be an object".to_string())?;
    let mut acc: Account = serde_json::from_value(raw.clone()).map_err(|e| e.to_string())?;
    let raw_email = if acc.email.trim().is_empty() {
        key
    } else {
        acc.email.as_str()
    };
    let email =
        normalize_email(raw_email).ok_or_else(|| format!("invalid account email: {raw_email}"))?;
    acc.email = email;
    let cleaned_name = clean_text(&acc.name);
    acc.name = if cleaned_name.is_empty() {
        default_account_name()
    } else {
        cleaned_name
    };
    if acc.verify_url.is_none() {
        if let Some(elig) = obj.get("eligibility").and_then(|v| v.as_object()) {
            if elig.get("state").and_then(|v| v.as_str()) == Some("verify_required") {
                let url = elig
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                acc.verify_url = Some(url);
            }
        }
    }
    if acc.cooldowns.is_empty() {
        if let Some(limits) = obj.get("quota_limits").and_then(|v| v.as_object()) {
            for (lkey, lval) in limits {
                if let Some(lobj) = lval.as_object() {
                    let fam = lobj.get("family").and_then(|v| v.as_str()).unwrap_or(lkey);
                    if let Some(reset) = lobj
                        .get("reset_at")
                        .and_then(|v| v.as_str())
                        .and_then(parse_rfc3339_unix)
                    {
                        let prev = acc.cooldowns.get(fam).copied().unwrap_or(0);
                        if reset > prev {
                            acc.cooldowns.insert(fam.to_string(), reset);
                        }
                    }
                }
            }
        }
    }
    if acc.quota.is_none() {
        if let Some(go_snap) = obj.get("quota_snapshot") {
            acc.quota = convert_go_quota_snapshot(go_snap);
        }
    }
    Ok(acc)
}

impl Serialize for Accounts {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let count = self
            .order
            .iter()
            .filter(|e| self.by_email.contains_key(*e))
            .count();
        let mut map = serializer.serialize_map(Some(count))?;
        for email in &self.order {
            if let Some(acc) = self.by_email.get(email) {
                map.serialize_entry(email, acc)?;
            }
        }
        map.end()
    }
}

struct AccountsVisitor;

impl<'de> Visitor<'de> for AccountsVisitor {
    type Value = Accounts;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an ordered map of email to account records")
    }

    fn visit_map<M: MapAccess<'de>>(
        self,
        mut access: M,
    ) -> core::result::Result<Accounts, M::Error> {
        let mut accounts = Accounts::new();
        while let Some((key, val)) = access.next_entry::<String, serde_json::Value>()? {
            let acc = upgrade_account_from_value(&key, val).map_err(de::Error::custom)?;
            if accounts.by_email.contains_key(&acc.email) {
                return Err(de::Error::custom(format!(
                    "duplicate account email: {}",
                    acc.email
                )));
            }
            accounts.upsert(acc);
        }
        Ok(accounts)
    }
}

impl<'de> Deserialize<'de> for Accounts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_map(AccountsVisitor)
    }
}

fn default_settings_schema() -> u32 {
    1
}

fn default_switch_mode() -> crate::policy::SwitchMode {
    crate::policy::SwitchMode::Auto
}

fn default_ranking_policy() -> crate::policy::RankingPolicy {
    crate::policy::RankingPolicy::Sticky
}

fn default_route_strategy() -> crate::policy::RouteStrategy {
    crate::policy::RouteStrategy::SameFamilyFirst
}

fn default_min_remaining_pct() -> u8 {
    10
}

fn default_pool_failover_policy() -> crate::policy::PoolFailoverPolicy {
    crate::policy::PoolFailoverPolicy {
        enabled: true,
        match_mode: crate::policy::PoolMatchMode::Any,
        checked_pools: Vec::new(),
        threshold_pct: 10,
        max_age_secs: 1800,
    }
}

fn default_notify_threshold_pct() -> u8 {
    20
}

fn default_notify_cooldown_secs() -> u64 {
    1800
}

fn default_true() -> bool {
    true
}

fn default_history_retention_days() -> u32 {
    30
}

fn default_history_max_bytes() -> usize {
    8 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_settings_schema")]
    pub schema: u32,
    #[serde(default = "default_switch_mode")]
    pub switch_mode: crate::policy::SwitchMode,
    #[serde(default = "default_ranking_policy")]
    pub default_policy: crate::policy::RankingPolicy,
    #[serde(default = "default_route_strategy")]
    pub route_strategy: crate::policy::RouteStrategy,
    #[serde(default = "default_min_remaining_pct")]
    pub min_remaining_pct: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_family: Option<ModelFamily>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, crate::policy::Profile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<crate::policy::DirectoryBinding>,
    #[serde(default = "default_pool_failover_policy", alias = "quota_policy")]
    pub pool_failover: crate::policy::PoolFailoverPolicy,
    #[serde(default)]
    pub notifications_enabled: bool,
    #[serde(default = "default_notify_threshold_pct")]
    pub notify_threshold_pct: u8,
    #[serde(default = "default_notify_cooldown_secs")]
    pub notify_cooldown_secs: u64,
    #[serde(default = "default_true")]
    pub history_enabled: bool,
    #[serde(default = "default_history_retention_days")]
    pub history_retention_days: u32,
    #[serde(default = "default_history_max_bytes")]
    pub history_max_bytes: usize,
    #[serde(default)]
    pub split_offset: i16,
    #[serde(default)]
    pub stack_offset: i16,
    #[serde(default)]
    pub statusline_installed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statusline_command: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub targets: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema: default_settings_schema(),
            switch_mode: default_switch_mode(),
            default_policy: default_ranking_policy(),
            route_strategy: default_route_strategy(),
            min_remaining_pct: default_min_remaining_pct(),
            prefer_family: None,
            aliases: BTreeMap::new(),
            profiles: BTreeMap::new(),
            bindings: Vec::new(),
            pool_failover: default_pool_failover_policy(),
            notifications_enabled: false,
            notify_threshold_pct: default_notify_threshold_pct(),
            notify_cooldown_secs: default_notify_cooldown_secs(),
            history_enabled: default_true(),
            history_retention_days: default_history_retention_days(),
            history_max_bytes: default_history_max_bytes(),
            split_offset: 0,
            stack_offset: 0,
            statusline_installed: false,
            statusline_command: None,
            targets: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp_unix: i64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub detail: String,
}

impl HistoryEntry {
    pub fn new(
        timestamp_unix: i64,
        kind: impl Into<String>,
        email: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix,
            kind: kind.into(),
            email: email.and_then(|e| normalize_email(&e).or(Some(e))),
            detail: detail.into(),
        }
    }

    pub fn now(kind: impl Into<String>, email: Option<String>, detail: impl Into<String>) -> Self {
        Self::new(wall_unix_secs(), kind, email, detail)
    }
}
