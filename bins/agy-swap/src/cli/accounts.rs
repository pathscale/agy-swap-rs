use std::collections::BTreeMap;

use agy_core::http::HttpClient;
use agy_core::isolate::active_isolated_sessions;
use agy_core::oauth::{
    fetch_verified_email, import_current_session, login_via_isolated_agy_tty,
    login_via_pkce_loopback_with_timeout, TokenBundle,
};
use agy_core::policy::select_next;
use agy_core::quota::QuotaService;
use agy_core::{Account, Accounts, ModelFamily, PoolQuota};
use clap::ArgMatches;
use serde_json::{json, Value};

use super::{explicit_account, family_name, format_duration_secs, format_reset_countdown, opt_flag, opt_str, parse_duration_secs, parse_family, AppContext};

pub(crate) fn read_stdin_bounded(max_bytes: usize) -> Result<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::io::stdin()
        .take((max_bytes as u64) + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed to read stdin: {e}"))?;
    if buf.len() > max_bytes {
        return Err(format!("stdin input exceeds {max_bytes} byte limit"));
    }
    String::from_utf8(buf).map_err(|_| "stdin input is not valid UTF-8".to_string())
}

pub(crate) fn open_https_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("refusing to open non-HTTPS URL".to_string());
    }
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(target_os = "macos"))]
    let opener = "xdg-open";
    match eko::command::Command::new(opener).arg(url.as_bytes()).output() {
        Some(out) if out.success() => Ok(()),
        Some(out) => Err(format!("{opener} exited with status {}", out.code)),
        None => Err(format!("failed to launch {opener}")),
    }
}

fn pool_json(pool: &PoolQuota) -> Value {
    json!({
        "name": pool.name,
        "effective_pct": pool.effective_pct(),
        "next_reset_unix": pool.next_reset_unix(),
        "five_hour": {
            "remaining_pct": pool.five_hour.remaining_pct,
            "reset_at_unix": pool.five_hour.reset_at_unix,
        },
        "weekly": {
            "remaining_pct": pool.weekly.remaining_pct,
            "reset_at_unix": pool.weekly.reset_at_unix,
        },
    })
}

pub(crate) fn account_json(ctx: &AppContext, account: &Account, active_email: Option<&str>, now_unix: i64) -> Value {
    let has_tok = ctx.has_token(account);
    let badge = account.badge(has_tok, now_unix);
    let active = active_email.map(|a| a.eq_ignore_ascii_case(&account.email)).unwrap_or(false);
    let quota_val = account.quota.as_ref().map(|q| {
        let extra: Vec<Value> = q.extra_pools.iter().map(pool_json).collect();
        json!({
            "fetched_at_unix": q.fetched_at_unix,
            "project_id": q.project_id,
            "plan_tier": q.plan_tier,
            "gemini": pool_json(&q.gemini),
            "claude_gpt": pool_json(&q.claude_gpt),
            "argon": q.argon.as_ref().map(pool_json),
            "extra_pools": extra,
        })
    });
    json!({
        "email": account.email,
        "name": account.name,
        "active": active,
        "isolated_sessions": active_isolated_sessions(&ctx.paths, &account.email),
        "badge": format!("{badge:?}"),
        "has_token": has_tok,
        "disabled": account.disabled,
        "aliases": account.aliases,
        "tags": account.tags,
        "vault_ref": account.vault_ref,
        "verify_url": account.verify_url,
        "last_error": account.last_error,
        "cooldowns": account.cooldowns,
        "reserve_threshold_pct": account.reserve_threshold_pct,
        "quota": quota_val,
    })
}

pub(crate) fn refresh_accounts_live(ctx: &AppContext, accounts: &mut Accounts, force: bool) -> Vec<(String, String)> {
    let http = match HttpClient::new() {
        Ok(h) => h,
        Err(err) => return vec![("http".to_string(), err.to_string())],
    };
    let mut svc = QuotaService::new(http);
    let now_unix = agy_core::paths::wall_unix_secs();
    let results = svc.refresh_all(accounts, &ctx.vault, force, now_unix);
    let mut failures = Vec::new();
    for (email, res) in results {
        if let Err(err) = res {
            failures.push((email, err.to_string()));
        }
    }
    if !accounts.is_empty() {
        if let Err(err) = ctx.store.save(accounts) {
            failures.push(("store".to_string(), err.to_string()));
        }
    }
    failures
}

fn validate_alias_opt(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(val) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if val.len() > 64 || val.chars().any(|c| c.is_whitespace() || c == '/' || c == '\\') {
        return Err("alias must be 1-64 characters without spaces or slashes".to_string());
    }
    Ok(Some(val.to_string()))
}

fn authenticate_bundle(ctx: &AppContext, via_agy: bool, no_browser: bool) -> Result<TokenBundle, String> {
    let force_agy = via_agy
        || eko::env::var("AGY_SWAP_LOGIN_MODE")
            .map(|v| v.trim().eq_ignore_ascii_case("agy"))
            .unwrap_or(false);
    if force_agy {
        return login_via_isolated_agy_tty(&ctx.paths).map_err(|e| e.to_string());
    }
    let open_browser = !no_browser && eko::env::var("AGY_SWAP_NO_BROWSER").as_deref() != Some("1");
    let timeout = eko::env::var("AGY_SWAP_LOGIN_TIMEOUT_SECS")
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(180);
    let http = HttpClient::new().map_err(|e| e.to_string())?;
    login_via_pkce_loopback_with_timeout(&http, open_browser, timeout).map_err(|e| e.to_string())
}

fn save_onboarded_account(
    ctx: &AppContext,
    cmd_name: &str,
    bundle: TokenBundle,
    explicit_email: Option<&str>,
    explicit_name: Option<&str>,
    alias_opt: Option<String>,
) -> Result<Value, String> {
    let explicit_email = explicit_email.map(|e| e.trim().to_ascii_lowercase()).filter(|s| !s.is_empty());
    let explicit_name = explicit_name.map(|n| n.trim().to_string()).filter(|s| !s.is_empty());
    if let (Some(hint), Some(exp)) = (&bundle.email_hint, &explicit_email) {
        if !hint.eq_ignore_ascii_case(exp) {
            return Err(format!("token identity {hint} does not match --email {exp}"));
        }
    }
    let offline = eko::env::var("AGY_SWAP_OFFLINE").as_deref() == Some("1");
    let (email, resolved_name) = if !offline && bundle.email_hint.is_none() && explicit_email.is_none() {
        match HttpClient::new().and_then(|http| fetch_verified_email(&http, &bundle.access_token)) {
            Ok((em, nm)) => (em.to_ascii_lowercase(), nm),
            Err(err) => return Err(err.to_string()),
        }
    } else if let Some(em) = explicit_email.or_else(|| bundle.email_hint.clone()) {
        (em.to_ascii_lowercase(), "Google User".to_string())
    } else {
        return Err("could not determine account email from token; pass --email".to_string());
    };
    if !email.contains('@') || !email.contains('.') {
        return Err(format!("invalid account email {email:?}"));
    }
    let name = explicit_name.unwrap_or(resolved_name);
    let mut accounts = ctx.store.load().map_err(|e| e.to_string())?;
    let vault_key = format!("account:{email}");
    ctx.vault.set(&vault_key, &bundle.raw_json).map_err(|e| e.to_string())?;
    let mut account = accounts.get(&email).cloned().unwrap_or_else(|| Account {
        email: email.clone(),
        name: name.clone(),
        aliases: Vec::new(),
        tags: Vec::new(),
        vault_ref: Some(vault_key.clone()),
        legacy_token_data: None,
        verify_url: None,
        last_error: None,
        disabled: false,
        cooldowns: BTreeMap::new(),
        reserve_threshold_pct: None,
        quota: None,
    });
    account.name = name.clone();
    account.vault_ref = Some(vault_key.clone());
    account.legacy_token_data = None;
    account.verify_url = None;
    account.last_error = None;
    if let Some(ref alias) = alias_opt {
        for em in accounts.order.clone() {
            if let Some(acc) = accounts.get_mut(&em) {
                acc.aliases.retain(|a| !a.eq_ignore_ascii_case(alias));
            }
        }
        account.aliases.retain(|a| !a.eq_ignore_ascii_case(alias));
        account.aliases.push(alias.clone());
    }
    accounts.upsert(account);
    ctx.store.save(&mut accounts).map_err(|e| e.to_string())?;
    if let Some(ref alias) = alias_opt {
        let mut settings = ctx.store.load_settings().unwrap_or_default();
        settings.aliases.insert(alias.clone(), email.clone());
        let _ = ctx.store.save_settings(&settings);
    }
    let cur_email = ctx.session.current_email();
    let switched = cur_email
        .as_deref()
        .map(|e| e.eq_ignore_ascii_case(&email))
        .unwrap_or(false);
    let mut quota_fetched = false;
    if !offline {
        if let Ok(http) = HttpClient::new() {
            let mut svc = QuotaService::new(http);
            let now_unix = agy_core::paths::wall_unix_secs();
            if let Some(acc_mut) = accounts.get_mut(&email) {
                if svc.refresh_account(acc_mut, &ctx.vault, now_unix).is_ok() {
                    quota_fetched = ctx.store.save(&mut accounts).is_ok();
                }
            }
        }
    }
    ctx.record_history(cmd_name, Some(&email), "account saved to vault");
    Ok(json!({
        "email": email,
        "name": name,
        "alias": alias_opt,
        "vault_ref": vault_key,
        "active": switched,
        "quota_fetched": quota_fetched,
    }))
}

pub fn cmd_import_current(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let alias_opt = match validate_alias_opt(opt_str(m, "alias")) {
        Ok(a) => a,
        Err(err) => return ctx.fail("import-current", err),
    };
    let bundle = match import_current_session(&ctx.paths, &ctx.session) {
        Ok(b) => b,
        Err(err) => return ctx.fail("import-current", err),
    };
    let saved = match save_onboarded_account(ctx, "import-current", bundle, opt_str(m, "email"), opt_str(m, "name"), alias_opt) {
        Ok(v) => v,
        Err(err) => return ctx.fail("import-current", err),
    };
    if ctx.json {
        return ctx.ok_json("import-current", saved);
    }
    println!(
        "{}✓ Imported {} ({}){}",
        ctx.palette.green,
        saved["email"].as_str().unwrap_or(""),
        saved["name"].as_str().unwrap_or(""),
        ctx.palette.reset
    );
    0
}

pub fn cmd_login(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let base_alias = match validate_alias_opt(opt_str(m, "alias")) {
        Ok(a) => a,
        Err(err) => return ctx.fail("login", err),
    };
    let count: usize = match opt_str(m, "count") {
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(n) if (1..=20).contains(&n) => n,
            _ => return ctx.fail("login", "--count must be between 1 and 20"),
        },
        None => 1,
    };
    let via_agy = opt_flag(m, "via_agy");
    let no_browser = opt_flag(m, "no_browser");
    let mut results = Vec::with_capacity(count);
    for idx in 0..count {
        if !ctx.json && count > 1 {
            eprintln!("Signing in account {}/{count}...", idx + 1);
        }
        let iter_alias = match (&base_alias, count) {
            (Some(a), 1) => Some(a.clone()),
            (Some(a), _) => Some(format!("{a}-{}", idx + 1)),
            (None, _) => None,
        };
        let bundle = match authenticate_bundle(ctx, via_agy, no_browser) {
            Ok(b) => b,
            Err(err) => return ctx.fail("login", err),
        };
        let saved = match save_onboarded_account(ctx, "login", bundle, None, None, iter_alias) {
            Ok(v) => v,
            Err(err) => return ctx.fail("login", err),
        };
        if !ctx.json {
            println!(
                "{}✓ Signed in {} ({}){}",
                ctx.palette.green,
                saved["email"].as_str().unwrap_or(""),
                saved["name"].as_str().unwrap_or(""),
                ctx.palette.reset
            );
        }
        results.push(saved);
    }
    if ctx.json {
        if count == 1 {
            return ctx.ok_json("login", results.into_iter().next().unwrap_or(Value::Null));
        }
        return ctx.ok_json("login", json!({"count": results.len(), "accounts": results}));
    }
    0
}

pub fn cmd_add(ctx: &AppContext, m: &ArgMatches) -> i32 {
    if opt_flag(m, "import_current") {
        return cmd_import_current(ctx, m);
    }
    let alias_opt = match validate_alias_opt(opt_str(m, "alias")) {
        Ok(a) => a,
        Err(err) => return ctx.fail("add", err),
    };
    let bundle = if let Some(src) = opt_str(m, "token") {
        let raw_token = if src == "-" {
            match read_stdin_bounded(1024 * 1024) {
                Ok(s) => s,
                Err(err) => return ctx.fail("add", err),
            }
        } else if eko::fs::exists(src.as_bytes()) {
            match eko::file::read(src) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => return ctx.fail("add", "token file is not valid UTF-8"),
                },
                Err(err) => return ctx.fail("add", err),
            }
        } else {
            src.to_string()
        };
        match TokenBundle::parse(raw_token.trim()) {
            Ok(b) => b,
            Err(err) => return ctx.fail("add", err),
        }
    } else if let Some(dir) = opt_str(m, "source_dir") {
        let trimmed = dir.trim_end_matches('/');
        let primary = format!("{trimmed}/antigravity-oauth-token");
        let fallback = format!("{trimmed}/oauth_creds.json");
        let path = if eko::fs::exists(primary.as_bytes()) { primary } else { fallback };
        let raw_token = match eko::file::read(&path) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => return ctx.fail("add", "source token file is not valid UTF-8"),
            },
            Err(err) => return ctx.fail("add", err),
        };
        match TokenBundle::parse(raw_token.trim()) {
            Ok(b) => b,
            Err(err) => return ctx.fail("add", err),
        }
    } else {
        match authenticate_bundle(ctx, opt_flag(m, "via_agy"), opt_flag(m, "no_browser")) {
            Ok(b) => b,
            Err(err) => return ctx.fail("add", err),
        }
    };
    let saved = match save_onboarded_account(ctx, "add", bundle, opt_str(m, "email"), opt_str(m, "name"), alias_opt) {
        Ok(v) => v,
        Err(err) => return ctx.fail("add", err),
    };
    if ctx.json {
        return ctx.ok_json("add", saved);
    }
    println!(
        "{}✓ Added {} ({}){}",
        ctx.palette.green,
        saved["email"].as_str().unwrap_or(""),
        saved["name"].as_str().unwrap_or(""),
        ctx.palette.reset
    );
    0
}

pub fn cmd_list(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("list", err),
    };
    let family = match opt_str(m, "family").map(parse_family).transpose() {
        Ok(f) => f,
        Err(err) => return ctx.fail("list", err),
    };
    let tag_filter = opt_str(m, "tag").map(|t| t.trim().to_ascii_lowercase());
    if opt_flag(m, "refresh") {
        let _ = refresh_accounts_live(ctx, &mut accounts, true);
    }
    let active = ctx.active_email(&accounts);
    let now_unix = agy_core::paths::wall_unix_secs();
    let mut items = Vec::new();
    for (idx, email) in accounts.order.iter().enumerate() {
        let Some(acc) = accounts.get(email) else { continue };
        if let Some(tag) = &tag_filter {
            if !acc.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                continue;
            }
        }
        items.push((idx + 1, acc));
    }
    if ctx.json {
        let rows: Vec<Value> = items
            .iter()
            .map(|(_, acc)| account_json(ctx, acc, active.as_deref(), now_unix))
            .collect();
        return ctx.ok_json("list", json!({"active": active, "accounts": rows}));
    }
    if items.is_empty() {
        println!("No saved accounts. Run 'agy-swap-rs add' or 'agy-swap-rs import-current' to add one.");
        return 0;
    }
    println!("{} #   ACCOUNT                        BADGE             GEMINI               CLAUDE/GPT{}", ctx.palette.bold, ctx.palette.reset);
    for (slot, acc) in items {
        let is_active = active.as_deref().map(|a| a.eq_ignore_ascii_case(&acc.email)).unwrap_or(false);
        let marker = if is_active { "*" } else { " " };
        let iso_n = active_isolated_sessions(&ctx.paths, &acc.email);
        let acct_col = if iso_n == 1 {
            format!("{} [RUN]", acc.email)
        } else if iso_n > 1 {
            format!("{} [RUNx{iso_n}]", acc.email)
        } else {
            acc.email.clone()
        };
        let badge = ctx.palette.badge_text(acc.badge(ctx.has_token(acc), now_unix));
        let gem_pct = acc.family_pct(Some(family.unwrap_or(ModelFamily::Gemini)));
        let cg_pct = acc.family_pct(Some(ModelFamily::Claude));
        let gem_bar = ctx.palette.gauge(gem_pct, 10, ctx.ascii);
        let cg_bar = ctx.palette.gauge(cg_pct, 10, ctx.ascii);
        println!("{marker}{slot:<2}  {acct_col:<29} {:<17} {gem_bar}  {cg_bar}", badge);
    }
    0
}

pub fn cmd_limits(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("limits", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let target = match explicit_account(m, "account") {
        Some(sel) => match ctx.resolve_selector(&accounts, &settings, sel) {
            Some(em) => Some(em),
            None => return ctx.fail("limits", format!("account {sel:?} not found")),
        },
        None => None,
    };
    let failures = if opt_flag(m, "no_refresh") && !opt_flag(m, "refresh") {
        Vec::new()
    } else {
        refresh_accounts_live(ctx, &mut accounts, opt_flag(m, "refresh"))
    };
    let active = ctx.active_email(&accounts);
    let now_unix = agy_core::paths::wall_unix_secs();
    if ctx.json {
        let rows: Vec<Value> = accounts
            .order
            .iter()
            .filter(|em| target.as_deref().map(|t| t == em.as_str()).unwrap_or(true))
            .filter_map(|em| accounts.get(em))
            .map(|acc| account_json(ctx, acc, active.as_deref(), now_unix))
            .collect();
        return ctx.ok_json("limits", json!({"active": active, "accounts": rows, "errors": failures}));
    }
    for email in &accounts.order {
        if target.as_deref().map(|t| t != email.as_str()).unwrap_or(false) {
            continue;
        }
        let Some(acc) = accounts.get(email) else { continue };
        let badge = ctx.palette.badge_text(acc.badge(ctx.has_token(acc), now_unix));
        println!("{}{} [{}]{}", ctx.palette.bold, acc.email, badge, ctx.palette.reset);
        if let Some(q) = &acc.quota {
            for pool in core::iter::once(&q.gemini).chain(core::iter::once(&q.claude_gpt)).chain(q.argon.iter()).chain(q.extra_pools.iter()) {
                let b5 = ctx.palette.gauge(pool.five_hour.remaining_pct, 12, ctx.ascii);
                let bw = ctx.palette.gauge(pool.weekly.remaining_pct, 12, ctx.ascii);
                let rst = format_reset_countdown(pool.next_reset_unix(), now_unix);
                println!("  {:<16} 5h {b5}  wk {bw}  reset {rst}", pool.name);
            }
        } else {
            println!("  quota snapshot unavailable");
        }
    }
    0
}

pub fn cmd_limit(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let Some((sub, sub_m)) = m.subcommand() else {
        return ctx.fail_usage("limit", "expected 'set' or 'clear' subcommand");
    };
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("limit", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let (sel, dur_opt) = if sub == "clear" {
        let Some(s) = explicit_account(sub_m, "account").or_else(|| opt_str(m, "use_account")) else {
            return ctx.fail_usage(
                "limit clear",
                "--use-account=<slot|alias|email> or ACCOUNT argument is required",
            );
        };
        (s, None)
    } else {
        let first = opt_str(sub_m, "first");
        let second = opt_str(sub_m, "second");
        let use_acc = opt_str(sub_m, "use_account").or_else(|| opt_str(m, "use_account"));
        match (first, second, use_acc) {
            (Some(acc_sel), Some(dur), _) => (acc_sel, Some(dur)),
            (Some(dur), None, Some(acc_sel)) => (acc_sel, Some(dur)),
            _ => {
                return ctx.fail_usage(
                    "limit set",
                    "--use-account=<slot|alias|email> or ACCOUNT argument is required",
                );
            }
        }
    };
    let Some(email) = ctx.resolve_selector(&accounts, &settings, sel) else {
        return ctx.fail("limit", format!("account {sel:?} not found"));
    };
    let family = match opt_str(sub_m, "family").or_else(|| opt_str(m, "family")).map(parse_family).transpose() {
        Ok(f) => f,
        Err(err) => return ctx.fail("limit", err),
    };
    let now_unix = agy_core::paths::wall_unix_secs();
    let Some(acc) = accounts.get_mut(&email) else {
        return ctx.fail("limit", "account disappeared");
    };
    if sub == "clear" {
        if let Some(fam) = family {
            acc.cooldowns.remove(family_name(fam));
        } else {
            acc.cooldowns.clear();
            acc.last_error = None;
        }
        if let Err(err) = ctx.store.save(&mut accounts) {
            return ctx.fail("limit clear", err);
        }
        ctx.record_history("limit_clear", Some(&email), "cleared manual cooldown");
        if ctx.json {
            return ctx.ok_json("limit clear", json!({"email": email, "cleared": true}));
        }
        println!("Cleared cooldowns for {email}.");
        return 0;
    }
    let dur_raw = dur_opt.unwrap_or("0");
    let secs = match parse_duration_secs(dur_raw) {
        Ok(s) => s,
        Err(err) => return ctx.fail("limit set", err),
    };
    let key = family_name(family.unwrap_or(ModelFamily::Claude)).to_string();
    if secs <= 0 {
        acc.cooldowns.remove(&key);
    } else {
        acc.cooldowns.insert(key.clone(), now_unix + secs);
    }
    if let Err(err) = ctx.store.save(&mut accounts) {
        return ctx.fail("limit set", err);
    }
    ctx.record_history("limit_set", Some(&email), &format!("{key}:{secs}s"));
    if ctx.json {
        return ctx.ok_json("limit set", json!({"email": email, "family": key, "reset_at_unix": now_unix + secs}));
    }
    println!("Set {key} cooldown on {email} for {}.", format_duration_secs(secs));
    0
}

pub fn switch_by_selector(ctx: &AppContext, selector: &str, force: bool) -> i32 {
    let accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("switch", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let Some(email) = ctx.resolve_selector(&accounts, &settings, selector) else {
        return ctx.fail("switch", format!("account {selector:?} not found"));
    };
    let Some(acc) = accounts.get(&email) else {
        return ctx.fail("switch", "account missing");
    };
    if acc.disabled && !force {
        return ctx.fail("switch", format!("account {email} is disabled; pass --force to switch anyway"));
    }
    let token = match ctx.account_token(acc) {
        Ok(t) => t,
        Err(err) => return ctx.fail("switch", err),
    };
    let previous = ctx.active_email(&accounts);
    if let Err(err) = ctx.session.switch_to(&email, &token) {
        return ctx.fail("switch", err);
    }
    ctx.record_history("switch", Some(&email), previous.as_deref().unwrap_or("none"));
    if ctx.json {
        return ctx.ok_json("switch", json!({"previous": previous, "active": email}));
    }
    println!("{}✓ Switched active session to {email}{}", ctx.palette.green, ctx.palette.reset);
    0
}

pub fn cmd_switch(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let Some(sel) = explicit_account(m, "account") else {
        return ctx.fail_usage(
            "switch",
            "--use-account=<slot|alias|email> or ACCOUNT argument is required",
        );
    };
    switch_by_selector(ctx, sel, opt_flag(m, "force"))
}

pub fn cmd_next(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("next", err),
    };
    if opt_flag(m, "refresh") {
        let _ = refresh_accounts_live(ctx, &mut accounts, true);
    }
    let family = match opt_str(m, "family").map(parse_family).transpose() {
        Ok(f) => f,
        Err(err) => return ctx.fail("next", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let active = ctx.active_email(&accounts);
    let now_unix = agy_core::paths::wall_unix_secs();
    let Some(next_email) = select_next(&accounts, active.as_deref(), family, settings.default_policy, settings.min_remaining_pct, now_unix) else {
        return ctx.fail("next", "no eligible standby account available");
    };
    let Some(acc) = accounts.get(&next_email) else {
        return ctx.fail("next", "selected account missing");
    };
    let token = match ctx.account_token(acc) {
        Ok(t) => t,
        Err(err) => return ctx.fail("next", err),
    };
    if let Err(err) = ctx.session.switch_to(&next_email, &token) {
        return ctx.fail("next", err);
    }
    ctx.record_history("rotate", Some(&next_email), active.as_deref().unwrap_or("none"));
    if ctx.json {
        return ctx.ok_json("next", json!({"previous": active, "active": next_email}));
    }
    println!("{}✓ Rotated active session to {next_email}{}", ctx.palette.green, ctx.palette.reset);
    0
}

pub fn remove_by_selector(ctx: &AppContext, selector: &str, force: bool) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("remove", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let Some(email) = ctx.resolve_selector(&accounts, &settings, selector) else {
        return ctx.fail("remove", format!("account {selector:?} not found"));
    };
    let active = ctx.active_email(&accounts);
    if active.as_deref().map(|a| a.eq_ignore_ascii_case(&email)).unwrap_or(false) && !force {
        return ctx.fail("remove", format!("{email} is currently active; pass --force to remove it"));
    }
    let Some(removed) = accounts.remove(&email) else {
        return ctx.fail("remove", "account not found");
    };
    if let Err(err) = ctx.store.save(&mut accounts) {
        return ctx.fail("remove", err);
    }
    let key = AppContext::vault_key_for(&removed);
    let _ = ctx.vault.delete(&key);
    ctx.record_history("remove", Some(&email), "removed account and vault entry");
    if ctx.json {
        return ctx.ok_json("remove", json!({"removed": email}));
    }
    println!("Removed {email}.");
    0
}

pub fn cmd_remove(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let Some(sel) = explicit_account(m, "account") else {
        return ctx.fail_usage(
            "remove",
            "--use-account=<slot|alias|email> or ACCOUNT argument is required",
        );
    };
    remove_by_selector(ctx, sel, opt_flag(m, "force"))
}

pub fn cmd_status(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("status", err),
    };
    if opt_flag(m, "refresh") {
        let _ = refresh_accounts_live(ctx, &mut accounts, true);
    }
    let active = ctx.active_email(&accounts);
    let target_email = if let Some(sel) = opt_str(m, "use_account") {
        let settings = ctx.store.load_settings().unwrap_or_default();
        let Some(em) = ctx.resolve_selector(&accounts, &settings, sel) else {
            return ctx.fail("status", format!("account {sel:?} not found"));
        };
        Some(em)
    } else {
        active.clone()
    };
    let now_unix = agy_core::paths::wall_unix_secs();
    let runtime_val: Option<Value> = eko::file::read(&ctx.paths.runtime_file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let active_acc = target_email.as_deref().and_then(|em| accounts.get(em));
    if ctx.json {
        return ctx.ok_json(
            "status",
            json!({
                "active": active,
                "account_count": accounts.len(),
                "active_account": active_acc.map(|a| account_json(ctx, a, active.as_deref(), now_unix)),
                "switch_runtime": runtime_val,
            }),
        );
    }
    let Some(em) = target_email else {
        println!("Active session: none ({} saved accounts)", accounts.len());
        return 0;
    };
    println!("{}Active:{} {em}", ctx.palette.bold, ctx.palette.reset);
    if let Some(acc) = active_acc {
        let badge = ctx.palette.badge_text(acc.badge(ctx.has_token(acc), now_unix));
        let gem = ctx.palette.gauge(acc.family_pct(Some(ModelFamily::Gemini)), 12, ctx.ascii);
        let cg = ctx.palette.gauge(acc.family_pct(Some(ModelFamily::Claude)), 12, ctx.ascii);
        println!("Status: {badge}  Gemini {gem}  Claude/GPT {cg}");
    }
    if runtime_val.as_ref().and_then(|v| v.get("restart_agy_needed")).and_then(Value::as_bool) == Some(true) {
        println!("{}! Restart agy CLI to pick up switched credentials (then run 'agy-swap-rs ack-restart'){}", ctx.palette.yellow, ctx.palette.reset);
    }
    0
}

pub fn cmd_logout(ctx: &AppContext) -> i32 {
    if let Err(err) = ctx.session.logout() {
        return ctx.fail("logout", err);
    }
    ctx.record_history("logout", None, "cleared active session");
    if ctx.json {
        return ctx.ok_json("logout", json!({"logged_out": true}));
    }
    println!("Logged out active Antigravity session.");
    0
}

pub fn cmd_verify(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("verify", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let now_unix = agy_core::paths::wall_unix_secs();
    if let Some(sel) = explicit_account(m, "account") {
        let Some(email) = ctx.resolve_selector(&accounts, &settings, sel) else {
            return ctx.fail("verify", format!("account {sel:?} not found"));
        };
        let Some(acc) = accounts.get(&email) else {
            return ctx.fail("verify", "account missing");
        };
        if let Some(url) = &acc.verify_url {
            if opt_flag(m, "open") {
                if let Err(err) = open_https_url(url) {
                    return ctx.fail("verify", err);
                }
            }
        }
        let has_tok = ctx.has_token(acc);
        if ctx.json {
            return ctx.ok_json("verify", json!({"email": email, "has_token": has_tok, "verify_url": acc.verify_url}));
        }
        println!("{email}: token={} verify_url={}", has_tok, acc.verify_url.as_deref().unwrap_or("none"));
        return 0;
    }
    if !opt_flag(m, "all") {
        return ctx.fail_usage(
            "verify",
            "--use-account=<slot|alias|email> or ACCOUNT argument is required (or pass --all)",
        );
    }
    let mut report = Vec::new();
    for email in &accounts.order {
        let Some(acc) = accounts.get(email) else { continue };
        let has_tok = ctx.has_token(acc);
        let badge = acc.badge(has_tok, now_unix);
        report.push(json!({
            "email": email,
            "has_token": has_tok,
            "disabled": acc.disabled,
            "verify_url": acc.verify_url,
            "badge": format!("{badge:?}"),
        }));
        if !ctx.json {
            println!("{email:<30} token={:<5} status={badge:?}", has_tok);
        }
    }
    if ctx.json {
        return ctx.ok_json("verify", json!({"accounts": report}));
    }
    0
}

pub fn cmd_account(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("list", m));
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("account", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let active = ctx.active_email(&accounts);
    let now_unix = agy_core::paths::wall_unix_secs();
    match sub {
        "list" => cmd_list(ctx, sub_m),
        "show" => {
            let Some(sel) = explicit_account(sub_m, "account").or_else(|| opt_str(m, "use_account")) else {
                return ctx.fail_usage(
                    "account show",
                    "--use-account=<slot|alias|email> or ACCOUNT argument is required",
                );
            };
            let Some(email) = ctx.resolve_selector(&accounts, &settings, sel) else {
                return ctx.fail("account show", format!("account {sel:?} not found"));
            };
            let Some(acc) = accounts.get(&email) else {
                return ctx.fail("account show", "account missing");
            };
            let val = account_json(ctx, acc, active.as_deref(), now_unix);
            if ctx.json {
                return ctx.ok_json("account show", val);
            }
            println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            0
        }
        "migrate" => {
            if !opt_flag(sub_m, "force") && !opt_flag(m, "force") {
                return ctx.fail("account migrate", "migration updates token storage; rerun with --force");
            }
            let count = match ctx.vault.migrate_legacy(&mut accounts) {
                Ok(c) => c,
                Err(err) => return ctx.fail("account migrate", err),
            };
            if let Err(err) = ctx.store.save(&mut accounts) {
                return ctx.fail("account migrate", err);
            }
            if ctx.json {
                return ctx.ok_json("account migrate", json!({"migrated": count}));
            }
            println!("Migrated {count} account secret(s) into vault.");
            0
        }
        "enable" | "disable" => {
            let Some(sel) = explicit_account(sub_m, "account").or_else(|| opt_str(m, "use_account")) else {
                return ctx.fail_usage(
                    "account",
                    "--use-account=<slot|alias|email> or ACCOUNT argument is required",
                );
            };
            let Some(email) = ctx.resolve_selector(&accounts, &settings, sel) else {
                return ctx.fail("account", format!("account {sel:?} not found"));
            };
            let disable = sub == "disable";
            if let Some(acc) = accounts.get_mut(&email) {
                acc.disabled = disable;
            }
            if let Err(err) = ctx.store.save(&mut accounts) {
                return ctx.fail("account", err);
            }
            if ctx.json {
                return ctx.ok_json(&format!("account {sub}"), json!({"email": email, "disabled": disable}));
            }
            println!("Account {email} {}.", if disable { "disabled" } else { "enabled" });
            0
        }
        _ => ctx.fail("account", format!("unknown subcommand {sub:?}")),
    }
}
