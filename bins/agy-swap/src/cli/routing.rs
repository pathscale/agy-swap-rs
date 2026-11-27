use agy_core::logwatch::{rotate_after_failure, DEFAULT_FAILOVER_DEDUPE_SECS};
use agy_core::policy::{
    discover_pool_names, evaluate_pool_failover, match_binding_for_dir, recommend, resolve_route,
    select_next, BindMode, DirectoryBinding, PoolMatchMode, Profile, RankingPolicy, RouteStrategy,
    SwitchMode,
};
use agy_core::ModelFamily;
use clap::ArgMatches;
use serde_json::{json, Value};

use super::accounts::refresh_accounts_live;
use super::{family_name, opt_flag, opt_str, parse_family, AppContext};

fn validate_identifier(raw: &str, label: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        return Err(format!(
            "{label} must be 1-64 characters without spaces or slashes"
        ));
    }
    Ok(trimmed.to_string())
}

fn current_working_dir() -> String {
    eko::env::current_dir()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| ".".to_string())
}

pub fn cmd_alias(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("list", m));
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("alias", err),
    };
    let mut settings = match ctx.store.load_settings() {
        Ok(s) => s,
        Err(err) => return ctx.fail("alias", err),
    };
    match sub {
        "set" => {
            let alias = match validate_identifier(opt_str(sub_m, "alias").unwrap_or(""), "alias") {
                Ok(a) => a,
                Err(err) => return ctx.fail("alias set", err),
            };
            let sel = opt_str(sub_m, "account").unwrap_or("");
            let Some(email) = ctx.resolve_selector(&accounts, &settings, sel) else {
                return ctx.fail("alias set", format!("account {sel:?} not found"));
            };
            settings.aliases.insert(alias.clone(), email.clone());
            for em in accounts.order.clone() {
                if let Some(acc) = accounts.get_mut(&em) {
                    acc.aliases.retain(|a| !a.eq_ignore_ascii_case(&alias));
                    if em.eq_ignore_ascii_case(&email) {
                        acc.aliases.push(alias.clone());
                    }
                }
            }
            if let Err(err) = ctx.store.save(&mut accounts) {
                return ctx.fail("alias set", err);
            }
            if let Err(err) = ctx.store.save_settings(&settings) {
                return ctx.fail("alias set", err);
            }
            if ctx.json {
                return ctx.ok_json("alias set", json!({"alias": alias, "email": email}));
            }
            println!("{alias} -> {email}");
            0
        }
        "rm" => {
            let alias = opt_str(sub_m, "alias").unwrap_or("").trim().to_string();
            settings.aliases.remove(&alias);
            for em in accounts.order.clone() {
                if let Some(acc) = accounts.get_mut(&em) {
                    acc.aliases.retain(|a| !a.eq_ignore_ascii_case(&alias));
                }
            }
            let _ = ctx.store.save(&mut accounts);
            if let Err(err) = ctx.store.save_settings(&settings) {
                return ctx.fail("alias rm", err);
            }
            if ctx.json {
                return ctx.ok_json("alias rm", json!({"removed": alias}));
            }
            println!("Removed alias {alias}.");
            0
        }
        "list" => {
            let mut merged = settings.aliases.clone();
            for em in &accounts.order {
                if let Some(acc) = accounts.get(em) {
                    for a in &acc.aliases {
                        merged.entry(a.clone()).or_insert_with(|| em.clone());
                    }
                }
            }
            if ctx.json {
                return ctx.ok_json("alias list", json!({"aliases": merged}));
            }
            for (alias, email) in &merged {
                println!("{alias:<18} -> {email}");
            }
            0
        }
        _ => ctx.fail("alias", format!("unknown subcommand {sub:?}")),
    }
}

pub fn cmd_tag(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("list", m));
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("tag", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    match sub {
        "add" | "rm" => {
            let sel = opt_str(sub_m, "account").unwrap_or("");
            let Some(email) = ctx.resolve_selector(&accounts, &settings, sel) else {
                return ctx.fail("tag", format!("account {sel:?} not found"));
            };
            let tag = match validate_identifier(opt_str(sub_m, "tag").unwrap_or(""), "tag") {
                Ok(t) => t.to_ascii_lowercase(),
                Err(err) => return ctx.fail("tag", err),
            };
            if let Some(acc) = accounts.get_mut(&email) {
                acc.tags.retain(|t| !t.eq_ignore_ascii_case(&tag));
                if sub == "add" {
                    acc.tags.push(tag.clone());
                }
            }
            if let Err(err) = ctx.store.save(&mut accounts) {
                return ctx.fail("tag", err);
            }
            let tags = accounts
                .get(&email)
                .map(|a| a.tags.clone())
                .unwrap_or_default();
            if ctx.json {
                return ctx.ok_json(&format!("tag {sub}"), json!({"email": email, "tags": tags}));
            }
            println!("{email}: {}", tags.join(", "));
            0
        }
        "list" => {
            let filter = opt_str(sub_m, "tag").map(|t| t.trim().to_ascii_lowercase());
            let mut rows = Vec::new();
            for em in &accounts.order {
                let Some(acc) = accounts.get(em) else {
                    continue;
                };
                if acc.tags.is_empty() {
                    continue;
                }
                if let Some(f) = &filter {
                    if !acc.tags.iter().any(|t| t.eq_ignore_ascii_case(f)) {
                        continue;
                    }
                }
                rows.push(json!({"email": em, "tags": acc.tags}));
                if !ctx.json {
                    println!("{em:<30} {}", acc.tags.join(", "));
                }
            }
            if ctx.json {
                return ctx.ok_json("tag list", json!({"accounts": rows}));
            }
            0
        }
        _ => ctx.fail("tag", format!("unknown subcommand {sub:?}")),
    }
}

pub fn cmd_profile(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("list", m));
    let accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("profile", err),
    };
    let mut settings = match ctx.store.load_settings() {
        Ok(s) => s,
        Err(err) => return ctx.fail("profile", err),
    };
    match sub {
        "set" => {
            let name =
                match validate_identifier(opt_str(sub_m, "name").unwrap_or(""), "profile name") {
                    Ok(n) => n,
                    Err(err) => return ctx.fail("profile set", err),
                };
            let sel = opt_str(sub_m, "account").unwrap_or("");
            let Some(primary) = ctx.resolve_selector(&accounts, &settings, sel) else {
                return ctx.fail("profile set", format!("account {sel:?} not found"));
            };
            let family = match opt_str(sub_m, "family")
                .or_else(|| opt_str(m, "family"))
                .map(parse_family)
                .transpose()
            {
                Ok(f) => f,
                Err(err) => return ctx.fail("profile set", err),
            };
            let policy = match opt_str(sub_m, "policy") {
                Some(raw) => match RankingPolicy::parse(raw) {
                    Some(p) => p,
                    None => return ctx.fail("profile set", format!("invalid policy {raw:?}")),
                },
                None => settings.default_policy,
            };
            let mut reserves = Vec::new();
            if let Some(raw_res) = opt_str(sub_m, "reserve") {
                for part in raw_res.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    match ctx.resolve_selector(&accounts, &settings, part) {
                        Some(em) => reserves.push(em),
                        None => {
                            return ctx
                                .fail("profile set", format!("reserve account {part:?} not found"))
                        }
                    }
                }
            }
            let threshold_pct = match opt_str(sub_m, "threshold") {
                Some(raw) => match raw.parse::<u8>() {
                    Ok(v) if v <= 100 => v,
                    _ => return ctx.fail("profile set", "threshold must be 0..=100"),
                },
                None => settings.min_remaining_pct,
            };
            let prof = Profile {
                name: name.clone(),
                primary,
                family,
                policy,
                reserves,
                threshold_pct,
            };
            settings.profiles.insert(name.clone(), prof.clone());
            if let Err(err) = ctx.store.save_settings(&settings) {
                return ctx.fail("profile set", err);
            }
            if ctx.json {
                return ctx.ok_json("profile set", json!({"profile": prof}));
            }
            println!("Saved profile '{}' -> {}.", prof.name, prof.primary);
            0
        }
        "rm" => {
            let name = opt_str(sub_m, "name").unwrap_or("").trim().to_string();
            settings.profiles.remove(&name);
            if let Err(err) = ctx.store.save_settings(&settings) {
                return ctx.fail("profile rm", err);
            }
            if ctx.json {
                return ctx.ok_json("profile rm", json!({"removed": name}));
            }
            println!("Removed profile {name}.");
            0
        }
        "list" => {
            if ctx.json {
                return ctx.ok_json("profile list", json!({"profiles": settings.profiles}));
            }
            for (name, prof) in &settings.profiles {
                println!(
                    "{name:<18} primary={} policy={} threshold={}%",
                    prof.primary, prof.policy, prof.threshold_pct
                );
            }
            0
        }
        _ => ctx.fail("profile", format!("unknown subcommand {sub:?}")),
    }
}

pub fn cmd_bind(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("list", m));
    let mut settings = match ctx.store.load_settings() {
        Ok(s) => s,
        Err(err) => return ctx.fail("bind", err),
    };
    match sub {
        "set" => {
            let raw_dir = opt_str(sub_m, "dir").unwrap_or("").trim();
            if raw_dir.is_empty() {
                return ctx.fail("bind set", "directory path must not be empty");
            }
            let path = agy_core::paths::clean_path_str(raw_dir);
            let prof_name = opt_str(sub_m, "profile").unwrap_or("").trim().to_string();
            if !settings.profiles.contains_key(&prof_name) {
                return ctx.fail("bind set", format!("profile {prof_name:?} does not exist"));
            }
            let mode = match opt_str(sub_m, "mode") {
                Some(raw) => match BindMode::parse(raw) {
                    Some(bm) => bm,
                    None => return ctx.fail("bind set", format!("invalid bind mode {raw:?}")),
                },
                None => BindMode::Prompt,
            };
            settings.bindings.retain(|b| b.path != path);
            let binding = DirectoryBinding {
                path: path.clone(),
                profile: prof_name.clone(),
                mode,
            };
            settings.bindings.push(binding.clone());
            if let Err(err) = ctx.store.save_settings(&settings) {
                return ctx.fail("bind set", err);
            }
            if ctx.json {
                return ctx.ok_json("bind set", json!({"binding": binding}));
            }
            println!("{path} -> {prof_name} ({mode})");
            0
        }
        "rm" => {
            let path = agy_core::paths::clean_path_str(opt_str(sub_m, "dir").unwrap_or(""));
            settings.bindings.retain(|b| b.path != path);
            if let Err(err) = ctx.store.save_settings(&settings) {
                return ctx.fail("bind rm", err);
            }
            if ctx.json {
                return ctx.ok_json("bind rm", json!({"removed": path}));
            }
            println!("Removed binding for {path}.");
            0
        }
        "list" => {
            if ctx.json {
                return ctx.ok_json("bind list", json!({"bindings": settings.bindings}));
            }
            for b in &settings.bindings {
                println!("{} -> {} ({})", b.path, b.profile, b.mode);
            }
            0
        }
        _ => ctx.fail("bind", format!("unknown subcommand {sub:?}")),
    }
}

pub fn cmd_recommend(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("recommend", err),
    };
    if opt_flag(m, "refresh") {
        let _ = refresh_accounts_live(ctx, &mut accounts, true);
    }
    let settings = ctx.store.load_settings().unwrap_or_default();
    let dir = opt_str(m, "dir")
        .map(str::to_string)
        .unwrap_or_else(current_working_dir);
    let prof_name = opt_str(m, "profile")
        .map(str::to_string)
        .or_else(|| match_binding_for_dir(&settings.bindings, &dir).map(|b| b.profile.clone()));
    let profile = match &prof_name {
        Some(name) => match settings.profiles.get(name) {
            Some(p) => Some(p),
            None => return ctx.fail("recommend", format!("profile {name:?} not found")),
        },
        None => None,
    };
    let family = match opt_str(m, "family").map(parse_family).transpose() {
        Ok(f) => f,
        Err(err) => return ctx.fail("recommend", err),
    };
    let policy = match opt_str(m, "policy") {
        Some(raw) => match RankingPolicy::parse(raw) {
            Some(p) => p,
            None => return ctx.fail("recommend", format!("invalid policy {raw:?}")),
        },
        None => settings.default_policy,
    };
    let active = ctx.active_email(&accounts);
    let now_unix = agy_core::paths::wall_unix_secs();
    let rec = recommend(
        &accounts,
        active.as_deref(),
        family,
        policy,
        settings.min_remaining_pct,
        profile,
        now_unix,
    );
    let mut applied = false;
    if opt_flag(m, "apply") {
        if let Some(ref target) = rec.selected_email {
            if !active
                .as_deref()
                .map(|a| a.eq_ignore_ascii_case(target))
                .unwrap_or(false)
            {
                if let Some(acc) = accounts.get(target) {
                    match ctx.account_token(acc) {
                        Ok(tok) => {
                            if let Err(err) = ctx.session.switch_to(target, &tok) {
                                return ctx.fail("recommend", err);
                            }
                            ctx.record_history("recommend_apply", Some(target), &rec.reason);
                            applied = true;
                        }
                        Err(err) => return ctx.fail("recommend", err),
                    }
                }
            }
        }
    }
    if ctx.json {
        return ctx.ok_json("recommend", json!({"recommendation": rec, "active": active, "applied": applied, "profile": prof_name}));
    }
    println!(
        "{}Recommended:{} {} ({})",
        ctx.palette.bold,
        ctx.palette.reset,
        rec.selected_email.as_deref().unwrap_or("none"),
        rec.reason
    );
    for (em, score, ok) in &rec.candidates {
        let status = if *ok { "eligible" } else { "ineligible" };
        println!("  {em:<30} {:6.1}%  {status}", score);
    }
    0
}

pub fn cmd_ensure_active(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("ensure-active", err),
    };
    if opt_flag(m, "refresh") {
        let _ = refresh_accounts_live(ctx, &mut accounts, true);
    }
    let family = match opt_str(m, "family").map(parse_family).transpose() {
        Ok(f) => f,
        Err(err) => return ctx.fail("ensure-active", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let active = ctx.active_email(&accounts);
    let now_unix = agy_core::paths::wall_unix_secs();
    let active_unhealthy = match active.as_deref().and_then(|em| accounts.get(em)) {
        None => true,
        Some(acc) => {
            acc.disabled
                || !ctx.has_token(acc)
                || acc.is_cooled_down(family, now_unix)
                || evaluate_pool_failover(acc, &settings.pool_failover, now_unix).failover_triggered
                || acc
                    .family_pct(family)
                    .map(|p| p <= f64::from(settings.min_remaining_pct))
                    .unwrap_or(false)
        }
    };
    if !active_unhealthy {
        if ctx.json {
            return ctx.ok_json(
                "ensure-active",
                json!({"triggered": false, "active": active, "switched_to": Value::Null}),
            );
        }
        println!("active-ok: {}", active.as_deref().unwrap_or("-"));
        return 0;
    }
    let target = select_next(
        &accounts,
        active.as_deref(),
        family,
        settings.default_policy,
        settings.min_remaining_pct,
        now_unix,
    );
    let can_switch = settings.switch_mode == SwitchMode::Auto || opt_flag(m, "force");
    let mut switched_to: Option<String> = None;
    if can_switch {
        if let Some(ref next_em) = target {
            if !active
                .as_deref()
                .map(|a| a.eq_ignore_ascii_case(next_em))
                .unwrap_or(false)
            {
                if let Some(acc) = accounts.get(next_em) {
                    if let Ok(tok) = ctx.account_token(acc) {
                        if ctx.session.switch_to(next_em, &tok).is_ok() {
                            ctx.record_history("ensure_active", Some(next_em), "policy failover");
                            switched_to = Some(next_em.clone());
                        }
                    }
                }
            }
        }
    }
    let final_active = switched_to.clone().or(active.clone());
    if ctx.json {
        return ctx.ok_json("ensure-active", json!({"triggered": true, "previous_active": active, "active": final_active, "switched_to": switched_to, "recommended": target}));
    }
    if let Some(sw) = switched_to {
        println!("ensured-active: {sw}");
    } else {
        println!(
            "ensure-active: recommended {}",
            target.as_deref().unwrap_or("none")
        );
    }
    0
}

pub fn cmd_resolve_route(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("resolve-route", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let family = match opt_str(m, "family").map(parse_family).transpose() {
        Ok(Some(f)) => f,
        Ok(None) => settings.prefer_family.unwrap_or(ModelFamily::Claude),
        Err(err) => return ctx.fail("resolve-route", err),
    };
    let strategy = match opt_str(m, "fallback_strategy") {
        Some(raw) => match RouteStrategy::parse(raw) {
            Some(s) => s,
            None => {
                return ctx.fail(
                    "resolve-route",
                    format!("invalid fallback strategy {raw:?}"),
                )
            }
        },
        None => settings.route_strategy,
    };
    let force_switch = opt_flag(m, "force_switch") || opt_flag(m, "force");
    let now_unix = agy_core::paths::wall_unix_secs();
    let decision = match resolve_route(
        &accounts,
        &ctx.vault,
        &ctx.session,
        family,
        strategy,
        settings.switch_mode,
        settings.min_remaining_pct,
        force_switch,
        now_unix,
    ) {
        Ok(d) => d,
        Err(err) => return ctx.fail("resolve-route", err),
    };
    if decision.switched {
        ctx.record_history(
            "resolve_route",
            decision.active_email.as_deref(),
            &decision.outcome,
        );
    }
    if ctx.json {
        return ctx.ok_json("resolve-route", json!(decision));
    }
    println!(
        "route: account={} family={} outcome={}",
        decision
            .active_email
            .as_deref()
            .or(decision.recommended_email.as_deref())
            .unwrap_or("-"),
        family_name(decision.selected_family),
        decision.outcome
    );
    0
}

pub fn cmd_rotate_after_failure(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let settings = ctx.store.load_settings().unwrap_or_default();
    let reason = opt_str(m, "reason").unwrap_or("manual");
    let family = match opt_str(m, "family").map(parse_family).transpose() {
        Ok(f) => f,
        Err(err) => return ctx.fail("rotate-after-failure", err),
    };
    let cooldown_secs = match opt_str(m, "cooldown_minutes") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(mins) if mins >= 0 => mins.saturating_mul(60),
            _ => return ctx.fail("rotate-after-failure", "invalid --cooldown-minutes"),
        },
        None => 3600,
    };
    let force_switch = opt_flag(m, "force_switch") || opt_flag(m, "force");
    let now_unix = agy_core::paths::wall_unix_secs();
    let res = match rotate_after_failure(
        &ctx.paths,
        &ctx.store,
        &ctx.vault,
        &ctx.session,
        settings.switch_mode,
        reason,
        family,
        cooldown_secs,
        DEFAULT_FAILOVER_DEDUPE_SECS,
        force_switch,
        now_unix,
    ) {
        Ok(r) => r,
        Err(err) => return ctx.fail("rotate-after-failure", err),
    };
    if ctx.json {
        return ctx.ok_json("rotate-after-failure", json!(res));
    }
    println!(
        "failover: outcome={} switched_to={}",
        res.outcome,
        res.switched_to.as_deref().unwrap_or("-")
    );
    0
}

pub fn cmd_quota_policy(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let accounts = ctx
        .store
        .load()
        .unwrap_or_else(|_| agy_core::Accounts::new());
    let mut settings = match ctx.store.load_settings() {
        Ok(s) => s,
        Err(err) => return ctx.fail("quota-policy", err),
    };
    let mut changed = false;
    if let Some(en) = opt_str(m, "enabled") {
        match en.trim().to_ascii_lowercase().as_str() {
            "on" | "true" | "1" => settings.pool_failover.enabled = true,
            "off" | "false" | "0" => settings.pool_failover.enabled = false,
            _ => return ctx.fail("quota-policy", "expected --enabled on|off"),
        }
        changed = true;
    }
    if let Some(vals) = m.try_get_many::<String>("pool").ok().flatten() {
        settings.pool_failover.checked_pools = vals
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        changed = true;
    }
    if let Some(raw_mode) = opt_str(m, "match_mode") {
        match PoolMatchMode::parse(raw_mode) {
            Some(pm) => settings.pool_failover.match_mode = pm,
            None => return ctx.fail("quota-policy", "expected --match any|all"),
        }
        changed = true;
    }
    if let Some(raw_th) = opt_str(m, "threshold") {
        match raw_th.parse::<u8>() {
            Ok(v) if v <= 100 => settings.pool_failover.threshold_pct = v,
            _ => return ctx.fail("quota-policy", "threshold must be 0..=100"),
        }
        changed = true;
    }
    if let Some(raw_age) = opt_str(m, "max_age_seconds") {
        match raw_age.parse::<u64>() {
            Ok(v) => settings.pool_failover.max_age_secs = v,
            Err(_) => return ctx.fail("quota-policy", "invalid --max-age-seconds"),
        }
        changed = true;
    }
    if changed {
        if let Err(err) = ctx.store.save_settings(&settings) {
            return ctx.fail("quota-policy", err);
        }
    }
    let known = discover_pool_names(&accounts);
    if ctx.json {
        return ctx.ok_json(
            "quota-policy",
            json!({"policy": settings.pool_failover, "known_pools": known}),
        );
    }
    let pol = &settings.pool_failover;
    println!(
        "enabled={} match={} threshold={}% max_age={}s pools=[{}]",
        pol.enabled,
        pol.match_mode,
        pol.threshold_pct,
        pol.max_age_secs,
        pol.checked_pools.join(", ")
    );
    0
}

pub fn cmd_switch_mode(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut settings = match ctx.store.load_settings() {
        Ok(s) => s,
        Err(err) => return ctx.fail("switch-mode", err),
    };
    if let Some(raw) = opt_str(m, "mode") {
        let Some(mode) = SwitchMode::parse(raw) else {
            return ctx.fail(
                "switch-mode",
                format!("invalid switch mode {raw:?} (expected auto or manual)"),
            );
        };
        settings.switch_mode = mode;
        if let Err(err) = ctx.store.save_settings(&settings) {
            return ctx.fail("switch-mode", err);
        }
    }
    if ctx.json {
        return ctx.ok_json("switch-mode", json!({"switch_mode": settings.switch_mode}));
    }
    println!("{}", settings.switch_mode);
    0
}

pub fn cmd_run(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let Some(sel) = opt_str(m, "use_account").filter(|s| !s.trim().is_empty()) else {
        return ctx.fail_usage(
            "run",
            "--use-account=<slot|alias|email> is required for 'run' (no default account is used)",
        );
    };
    let mut forward: Vec<String> = m
        .try_get_many::<String>("run_args")
        .ok()
        .flatten()
        .map(|it| it.cloned().collect())
        .unwrap_or_default();
    if forward.first().map(String::as_str) == Some("now") {
        forward.remove(0);
    }
    super::execute_isolated_for_selector(sel, &forward)
}
