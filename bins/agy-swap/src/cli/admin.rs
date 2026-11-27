use agy_core::backup::{
    export_backup, export_backup_to_file, import_backup_from_file, verify_backup, BackupBundle,
};
use agy_core::http::HttpClient;
use agy_core::logwatch::{ack_restart, load_runtime, poll_logs_once};
use agy_core::ops::{
    compute_forecasts, install_agy, install_statusline, render_prometheus_metrics,
    render_statusline, render_statusline_from_json, run_doctor, self_update, summarize_history,
};
use agy_core::policy::{PoolMatchMode, RankingPolicy, RouteStrategy, SwitchMode};
use agy_core::{atomic_write_private, Settings, VERSION};
use agy_tui::{diff_ansi, Breakpoint, Frame, HitMap, PointerShape, Surface};
use clap::ArgMatches;
use serde_json::{json, Value};

use super::accounts::{read_stdin_bounded, refresh_accounts_live};
use super::{explicit_account, opt_flag, opt_str, parse_duration_secs, parse_family, AppContext};

pub fn cmd_doctor(ctx: &AppContext, _m: &ArgMatches) -> i32 {
    let checks = run_doctor(&ctx.paths, &ctx.store, &ctx.vault, &ctx.session);
    let healthy = checks.iter().all(|c| c.ok);
    let data = json!({
        "healthy": healthy,
        "checks": checks,
        "paths": {
            "config_dir": ctx.paths.config_dir,
            "accounts": ctx.paths.accounts_file,
            "vault": ctx.paths.vault_file,
            "settings": ctx.paths.settings_file,
            "history": ctx.paths.history_file,
        }
    });
    if ctx.json {
        let _ = ctx.ok_json("doctor", data);
        return if healthy { 0 } else { 1 };
    }
    for check in &checks {
        let (color, sym) = if check.ok {
            (ctx.palette.green, "✓")
        } else {
            (ctx.palette.red, "✕")
        };
        println!(
            "{color}{sym}{} {:<18} {}",
            ctx.palette.reset, check.name, check.detail
        );
    }
    if healthy {
        0
    } else {
        1
    }
}

pub fn cmd_config(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("show", m));
    match sub {
        "show" => {
            let settings = match ctx.store.load_settings() {
                Ok(s) => s,
                Err(err) => return ctx.fail("config show", err),
            };
            if ctx.json {
                return ctx.ok_json("config show", json!(settings));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&settings).unwrap_or_default()
            );
            0
        }
        "set" => {
            let mut settings = match ctx.store.load_settings() {
                Ok(s) => s,
                Err(err) => return ctx.fail("config set", err),
            };
            let key = opt_str(sub_m, "key").unwrap_or("").trim();
            let val = opt_str(sub_m, "value").unwrap_or("").trim();
            match key {
                "switch_mode" => match SwitchMode::parse(val) {
                    Some(sm) => settings.switch_mode = sm,
                    None => return ctx.fail("config set", "expected auto or manual"),
                },
                "policy" | "default_policy" => match RankingPolicy::parse(val) {
                    Some(rp) => settings.default_policy = rp,
                    None => {
                        return ctx.fail("config set", "expected sticky, balanced, or round-robin")
                    }
                },
                "route_strategy" => match RouteStrategy::parse(val) {
                    Some(rs) => settings.route_strategy = rs,
                    None => {
                        return ctx.fail(
                            "config set",
                            "expected same-family-first, same-account-first, or strict-family",
                        )
                    }
                },
                "min_remaining_pct" => match val.parse::<u8>() {
                    Ok(v) if v <= 100 => settings.min_remaining_pct = v,
                    _ => return ctx.fail("config set", "expected 0..=100"),
                },
                "prefer_family" => {
                    if val.is_empty() || val.eq_ignore_ascii_case("none") {
                        settings.prefer_family = None;
                    } else {
                        match parse_family(val) {
                            Ok(f) => settings.prefer_family = Some(f),
                            Err(err) => return ctx.fail("config set", err),
                        }
                    }
                }
                "pool_failover.enabled" => {
                    settings.pool_failover.enabled = matches!(
                        val.to_ascii_lowercase().as_str(),
                        "1" | "true" | "on" | "yes"
                    )
                }
                "pool_failover.match_mode" => match PoolMatchMode::parse(val) {
                    Some(pm) => settings.pool_failover.match_mode = pm,
                    None => return ctx.fail("config set", "expected any or all"),
                },
                "split_offset" => match val.parse::<i16>() {
                    Ok(v) => settings.split_offset = v.clamp(-40, 40),
                    Err(_) => return ctx.fail("config set", "invalid integer"),
                },
                other if !other.is_empty() => {
                    settings
                        .extra
                        .insert(other.to_string(), Value::String(val.to_string()));
                }
                _ => return ctx.fail("config set", "missing key"),
            }
            if let Err(err) = ctx.store.save_settings(&settings) {
                return ctx.fail("config set", err);
            }
            if ctx.json {
                return ctx.ok_json("config set", json!({"key": key, "value": val}));
            }
            println!("Updated {key} = {val}");
            0
        }
        "reset" => {
            if !opt_flag(sub_m, "force") && !opt_flag(m, "force") {
                return ctx.fail(
                    "config reset",
                    "pass --force to reset settings.json to defaults",
                );
            }
            let defaults = Settings::default();
            if let Err(err) = ctx.store.save_settings(&defaults) {
                return ctx.fail("config reset", err);
            }
            if ctx.json {
                return ctx.ok_json("config reset", json!({"reset": true}));
            }
            println!("Reset settings.json to defaults.");
            0
        }
        _ => ctx.fail("config", format!("unknown subcommand {sub:?}")),
    }
}

pub fn cmd_watch(ctx: &AppContext, m: &ArgMatches) -> i32 {
    if opt_flag(m, "from_start") {
        let cursor_path = format!("{}/logwatch-cursors.json", ctx.paths.config_dir);
        let _ = atomic_write_private(&cursor_path, br#"{"initialized":true,"offsets":{}}"#);
    }
    let poll_ms: u64 = if let Some(raw_secs) = opt_str(m, "poll_seconds") {
        match raw_secs.parse::<f64>() {
            Ok(v) if v.is_finite() && v >= 0.05 => (v * 1000.0) as u64,
            _ => return ctx.fail("watch", "invalid --poll-seconds"),
        }
    } else if let Some(raw_int) = opt_str(m, "interval") {
        match parse_duration_secs(raw_int) {
            Ok(s) if s >= 1 => (s as u64) * 1000,
            _ => return ctx.fail("watch", "interval must be >= 1s"),
        }
    } else {
        1000
    };
    let once = opt_flag(m, "once");
    let no_rotate = opt_flag(m, "no_rotate");
    let force_switch = !no_rotate && (opt_flag(m, "force_switch") || opt_flag(m, "force"));
    loop {
        if opt_flag(m, "refresh") {
            if let Ok(mut accounts) = ctx.store.load() {
                let _ = refresh_accounts_live(ctx, &mut accounts, true);
            }
        }
        let settings = ctx.store.load_settings().unwrap_or_default();
        let mode = if no_rotate {
            SwitchMode::Manual
        } else {
            settings.switch_mode
        };
        let now_unix = agy_core::paths::wall_unix_secs();
        let failover = match poll_logs_once(
            &ctx.paths,
            &ctx.store,
            &ctx.vault,
            &ctx.session,
            mode,
            force_switch,
            now_unix,
        ) {
            Ok(f) => f,
            Err(err) => return ctx.fail("watch", err),
        };
        let runtime = load_runtime(&ctx.paths).unwrap_or_default();
        let active = ctx.session.current_email();
        if ctx.json {
            let _ = ctx.ok_json(
                "watch",
                json!({"active": active, "failover": failover, "runtime": runtime}),
            );
        } else if let Some(ref res) = failover {
            println!(
                "watch: outcome={} switched_to={} restart_needed={}",
                res.outcome,
                res.switched_to.as_deref().unwrap_or("-"),
                res.restart_needed
            );
        } else if once {
            println!("watch: idle (active={})", active.as_deref().unwrap_or("-"));
        }
        if once {
            return 0;
        }
        eko::sleep_ms(poll_ms);
    }
}

pub fn cmd_ack_restart(ctx: &AppContext) -> i32 {
    let runtime = match ack_restart(&ctx.paths) {
        Ok(r) => r,
        Err(err) => return ctx.fail("ack-restart", err),
    };
    if ctx.json {
        return ctx.ok_json(
            "ack-restart",
            json!({"restart_agy_needed": runtime.restart_agy_needed, "runtime": runtime}),
        );
    }
    println!("restart-acknowledged");
    0
}

pub fn cmd_history(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let action = opt_str(m, "action").unwrap_or("list");
    let limit = opt_str(m, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 10_000);
    match action {
        "list" => {
            let entries = match ctx.store.read_history(limit) {
                Ok(e) => e,
                Err(err) => return ctx.fail("history list", err),
            };
            if ctx.json {
                return ctx.ok_json("history list", json!({"events": entries}));
            }
            for e in &entries {
                let ts = agy_core::paths::format_rfc3339_utc(e.timestamp_unix);
                println!(
                    "{ts}  {:<16}  {:<28}  {}",
                    e.kind,
                    e.email.as_deref().unwrap_or("-"),
                    e.detail
                );
            }
            0
        }
        "clear" => {
            if !opt_flag(m, "force") {
                return ctx.fail("history clear", "pass --force to clear history");
            }
            eko::fs::unlink(ctx.paths.history_file.as_bytes());
            if ctx.json {
                return ctx.ok_json("history clear", json!({"cleared": true}));
            }
            println!("Cleared history.");
            0
        }
        "export" => {
            let entries = match ctx.store.read_history(10_000) {
                Ok(e) => e,
                Err(err) => return ctx.fail("history export", err),
            };
            let out = opt_str(m, "output").unwrap_or("-");
            if out == "-" {
                for e in &entries {
                    if let Ok(line) = serde_json::to_string(e) {
                        println!("{line}");
                    }
                }
                return 0;
            }
            let mut payload = serde_json::to_vec_pretty(&entries).unwrap_or_default();
            payload.push(b'\n');
            if let Err(err) = atomic_write_private(out, &payload) {
                return ctx.fail("history export", err);
            }
            0
        }
        _ => ctx.fail("history", format!("unknown action {action:?}")),
    }
}

pub fn cmd_stats(ctx: &AppContext) -> i32 {
    let entries = match ctx.store.read_history(10_000) {
        Ok(e) => e,
        Err(err) => return ctx.fail("stats", err),
    };
    let summary = summarize_history(&entries);
    if ctx.json {
        return ctx.ok_json("stats", json!(summary));
    }
    println!("Events: {}", summary.total_events);
    for (k, count) in &summary.by_kind {
        println!("  {k:<18} {count}");
    }
    0
}

pub fn cmd_forecast(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("forecast", err),
    };
    if opt_flag(m, "refresh") {
        let _ = refresh_accounts_live(ctx, &mut accounts, true);
    }
    let settings = ctx.store.load_settings().unwrap_or_default();
    let filter_email = match explicit_account(m, "account") {
        Some(sel) => match ctx.resolve_selector(&accounts, &settings, sel) {
            Some(em) => Some(em),
            None => return ctx.fail("forecast", format!("account {sel:?} not found")),
        },
        None => None,
    };
    let now_unix = agy_core::paths::wall_unix_secs();
    let rows: Vec<_> = compute_forecasts(&accounts, now_unix)
        .into_iter()
        .filter(|f| {
            filter_email
                .as_deref()
                .map(|w| w.eq_ignore_ascii_case(&f.email))
                .unwrap_or(true)
        })
        .collect();
    if ctx.json {
        return ctx.ok_json("forecast", json!({"forecasts": rows}));
    }
    for row in &rows {
        let pct = row
            .remaining_pct
            .map(|p| format!("{p:.1}%"))
            .unwrap_or_else(|| "unknown".to_string());
        println!(
            "{:<28} {:<14} {:<10} confidence={}",
            row.email, row.pool, pct, row.confidence
        );
    }
    0
}

fn read_passphrase(m: &ArgMatches) -> Result<Option<String>, String> {
    if opt_flag(m, "passphrase_stdin") {
        let raw = read_stdin_bounded(64 * 1024)?;
        let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
        return Ok(Some(trimmed));
    }
    Ok(opt_str(m, "passphrase").map(str::to_string))
}

pub fn cmd_backup(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("export", m));
    let pass = match read_passphrase(sub_m) {
        Ok(p) => p,
        Err(err) => return ctx.fail("backup", err),
    };
    let now_unix = agy_core::paths::wall_unix_secs();
    match sub {
        "export" => {
            let include_secrets = opt_flag(sub_m, "include_secrets");
            let target = opt_str(sub_m, "output")
                .or_else(|| opt_str(sub_m, "file"))
                .unwrap_or("agy-swap-rs-backup.json");
            if target == "-" {
                let bundle = match export_backup(
                    &ctx.store,
                    &ctx.vault,
                    include_secrets,
                    pass.as_deref(),
                    now_unix,
                ) {
                    Ok(b) => b,
                    Err(err) => return ctx.fail("backup export", err),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&bundle).unwrap_or_default()
                );
                return 0;
            }
            let bundle = match export_backup_to_file(
                target,
                &ctx.store,
                &ctx.vault,
                include_secrets,
                pass.as_deref(),
                now_unix,
            ) {
                Ok(b) => b,
                Err(err) => return ctx.fail("backup export", err),
            };
            if ctx.json {
                return ctx.ok_json("backup export", json!({"path": target, "contains_secrets": bundle.contains_secrets, "accounts": bundle.accounts.len()}));
            }
            println!(
                "Backup written to {target} (contains_secrets={}).",
                bundle.contains_secrets
            );
            0
        }
        "import" => {
            let Some(file) = opt_str(sub_m, "file") else {
                return ctx.fail("backup import", "missing backup FILE");
            };
            let merge = opt_flag(sub_m, "merge");
            let summary = match import_backup_from_file(
                file,
                &ctx.paths,
                &ctx.store,
                &ctx.vault,
                pass.as_deref(),
                merge,
            ) {
                Ok(s) => s,
                Err(err) => return ctx.fail("backup import", err),
            };
            if ctx.json {
                return ctx.ok_json("backup import", json!(summary));
            }
            println!(
                "Imported {} account(s); restored {} vault secret(s).",
                summary.accounts_count, summary.secrets_restored
            );
            0
        }
        "verify" => {
            let Some(file) = opt_str(sub_m, "file") else {
                return ctx.fail("backup verify", "missing backup FILE");
            };
            let raw = match eko::file::read_to_string(file) {
                Ok(s) => s,
                Err(err) => return ctx.fail("backup verify", err),
            };
            let bundle: BackupBundle = match serde_json::from_str(&raw) {
                Ok(b) => b,
                Err(err) => return ctx.fail("backup verify", err),
            };
            let secret_count = match verify_backup(&bundle, pass.as_deref()) {
                Ok(n) => n,
                Err(err) => return ctx.fail("backup verify", err),
            };
            if ctx.json {
                return ctx.ok_json(
                    "backup verify",
                    json!({"valid": true, "secrets": secret_count}),
                );
            }
            println!("Backup valid ({secret_count} encrypted secret(s)).");
            0
        }
        _ => ctx.fail("backup", format!("unknown subcommand {sub:?}")),
    }
}

pub fn cmd_statusline(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let (sub, sub_m) = m.subcommand().unwrap_or(("render", m));
    match sub {
        "render" => {
            let line = if !agy_tui::is_tty(0) {
                match read_stdin_bounded(256 * 1024) {
                    Ok(raw) if !raw.trim().is_empty() => match render_statusline_from_json(&raw) {
                        Ok(s) => s,
                        Err(err) => return ctx.fail("statusline render", err),
                    },
                    _ => {
                        let accounts = ctx
                            .store
                            .load()
                            .unwrap_or_else(|_| agy_core::Accounts::new());
                        let active = ctx.active_email(&accounts);
                        render_statusline(
                            &accounts,
                            active.as_deref(),
                            agy_core::paths::wall_unix_secs(),
                        )
                    }
                }
            } else {
                let accounts = ctx
                    .store
                    .load()
                    .unwrap_or_else(|_| agy_core::Accounts::new());
                let active = ctx.active_email(&accounts);
                render_statusline(
                    &accounts,
                    active.as_deref(),
                    agy_core::paths::wall_unix_secs(),
                )
            };
            if ctx.json {
                return ctx.ok_json("statusline render", json!({"text": line}));
            }
            println!("{line}");
            0
        }
        "install" => {
            let tool = opt_str(sub_m, "tool").unwrap_or("zsh");
            let dest = match install_statusline(tool, &ctx.paths) {
                Ok(d) => d,
                Err(err) => return ctx.fail("statusline install", err),
            };
            if ctx.json {
                return ctx.ok_json(
                    "statusline install",
                    json!({"installed": true, "tool": tool, "path": dest}),
                );
            }
            println!("Installed statusline integration ({tool}) in {dest}");
            0
        }
        _ => ctx.fail("statusline", format!("unknown subcommand {sub:?}")),
    }
}

pub fn cmd_metrics(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let mut accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("metrics", err),
    };
    if opt_flag(m, "refresh") {
        let _ = refresh_accounts_live(ctx, &mut accounts, true);
    }
    let fmt = opt_str(m, "format").unwrap_or("prometheus");
    let active = ctx.active_email(&accounts);
    let now_unix = agy_core::paths::wall_unix_secs();
    let prom = render_prometheus_metrics(&accounts, active.as_deref(), now_unix);
    if ctx.json || fmt.eq_ignore_ascii_case("json") {
        return ctx.ok_json(
            "metrics",
            json!({"active": active, "account_count": accounts.len(), "prometheus": prom}),
        );
    }
    print!("{prom}");
    0
}

pub fn cmd_install_agy(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let http = match HttpClient::new() {
        Ok(h) => h,
        Err(err) => return ctx.fail("install-agy", err),
    };
    let dir = opt_str(m, "dir");
    let installed = match install_agy(&http, &ctx.paths, dir) {
        Ok(p) => p,
        Err(err) => return ctx.fail("install-agy", err),
    };
    if ctx.json {
        return ctx.ok_json("install-agy", json!({"path": installed}));
    }
    println!(
        "{}✓ Installed agy at {installed}{}",
        ctx.palette.green, ctx.palette.reset
    );
    0
}

pub fn cmd_update(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let check_only = opt_flag(m, "check")
        || opt_str(m, "mode")
            .map(|s| s.eq_ignore_ascii_case("check"))
            .unwrap_or(false);
    let http = match HttpClient::new() {
        Ok(h) => h,
        Err(err) => return ctx.fail("update", err),
    };
    let msg = match self_update(&http, check_only) {
        Ok(s) => s,
        Err(err) => return ctx.fail("update", err),
    };
    if ctx.json {
        return ctx.ok_json("update", json!({"check_only": check_only, "message": msg}));
    }
    println!("{msg}");
    0
}

pub fn cmd_version(as_json: bool) -> i32 {
    if as_json {
        println!("{}", serde_json::to_string_pretty(&json!({"schema_version": 1, "command": "version", "ok": true, "data": {"version": VERSION}})).unwrap_or_default());
        return 0;
    }
    println!("agy-swap-rs v{VERSION}");
    0
}

pub fn cmd_completion(m: &ArgMatches, as_json: bool) -> i32 {
    let shell = opt_str(m, "shell")
        .unwrap_or("bash")
        .trim()
        .to_ascii_lowercase();
    let cmds = "add login import-current list limits limit switch next remove status logout verify account alias tag profile bind recommend ensure-active resolve-route rotate-after-failure quota-policy switch-mode run doctor config watch ack-restart history stats forecast backup statusline metrics install-agy update version completion";
    let script = match shell.as_str() {
        "bash" => format!("_agy_swap_rs_complete() {{ COMPREPLY=($(compgen -W '{cmds}' -- \"${{COMP_WORDS[COMP_CWORD]}}\")); }}; complete -F _agy_swap_rs_complete agy-swap-rs"),
        "zsh" => format!("#compdef agy-swap-rs\n_arguments '1:command:({cmds})'"),
        "fish" => format!("complete -c agy-swap-rs -f -a '{cmds}'"),
        "powershell" | "pwsh" => format!("Register-ArgumentCompleter -Native -CommandName agy-swap-rs -ScriptBlock {{ param($wordToComplete) '{cmds}'.Split(' ') | Where-Object {{ $_ -like \"$wordToComplete*\" }} }}"),
        other => {
            eprintln!("agy-swap-rs: completion: unsupported shell {other:?}");
            return 1;
        }
    };
    if as_json {
        println!("{}", serde_json::to_string_pretty(&json!({"schema_version": 1, "command": "completion", "ok": true, "data": {"shell": shell, "script": script}})).unwrap_or_default());
        return 0;
    }
    println!("{script}");
    0
}

pub fn cmd_dump_frame(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let raw_size = opt_str(m, "size").unwrap_or("120x36");
    let Some((w_str, h_str)) = raw_size.split_once(['x', 'X']) else {
        return ctx.fail(
            "__dump-frame",
            format!("invalid size {raw_size:?} (expected WxH)"),
        );
    };
    let (Ok(w), Ok(h)) = (w_str.trim().parse::<u16>(), h_str.trim().parse::<u16>()) else {
        return ctx.fail("__dump-frame", format!("invalid dimensions {raw_size:?}"));
    };
    let ascii = opt_flag(m, "ascii") || ctx.ascii;
    let plain = crate::ui::render_frame_for_size(&ctx.paths, w, h, ascii);
    let state = crate::ui::state::DeckState::load(&ctx.paths);
    let surface = crate::ui::render_snapshot_surface(&state, w, h, ascii);
    let mut ansi_buf = Vec::new();
    diff_ansi(None, &surface, true, &mut ansi_buf);
    if ctx.json {
        let mut hit_surf = Surface::new(w, h);
        let mut hits = HitMap::new();
        {
            let mut frame = Frame::new(&mut hit_surf, &mut hits, ascii);
            let theme = crate::ui::theme::Theme::detect(ascii);
            crate::ui::deck::render_deck(&mut frame, &state, &theme);
        }
        let mut pointer_cells = 0usize;
        let mut col_resize_cells = 0usize;
        let mut row_resize_cells = 0usize;
        for y in 0..h {
            for x in 0..w {
                if let Some((_, shape)) = hits.hit_test(x, y) {
                    match shape {
                        PointerShape::Pointer => pointer_cells += 1,
                        PointerShape::ColResize => col_resize_cells += 1,
                        PointerShape::RowResize => row_resize_cells += 1,
                        PointerShape::Default => {}
                    }
                }
            }
        }
        let bp = Breakpoint::from_width(w);
        return ctx.ok_json(
            "__dump-frame",
            json!({
                "width": w,
                "height": h,
                "breakpoint": format!("{bp:?}"),
                "hit_regions": hits.len(),
                "pointer_cells": pointer_cells,
                "col_resize_cells": col_resize_cells,
                "row_resize_cells": row_resize_cells,
                "plain": plain,
                "ansi": String::from_utf8_lossy(&ansi_buf),
                "ansi_bytes": ansi_buf.len(),
            }),
        );
    }
    if opt_flag(m, "ansi") {
        eko::print::write_fd(1, &ansi_buf);
    } else {
        println!("{plain}");
    }
    0
}
