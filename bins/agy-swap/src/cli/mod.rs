pub mod accounts;
pub mod admin;
pub mod args;
pub mod image;
pub mod routing;

use agy_core::{
    Account, Accounts, Badge, HistoryEntry, ModelFamily, Paths, SessionManager, Settings, Store,
    Vault,
};
use clap::error::ErrorKind;
use serde_json::{json, Value};

fn migrate_legacy_gemini_config_dir(paths: &Paths) {
    let legacy_dir = agy_core::paths::join_path(&paths.home, ".gemini/agy-swap-rs");
    if legacy_dir.is_empty() || legacy_dir == paths.config_dir || !eko::file::exists(&legacy_dir) {
        return;
    }
    if agy_core::store::ensure_private_dir(&paths.config_dir).is_err() {
        return;
    }
    for file_name in [
        "accounts.json",
        "vault.json",
        "settings.json",
        "history-v1.jsonl",
    ] {
        let src = agy_core::paths::join_path(&legacy_dir, file_name);
        let dst = agy_core::paths::join_path(&paths.config_dir, file_name);
        let Ok(src_mtime) = std::fs::metadata(&src).and_then(|m| m.modified()) else {
            continue;
        };
        let should_copy = match std::fs::metadata(&dst).and_then(|m| m.modified()) {
            Ok(dst_mtime) => src_mtime > dst_mtime,
            Err(_) => true,
        };
        if should_copy {
            if let Ok(bytes) = std::fs::read(&src) {
                let _ = agy_core::atomic_write_private(&dst, &bytes);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&legacy_dir);
}

pub fn detect_paths() -> agy_core::Result<Paths> {
    if let (Some(home), Some(cfg)) = (eko::env::var("HOME"), eko::env::var("AGY_SWAP_CONFIG_DIR")) {
        if !home.is_empty() && !cfg.is_empty() {
            return Ok(Paths::from_home_and_config(&home, &cfg));
        }
    }
    let paths = Paths::detect()?;
    migrate_legacy_gemini_config_dir(&paths);
    Ok(paths)
}

pub fn harvest_all_overlays(paths: &Paths, store: &Store, vault: &Vault) {
    if let Ok(accounts) = store.load() {
        for email in &accounts.order {
            let _ = agy_core::isolate::harvest_overlay_home(paths, store, vault, email);
        }
    }
}

pub fn sync_session_quiet(paths: &Paths) {
    let store = Store::new(paths.clone());
    let vault = Vault::new(paths.clone());
    harvest_all_overlays(paths, &store, &vault);
    let session = SessionManager::new(paths.clone());
    let _ = session.reconcile_active_session(&store, &vault);
}

#[derive(Clone, Debug)]
pub struct CliPalette {
    pub orange: &'static str,
    pub green: &'static str,
    pub blue: &'static str,
    pub red: &'static str,
    pub yellow: &'static str,
    pub gray: &'static str,
    pub dark_gray: &'static str,
    pub bold: &'static str,
    pub reset: &'static str,
}

impl CliPalette {
    pub fn detect(stdout_tty: bool) -> Self {
        let no_color = eko::env::var("NO_COLOR")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let dumb = eko::env::var("TERM").as_deref() == Some("dumb");
        if !stdout_tty || no_color || dumb {
            return Self {
                orange: "",
                green: "",
                blue: "",
                red: "",
                yellow: "",
                gray: "",
                dark_gray: "",
                bold: "",
                reset: "",
            };
        }
        let ct = eko::env::var("COLORTERM")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let term = eko::env::var("TERM")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let truecolor = ct == "truecolor"
            || ct == "24bit"
            || term.contains("ghostty")
            || term.contains("alacritty")
            || term.contains("kitty")
            || term.contains("iterm");
        if truecolor {
            Self {
                orange: "\x1b[38;2;255;137;26m",
                green: "\x1b[38;2;52;211;153m",
                blue: "\x1b[38;2;56;189;248m",
                red: "\x1b[38;2;248;113;113m",
                yellow: "\x1b[38;2;251;191;36m",
                gray: "\x1b[38;2;139;148;158m",
                dark_gray: "\x1b[38;2;48;54;61m",
                bold: "\x1b[1m",
                reset: "\x1b[0m",
            }
        } else {
            Self {
                orange: "\x1b[38;5;208m",
                green: "\x1b[38;5;78m",
                blue: "\x1b[38;5;75m",
                red: "\x1b[38;5;203m",
                yellow: "\x1b[38;5;220m",
                gray: "\x1b[38;5;244m",
                dark_gray: "\x1b[38;5;238m",
                bold: "\x1b[1m",
                reset: "\x1b[0m",
            }
        }
    }

    pub fn badge_text(&self, badge: Badge) -> String {
        let (color, label) = match badge {
            Badge::Ready => (self.green, "READY"),
            Badge::Low => (self.yellow, "LOW"),
            Badge::Critical => (self.red, "CRITICAL"),
            Badge::GeminiOnly => (self.blue, "GEMINI ONLY"),
            Badge::ClaudeGptOnly => (self.orange, "CLAUDE/GPT ONLY"),
            Badge::Limited => (self.red, "LIMITED"),
            Badge::NoToken => (self.gray, "NO TOKEN"),
            Badge::Verify => (self.yellow, "VERIFY"),
        };
        format!("{color}{label}{}", self.reset)
    }

    pub fn gauge(&self, pct: Option<f64>, width: usize, ascii: bool) -> String {
        let w = width.max(1);
        let Some(raw) = pct else {
            let ch = if ascii { "-" } else { "░" };
            return format!("[{}{}{}]   n/a ", self.dark_gray, ch.repeat(w), self.reset);
        };
        let clamped = raw.clamp(0.0, 100.0);
        let frac = clamped / 100.0;
        let color = if clamped <= 10.0 {
            self.red
        } else if clamped <= 30.0 {
            self.yellow
        } else {
            self.green
        };
        let total = frac * (w as f64);
        let mut full = total.floor() as usize;
        if ascii {
            if total - (full as f64) >= 0.5 && full < w {
                full += 1;
            }
            let rem = w.saturating_sub(full);
            return format!(
                "[{color}{}{}{}{}] {:5.1}%",
                "#".repeat(full),
                self.dark_gray,
                "-".repeat(rem),
                self.reset,
                clamped
            );
        }
        let blocks = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
        let mut sub = ((total - (full as f64)) * 8.0).round() as usize;
        if sub >= 8 {
            full += 1;
            sub = 0;
        }
        let mut bar = String::new();
        if full > 0 {
            bar.push_str(color);
            bar.push_str(&"█".repeat(full.min(w)));
        }
        let mut used = full.min(w);
        if sub > 0 && used < w {
            bar.push_str(color);
            bar.push_str(blocks[sub]);
            used += 1;
        }
        if used < w {
            bar.push_str(self.dark_gray);
            bar.push_str(&"░".repeat(w - used));
        }
        bar.push_str(self.reset);
        format!("[{bar}] {:5.1}%", clamped)
    }
}

pub struct AppContext {
    pub paths: Paths,
    pub store: Store,
    pub vault: Vault,
    pub session: SessionManager,
    pub json: bool,
    pub ascii: bool,
    pub palette: CliPalette,
}

impl AppContext {
    pub fn new(paths: Paths, json: bool, _verbose: bool) -> Self {
        let stdout_tty = agy_tui::is_tty(1);
        let ascii = eko::env::var("AGY_SWAP_ASCII").as_deref() == Some("1");
        Self {
            store: Store::new(paths.clone()),
            vault: Vault::new(paths.clone()),
            session: SessionManager::new(paths.clone()),
            paths,
            json,
            ascii,
            palette: CliPalette::detect(stdout_tty && !json),
        }
    }

    pub fn ok_json(&self, command: &str, data: Value) -> i32 {
        let envelope = json!({
            "schema_version": 1,
            "command": command,
            "ok": true,
            "data": data,
        });
        match serde_json::to_string_pretty(&envelope) {
            Ok(text) => {
                println!("{text}");
                0
            }
            Err(err) => {
                eprintln!("agy-swap-rs: cannot serialize JSON: {err}");
                1
            }
        }
    }

    pub fn fail(&self, command: &str, err: impl core::fmt::Display) -> i32 {
        self.fail_with_code(command, err, 1)
    }

    pub fn fail_usage(&self, command: &str, err: impl core::fmt::Display) -> i32 {
        self.fail_with_code(command, err, 2)
    }

    fn fail_with_code(&self, command: &str, err: impl core::fmt::Display, code: i32) -> i32 {
        let msg = err.to_string();
        if self.json {
            let envelope = json!({
                "schema_version": 1,
                "command": command,
                "ok": false,
                "error": msg,
            });
            if let Ok(text) = serde_json::to_string_pretty(&envelope) {
                println!("{text}");
            }
            return code;
        }
        eprintln!(
            "{}agy-swap-rs: {command}: {msg}{}",
            self.palette.red, self.palette.reset
        );
        code
    }

    pub fn vault_key_for(account: &Account) -> String {
        account
            .vault_ref
            .clone()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| format!("account:{}", account.email))
    }

    pub fn account_token(&self, account: &Account) -> agy_core::Result<String> {
        let key = Self::vault_key_for(account);
        if let Some(secret) = self.vault.get(&key)? {
            if !secret.trim().is_empty() {
                return Ok(secret);
            }
        }
        let det_key = format!("account:{}", account.email);
        if det_key != key {
            if let Some(secret) = self.vault.get(&det_key)? {
                if !secret.trim().is_empty() {
                    return Ok(secret);
                }
            }
        }
        if let Some(legacy) = &account.legacy_token_data {
            if !legacy.trim().is_empty() {
                return Ok(legacy.clone());
            }
        }
        Err(agy_core::Error::Auth(format!(
            "no saved token for {}",
            account.email
        )))
    }

    pub fn has_token(&self, account: &Account) -> bool {
        self.account_token(account).is_ok()
    }

    pub fn active_email(&self, accounts: &Accounts) -> Option<String> {
        if let Some(email) = self.session.current_email() {
            if let Some(resolved) = accounts.resolve(&email) {
                return Some(resolved.to_string());
            }
            if !email.trim().is_empty() {
                return Some(email);
            }
        }
        if let Some(raw_token) = self.session.current_token() {
            if let Ok(bundle) = agy_core::oauth::TokenBundle::parse(&raw_token) {
                if let Some(hint) = bundle.email_hint {
                    if let Some(resolved) = accounts.resolve(&hint) {
                        return Some(resolved.to_string());
                    }
                    return Some(hint);
                }
            }
        }
        None
    }

    pub fn resolve_selector(
        &self,
        accounts: &Accounts,
        settings: &Settings,
        raw: &str,
    ) -> Option<String> {
        let mut target = raw.trim().to_string();
        if target.is_empty() {
            return None;
        }
        for _ in 0..8 {
            if let Some(next) = settings.aliases.get(&target) {
                if next == &target {
                    break;
                }
                target = next.clone();
                continue;
            }
            if let Some(profile) = settings.profiles.get(&target) {
                if profile.primary == target {
                    break;
                }
                target = profile.primary.clone();
                continue;
            }
            break;
        }
        accounts.resolve(&target).map(str::to_string)
    }

    pub fn record_history(&self, kind: &str, email: Option<&str>, detail: &str) {
        let entry = HistoryEntry {
            timestamp_unix: agy_core::paths::wall_unix_secs(),
            kind: kind.to_string(),
            email: email.map(str::to_string),
            detail: detail.to_string(),
        };
        let _ = self.store.append_history(&entry);
    }
}

pub fn opt_str<'a>(m: &'a clap::ArgMatches, id: &str) -> Option<&'a str> {
    m.try_get_one::<String>(id)
        .ok()
        .flatten()
        .map(String::as_str)
}

pub fn explicit_account<'a>(m: &'a clap::ArgMatches, id: &str) -> Option<&'a str> {
    opt_str(m, id).or_else(|| opt_str(m, "use_account"))
}

pub fn opt_flag(m: &clap::ArgMatches, id: &str) -> bool {
    m.try_get_one::<bool>(id)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

pub fn format_duration_secs(secs: i64) -> String {
    let total_mins = (secs.max(0)) / 60;
    let days = total_mins / (24 * 60);
    let hours = (total_mins % (24 * 60)) / 60;
    let mins = total_mins % 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

pub fn format_reset_countdown(reset_at_unix: Option<i64>, now_unix: i64) -> String {
    let Some(at) = reset_at_unix else {
        return "-".to_string();
    };
    let diff = at - now_unix;
    if diff <= 0 {
        "due".to_string()
    } else {
        format_duration_secs(diff)
    }
}

pub fn parse_duration_secs(raw: &str) -> Result<i64, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if matches!(trimmed.as_str(), "0" | "reset" | "clear" | "none") {
        return Ok(0);
    }
    if trimmed.is_empty() {
        return Err("duration must not be empty".to_string());
    }
    let max_secs: i64 = 7 * 24 * 3600;
    if trimmed.bytes().all(|b| b.is_ascii_digit()) {
        let mins: i64 = trimmed
            .parse()
            .map_err(|_| "invalid duration".to_string())?;
        let secs = mins
            .checked_mul(60)
            .ok_or_else(|| "duration overflow".to_string())?;
        if secs > max_secs {
            return Err("duration exceeds maximum of 7d".to_string());
        }
        return Ok(secs);
    }
    let mut total: i64 = 0;
    let mut num = String::new();
    let mut prev_rank = 0u8;
    for ch in trimmed.chars() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        if ch.is_ascii_digit() {
            num.push(ch);
            continue;
        }
        if num.is_empty() {
            return Err(format!("invalid duration {raw:?}"));
        }
        let count: i64 = num
            .parse()
            .map_err(|_| format!("invalid duration {raw:?}"))?;
        num.clear();
        let (rank, mult) = match ch {
            'd' => (1u8, 86_400i64),
            'h' => (2u8, 3_600i64),
            'm' => (3u8, 60i64),
            's' => (4u8, 1i64),
            _ => return Err(format!("invalid duration unit {ch:?}")),
        };
        if rank <= prev_rank {
            return Err(format!("out-of-order duration unit in {raw:?}"));
        }
        prev_rank = rank;
        let add = count
            .checked_mul(mult)
            .ok_or_else(|| "duration overflow".to_string())?;
        total = total
            .checked_add(add)
            .ok_or_else(|| "duration overflow".to_string())?;
    }
    if !num.is_empty() || total > max_secs {
        return Err(format!("invalid or out-of-range duration {raw:?}"));
    }
    Ok(total)
}

pub fn parse_family(raw: &str) -> Result<ModelFamily, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gemini" => Ok(ModelFamily::Gemini),
        "claude" | "other" | "claude-gpt" | "third-party" => Ok(ModelFamily::Claude),
        "gpt" => Ok(ModelFamily::Gpt),
        "argon" => Ok(ModelFamily::Argon),
        other => Err(format!(
            "invalid model family {other:?} (expected gemini, claude, gpt, or argon)"
        )),
    }
}

pub fn family_name(family: ModelFamily) -> &'static str {
    match family {
        ModelFamily::Gemini => "gemini",
        ModelFamily::Claude => "claude",
        ModelFamily::Gpt => "gpt",
        ModelFamily::Argon => "argon",
    }
}

fn is_management_subcommand(s: &str) -> bool {
    matches!(
        s,
        "add"
            | "login"
            | "import-current"
            | "list"
            | "limits"
            | "limit"
            | "image"
            | "switch"
            | "activate"
            | "next"
            | "switch-next"
            | "rotate"
            | "remove"
            | "rm"
            | "status"
            | "current"
            | "logout"
            | "verify"
            | "verify-accounts"
            | "account"
            | "alias"
            | "tag"
            | "profile"
            | "bind"
            | "recommend"
            | "ensure-active"
            | "resolve-route"
            | "rotate-after-failure"
            | "quota-policy"
            | "switch-mode"
            | "doctor"
            | "config"
            | "watch"
            | "ack-restart"
            | "history"
            | "stats"
            | "forecast"
            | "backup"
            | "statusline"
            | "metrics"
            | "install-agy"
            | "update"
            | "version"
            | "completion"
            | "__dump-frame"
    )
}

fn normalize_forwarded_agy_args(raw: &[String]) -> Vec<String> {
    let mut slice = raw;
    if slice.first().map(String::as_str) == Some("run") {
        slice = &slice[1..];
    }
    if slice.first().map(String::as_str) == Some("now") {
        slice = &slice[1..];
    }
    if slice.first().map(String::as_str) == Some("--") {
        slice = &slice[1..];
    }
    slice.to_vec()
}

pub fn execute_isolated_for_selector(selector: &str, agy_args: &[String]) -> i32 {
    let paths = match detect_paths() {
        Ok(p) => p,
        Err(err) => {
            eprintln!("agy-swap-rs: {err}");
            return 1;
        }
    };
    let ctx = AppContext::new(paths, false, false);
    harvest_all_overlays(&ctx.paths, &ctx.store, &ctx.vault);
    let accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("agy-swap-rs: {err}");
            return 1;
        }
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let Some(email) = ctx.resolve_selector(&accounts, &settings, selector) else {
        eprintln!("agy-swap-rs: use-account: account {selector:?} not found");
        return 1;
    };
    match agy_core::isolate::run_isolated_agy(&ctx.paths, &ctx.store, &ctx.vault, &email, agy_args)
    {
        Ok(code) => {
            ctx.record_history("isolated_run", Some(&email), "isolated agy session");
            code
        }
        Err(err) => {
            eprintln!("agy-swap-rs: isolated run failed for {email}: {err}");
            1
        }
    }
}

fn is_known_top_level_flag(s: &str) -> bool {
    matches!(
        s,
        "-h" | "--help"
            | "-V"
            | "--version"
            | "--json"
            | "--verbose"
            | "--refresh"
            | "--force"
            | "--family"
            | "--add"
            | "--token"
            | "--list"
            | "--next"
            | "--auto-rotate"
            | "--switch-to"
            | "--switch"
            | "--remove"
            | "--status"
            | "--logout"
            | "help"
    ) || s.starts_with("--family=")
        || s.starts_with("--token=")
        || s.starts_with("--switch-to=")
        || s.starts_with("--remove=")
}

pub fn try_run_isolated_wrapper(argv: &[String]) -> Option<i32> {
    let first = argv.first()?.as_str();
    if first == "run" {
        let mut sel: Option<String> = None;
        let mut forward: Vec<String> = Vec::new();
        let mut i = 1usize;
        let mut passthrough = false;
        while i < argv.len() {
            let cur = argv[i].as_str();
            if passthrough {
                forward.push(argv[i].clone());
                i += 1;
                continue;
            }
            if cur == "--" {
                passthrough = true;
                i += 1;
                continue;
            }
            if (cur == "--help" || cur == "-h") && sel.is_none() && forward.is_empty() {
                return None;
            }
            if let Some(v) = cur.strip_prefix("--use-account=") {
                sel = Some(v.trim().to_string());
                i += 1;
                continue;
            }
            if cur == "--use-account" {
                sel = argv.get(i + 1).map(|s| s.trim().to_string());
                i += 2;
                continue;
            }
            forward.push(argv[i].clone());
            i += 1;
        }
        let Some(chosen) = sel.filter(|s| !s.is_empty()) else {
            eprintln!("agy-swap-rs: error: --use-account=<slot|alias|email> is required for 'run' (no default account is used).");
            return Some(2);
        };
        let cleaned = normalize_forwarded_agy_args(&forward);
        return Some(execute_isolated_for_selector(&chosen, &cleaned));
    }

    let mut sel: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut after_sep = false;
    while i < argv.len() {
        let cur = argv[i].as_str();
        if after_sep {
            rest.push(argv[i].clone());
            i += 1;
            continue;
        }
        if cur == "--" {
            after_sep = true;
            i += 1;
            continue;
        }
        if cur.starts_with("--use-family") {
            eprintln!("agy-swap-rs: error: --use-account=<slot|alias|email> is required (automatic family selection is disabled; no default account is used).");
            return Some(2);
        }
        if let Some(v) = cur.strip_prefix("--use-account=") {
            if v.trim().is_empty() {
                eprintln!("agy-swap-rs: error: --use-account=<slot|alias|email> requires a non-empty selector.");
                return Some(2);
            }
            sel = Some(v.trim().to_string());
            i += 1;
            continue;
        }
        if cur == "--use-account" {
            let Some(v) = argv.get(i + 1).map(|s| s.trim()).filter(|s| !s.is_empty()) else {
                eprintln!("agy-swap-rs: error: --use-account=<slot|alias|email> requires an account selector.");
                return Some(2);
            };
            sel = Some(v.to_string());
            i += 2;
            continue;
        }
        rest.push(argv[i].clone());
        i += 1;
    }

    let first_non_acct = rest.first().map(String::as_str);
    if let Some(chosen) = sel {
        if let Some(sub) = first_non_acct {
            if is_management_subcommand(sub) {
                return None;
            }
        }
        let cleaned = normalize_forwarded_agy_args(&rest);
        return Some(execute_isolated_for_selector(&chosen, &cleaned));
    }

    if !is_management_subcommand(first) && !is_known_top_level_flag(first) {
        eprintln!(
            "agy-swap-rs: error: --use-account=<slot|alias|email> is required when invoking agy from the CLI (no default account is used).\nexample: agy-swap-rs --use-account=1 {}",
            argv.join(" ")
        );
        return Some(2);
    }

    None
}

pub fn run(argv: &[String]) -> i32 {
    let cli = args::build_cli();
    let iter = core::iter::once("agy-swap-rs".to_string()).chain(argv.iter().cloned());
    let matches = match cli.try_get_matches_from(iter) {
        Ok(m) => m,
        Err(err) => match err.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                print!("{err}");
                return 0;
            }
            _ => {
                eprint!("{err}");
                eprintln!(
                    "agy-swap-rs: error: pass --use-account=<slot|alias|email> to run agy or specify a valid subcommand (no default account is used)."
                );
                return 2;
            }
        },
    };

    let json_flag = matches.get_flag("json");
    let verbose = matches.get_flag("verbose");
    if matches.subcommand_name() == Some("version") {
        return admin::cmd_version(json_flag);
    }
    if let Some(("completion", sub_m)) = matches.subcommand() {
        return admin::cmd_completion(sub_m, json_flag);
    }

    let paths = match detect_paths() {
        Ok(p) => p,
        Err(err) => {
            if json_flag {
                println!(
                    "{}",
                    json!({"schema_version": 1, "command": "init", "ok": false, "error": err.to_string()})
                );
            } else {
                eprintln!("agy-swap-rs: {err}");
            }
            return 1;
        }
    };
    let ctx = AppContext::new(paths, json_flag, verbose);

    if let Some(("__dump-frame", sub_m)) = matches.subcommand() {
        return admin::cmd_dump_frame(&ctx, sub_m);
    }

    let skip_reconcile = matches!(
        matches.subcommand_name(),
        Some(
            "alias"
                | "tag"
                | "profile"
                | "bind"
                | "config"
                | "history"
                | "stats"
                | "backup"
                | "import-current"
                | "login"
                | "add"
        )
    );
    if !skip_reconcile {
        harvest_all_overlays(&ctx.paths, &ctx.store, &ctx.vault);
        let _ = ctx.session.reconcile_active_session(&ctx.store, &ctx.vault);
    }

    if let Some((name, sub_m)) = matches.subcommand() {
        return match name {
            "add" => accounts::cmd_add(&ctx, sub_m),
            "login" => accounts::cmd_login(&ctx, sub_m),
            "import-current" => accounts::cmd_import_current(&ctx, sub_m),
            "list" => accounts::cmd_list(&ctx, sub_m),
            "limits" => accounts::cmd_limits(&ctx, sub_m),
            "limit" => accounts::cmd_limit(&ctx, sub_m),
            "image" => image::cmd_image(&ctx, sub_m),
            "switch" => accounts::cmd_switch(&ctx, sub_m),
            "next" => accounts::cmd_next(&ctx, sub_m),
            "remove" => accounts::cmd_remove(&ctx, sub_m),
            "status" => accounts::cmd_status(&ctx, sub_m),
            "logout" => accounts::cmd_logout(&ctx),
            "verify" => accounts::cmd_verify(&ctx, sub_m),
            "account" => accounts::cmd_account(&ctx, sub_m),
            "alias" => routing::cmd_alias(&ctx, sub_m),
            "tag" => routing::cmd_tag(&ctx, sub_m),
            "profile" => routing::cmd_profile(&ctx, sub_m),
            "bind" => routing::cmd_bind(&ctx, sub_m),
            "recommend" => routing::cmd_recommend(&ctx, sub_m),
            "ensure-active" => routing::cmd_ensure_active(&ctx, sub_m),
            "resolve-route" => routing::cmd_resolve_route(&ctx, sub_m),
            "rotate-after-failure" => routing::cmd_rotate_after_failure(&ctx, sub_m),
            "quota-policy" => routing::cmd_quota_policy(&ctx, sub_m),
            "switch-mode" => routing::cmd_switch_mode(&ctx, sub_m),
            "run" => routing::cmd_run(&ctx, sub_m),
            "doctor" => admin::cmd_doctor(&ctx, sub_m),
            "config" => admin::cmd_config(&ctx, sub_m),
            "watch" => admin::cmd_watch(&ctx, sub_m),
            "ack-restart" => admin::cmd_ack_restart(&ctx),
            "history" => admin::cmd_history(&ctx, sub_m),
            "stats" => admin::cmd_stats(&ctx),
            "forecast" => admin::cmd_forecast(&ctx, sub_m),
            "backup" => admin::cmd_backup(&ctx, sub_m),
            "statusline" => admin::cmd_statusline(&ctx, sub_m),
            "metrics" => admin::cmd_metrics(&ctx, sub_m),
            "install-agy" => admin::cmd_install_agy(&ctx, sub_m),
            "update" => admin::cmd_update(&ctx, sub_m),
            _ => ctx.fail("cli", format!("unknown subcommand {name:?}")),
        };
    }

    if matches.get_flag("legacy_add") || matches.get_one::<String>("token").is_some() {
        return accounts::cmd_add(&ctx, &matches);
    }
    if matches.get_flag("legacy_logout") {
        return accounts::cmd_logout(&ctx);
    }
    if matches.get_flag("legacy_next") || matches.get_flag("auto_rotate") {
        return accounts::cmd_next(&ctx, &matches);
    }
    if let Some(target) = matches.get_one::<String>("switch_to") {
        return accounts::switch_by_selector(&ctx, target, matches.get_flag("force"));
    }
    if matches.get_flag("legacy_switch") {
        return accounts::cmd_switch(&ctx, &matches);
    }
    if let Some(target) = matches.get_one::<String>("legacy_remove") {
        return accounts::remove_by_selector(&ctx, target, matches.get_flag("force"));
    }
    if matches.get_flag("legacy_status") {
        return accounts::cmd_status(&ctx, &matches);
    }
    if matches.get_flag("legacy_list") {
        return accounts::cmd_list(&ctx, &matches);
    }
    eprintln!(
        "agy-swap-rs: error: --use-account=<slot|alias|email> is required in CLI mode (no default account is used)."
    );
    2
}
