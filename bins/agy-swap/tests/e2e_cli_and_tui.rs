use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use agy_core::{Error, Paths, PoolQuota, PoolWindow, QuotaSnapshot, SessionManager, Store, Vault};
use agy_tui::{diff_ansi, Frame, HitId, HitMap, PointerShape, Rect, Style, Surface};
use serde_json::{json, Value};

static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

fn make_oauth_token(email: &str, access_token: &str, refresh_token: &str, expiry_unix: i64) -> String {
    let rfc3339 = agy_core::paths::format_rfc3339_utc(expiry_unix);
    serde_json::to_string(&json!({
        "email": email,
        "token": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expiry": rfc3339,
            "expiry_date": expiry_unix * 1000,
        }
    }))
    .expect("serialize oauth token")
}

struct E2eEnv {
    root: PathBuf,
    home: PathBuf,
    config_dir: PathBuf,
    paths: Paths,
}

impl E2eEnv {
    fn new(label: &str) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let root = PathBuf::from(format!("/tmp/agy-swap-e2e-{pid}-{seq}-{label}"));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let config_dir = root.join("config");
        let bin_dir = root.join("bin");
        std::fs::create_dir_all(&home).expect("create isolated HOME");
        std::fs::create_dir_all(&config_dir).expect("create isolated config_dir");
        std::fs::create_dir_all(&bin_dir).expect("create isolated bin_dir");
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 config_dir");
        let home_str = home.to_str().expect("utf8 home");
        let cfg_str = config_dir.to_str().expect("utf8 config_dir");
        let paths = Paths::from_home_and_config(home_str, cfg_str);
        Self { root, home, config_dir, paths }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-swap-rs"));
        let path_env = format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.root.join("bin").display());
        c.env_clear()
            .env("PATH", path_env)
            .env("HOME", &self.home)
            .env("AGY_SWAP_CONFIG_DIR", &self.config_dir)
            .env("AGY_SWAP_VAULT", "file")
            .env("AGY_SWAP_SESSION_STORE", "file")
            .env("AGY_SWAP_MIRROR_OS_KEYRING", "0")
            .env("AGY_SWAP_OFFLINE", "1")
            .env("NO_COLOR", "1")
            .env("TERM", "xterm-256color");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().expect("spawn agy-swap")
    }

    fn run_with_stdin(&self, args: &[&str], stdin_data: &str) -> Output {
        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn agy-swap with stdin");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_data.as_bytes()).expect("write stdin payload");
        }
        child.wait_with_output().expect("wait agy-swap")
    }

    fn run_ok_json(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "expected success for {:?}, status={:?}, stdout={}, stderr={}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        let parsed: Value = serde_json::from_slice(&out.stdout).expect("valid JSON stdout");
        assert_eq!(parsed.get("ok").and_then(Value::as_bool), Some(true));
        parsed
    }

    fn run_ok_json_stdin(&self, args: &[&str], stdin_data: &str) -> Value {
        let out = self.run_with_stdin(args, stdin_data);
        assert!(
            out.status.success(),
            "expected success for {:?}, status={:?}, stdout={}, stderr={}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        let parsed: Value = serde_json::from_slice(&out.stdout).expect("valid JSON stdout");
        assert_eq!(parsed.get("ok").and_then(Value::as_bool), Some(true));
        parsed
    }

    fn add_account(&self, email: &str, name: &str, access: &str, refresh: &str, expiry_unix: i64) {
        let tok = make_oauth_token(email, access, refresh, expiry_unix);
        let _ = self.run_ok_json_stdin(
            &["add", "--token", "-", "--email", email, "--name", name, "--json"],
            &tok,
        );
    }

    fn seed_quota(&self, email: &str, gem_pct: f64, cg_pct: f64, argon_pct: Option<f64>, now_unix: i64) {
        let store = Store::new(self.paths.clone());
        let mut accounts = store.load().expect("load store for quota seed");
        let acc = accounts.get_mut(email).expect("account present for quota seed");
        let mut gem = PoolQuota::new("Gemini");
        gem.five_hour = PoolWindow::new(Some(gem_pct), Some(now_unix + 3600));
        gem.weekly = PoolWindow::new(Some((gem_pct + 5.0).min(100.0)), Some(now_unix + 86_400 * 3));
        let mut cg = PoolQuota::new("Claude/GPT");
        cg.five_hour = PoolWindow::new(Some(cg_pct), Some(now_unix + 5400));
        cg.weekly = PoolWindow::new(Some((cg_pct + 8.0).min(100.0)), Some(now_unix + 86_400 * 4));
        let argon = argon_pct.map(|p| {
            let mut pool = PoolQuota::new("Gemini 4 Argon");
            pool.weekly = PoolWindow::new(Some(p), Some(now_unix + 86_400 * 5));
            pool
        });
        acc.quota = Some(QuotaSnapshot {
            fetched_at_unix: now_unix,
            project_id: Some("agy-e2e-proj".to_string()),
            plan_tier: Some("Google AI Pro".to_string()),
            gemini: gem,
            claude_gpt: cg,
            argon,
            extra_pools: Vec::new(),
        });
        store.save(&mut accounts).expect("save seeded quota");
    }
}

impl Drop for E2eEnv {
    fn drop(&mut self) {
        let ide_dir = self.home.join(".gemini/antigravity");
        if ide_dir.exists() {
            let _ = std::fs::set_permissions(&ide_dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assert_mode_0600(path: &str) {
    let meta = std::fs::metadata(path).unwrap_or_else(|e| panic!("stat {path}: {e}"));
    assert_eq!(meta.permissions().mode() & 0o777, 0o600, "expected 0600 on {path}");
}

#[test]
fn e2e_account_lifecycle_ordering_permissions_and_locking() {
    let env = E2eEnv::new("lifecycle");
    let now = agy_core::paths::wall_unix_secs();
    env.add_account("zeta@example.com", "Zeta User", "ya29.zeta-1", "1//rt-zeta", now + 3600);
    env.add_account("alpha@example.com", "Alpha User", "ya29.alpha-1", "1//rt-alpha", now + 3600);
    env.add_account("gamma@example.com", "Gamma User", "ya29.gamma-1", "1//rt-gamma", now + 3600);

    assert_mode_0600(&env.paths.accounts_file);
    assert_mode_0600(&env.paths.vault_file);
    let raw_accounts = std::fs::read_to_string(&env.paths.accounts_file).expect("read accounts.json");
    assert!(!raw_accounts.contains("ya29."), "accounts.json must not contain plaintext access tokens");
    assert!(!raw_accounts.contains("1//rt-"), "accounts.json must not contain refresh tokens");
    let pos_zeta = raw_accounts.find("zeta@example.com").expect("zeta in accounts.json");
    let pos_alpha = raw_accounts.find("alpha@example.com").expect("alpha in accounts.json");
    let pos_gamma = raw_accounts.find("gamma@example.com").expect("gamma in accounts.json");
    assert!(pos_zeta < pos_alpha && pos_alpha < pos_gamma, "insertion order must be preserved");

    let _ = env.run_ok_json(&["alias", "set", "work", "alpha@example.com", "--json"]);
    let _ = env.run_ok_json(&["tag", "add", "2", "prod", "--json"]);

    let sw1 = env.run_ok_json(&["switch", "1", "--json"]);
    assert_eq!(sw1["data"]["active"].as_str(), Some("zeta@example.com"));
    let sw_alias = env.run_ok_json(&["switch", "work", "--json"]);
    assert_eq!(sw_alias["data"]["active"].as_str(), Some("alpha@example.com"));
    let sw_email = env.run_ok_json(&["switch", "gamma@example.com", "--json"]);
    assert_eq!(sw_email["data"]["active"].as_str(), Some("gamma@example.com"));

    let filtered = env.run_ok_json(&["list", "--tag", "prod", "--json"]);
    let rows = filtered["data"]["accounts"].as_array().expect("accounts array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["email"].as_str(), Some("alpha@example.com"));

    let _ = env.run_ok_json(&["remove", "1", "--json"]);
    let vault = Vault::new(env.paths.clone());
    assert!(vault.get("account:zeta@example.com").expect("vault lookup").is_none());
    assert!(vault.get("account:alpha@example.com").expect("vault lookup").is_some());

    let store = Store::new(env.paths.clone());
    let mut copy_a = store.load().expect("load copy_a");
    let mut copy_b = store.load().expect("load copy_b");
    copy_a.get_mut("alpha@example.com").expect("alpha").name = "Alpha Updated".to_string();
    store.save(&mut copy_a).expect("save copy_a");
    copy_b.get_mut("gamma@example.com").expect("gamma").name = "Stale Write".to_string();
    assert_eq!(store.save(&mut copy_b), Err(Error::Conflict));

    let lock_a = eko::file::File::append(&env.paths.accounts_lock).expect("open lock_a");
    lock_a.lock_exclusive(true).expect("acquire nonblocking flock on lock_a");
    let lock_b = eko::file::File::append(&env.paths.accounts_lock).expect("open lock_b");
    assert!(lock_b.lock_exclusive(true).is_err(), "second nonblocking flock must contend");
    lock_a.unlock().expect("unlock lock_a");
    lock_b.lock_exclusive(true).expect("acquire flock after unlock");
    lock_b.unlock().expect("unlock lock_b");
}

#[test]
fn e2e_session_switch_rollback_and_reconcile_harvest() {
    let env = E2eEnv::new("session");
    let now = agy_core::paths::wall_unix_secs();
    env.add_account("alpha@example.com", "Alpha", "ya29.alpha-v1", "1//rt-alpha", now + 1800);
    env.add_account("beta@example.com", "Beta", "ya29.beta-v1", "1//rt-beta", now + 1800);

    let _ = env.run_ok_json(&["switch", "alpha@example.com", "--json"]);
    assert_mode_0600(&env.paths.agy_oauth_file);
    assert_mode_0600(&env.paths.google_accounts_file());
    let initial_tok = std::fs::read_to_string(&env.paths.agy_oauth_file).expect("read agy oauth");
    assert!(initial_tok.contains("ya29.alpha-v1"));

    let creds = PathBuf::from(env.paths.oauth_creds_file());
    let _ = std::fs::remove_file(&creds);
    std::fs::create_dir_all(creds.join("block")).expect("create obstructing dir");

    let failed = env.run(&["switch", "beta@example.com", "--json"]);
    let _ = std::fs::remove_dir_all(&creds);
    assert!(!failed.status.success(), "switch must fail when target step fails");

    let after_rollback = std::fs::read_to_string(&env.paths.agy_oauth_file).expect("read rolled-back oauth");
    assert!(after_rollback.contains("ya29.alpha-v1"), "rollback must preserve alpha token");
    assert!(!after_rollback.contains("ya29.beta-v1"), "rollback must not leak beta token");
    let session = SessionManager::new(env.paths.clone());
    assert_eq!(session.current_email().as_deref(), Some("alpha@example.com"));

    let refreshed = make_oauth_token("alpha@example.com", "ya29.alpha-refreshed-v2", "1//rt-alpha", now + 7200);
    for target in [
        env.paths.agy_oauth_file.clone(),
        env.paths.ide_oauth_file(),
        env.paths.jetski_oauth_file(),
    ] {
        std::fs::write(&target, &refreshed).expect("write refreshed live token");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("0600");
    }
    let sync_out = env.run(&["--sync-session"]);
    assert!(sync_out.status.success(), "--sync-session must exit 0");
    let vault = Vault::new(env.paths.clone());
    let harvested = vault
        .get("account:alpha@example.com")
        .expect("vault read")
        .expect("alpha secret exists");
    assert!(harvested.contains("ya29.alpha-refreshed-v2"), "vault must harvest fresher live token");
}

#[test]
fn e2e_encrypted_backup_roundtrip_and_wrong_passphrase() {
    let env = E2eEnv::new("backup");
    let now = agy_core::paths::wall_unix_secs();
    env.add_account("alpha@example.com", "Alpha", "ya29.secret-alpha-999", "1//rt-sec-a", now + 3600);
    env.add_account("beta@example.com", "Beta", "ya29.secret-beta-888", "1//rt-sec-b", now + 3600);
    let _ = env.run_ok_json(&["alias", "set", "pri", "alpha@example.com", "--json"]);
    let _ = env.run_ok_json(&["switch-mode", "manual", "--json"]);

    let backup_file = env.root.join("encrypted-backup.json");
    let backup_str = backup_file.to_str().expect("utf8 backup path");
    let exp = env.run_ok_json_stdin(
        &["backup", "export", backup_str, "--include-secrets", "--passphrase-stdin", "--json"],
        "correct-horse-battery-staple\n",
    );
    assert_eq!(exp["data"]["contains_secrets"].as_bool(), Some(true));
    assert_mode_0600(backup_str);

    let raw_backup = std::fs::read_to_string(&backup_file).expect("read backup");
    assert!(!raw_backup.contains("ya29.secret-alpha-999"), "plaintext access token must never hit disk");
    assert!(!raw_backup.contains("1//rt-sec-a"), "plaintext refresh token must never hit disk");
    assert!(raw_backup.contains("aes-256-gcm"));
    assert!(raw_backup.contains("pbkdf2-hmac-sha256"));

    let wrong_verify = env.run_with_stdin(
        &["backup", "verify", backup_str, "--passphrase-stdin", "--json"],
        "wrong-passphrase\n",
    );
    assert!(!wrong_verify.status.success(), "wrong passphrase must fail AES-GCM tag check");
    let ok_verify = env.run_ok_json_stdin(
        &["backup", "verify", backup_str, "--passphrase-stdin", "--json"],
        "correct-horse-battery-staple\n",
    );
    assert_eq!(ok_verify["data"]["secrets"].as_u64(), Some(2));

    let _ = std::fs::remove_file(&env.paths.accounts_file);
    let _ = std::fs::remove_file(&env.paths.vault_file);
    let _ = std::fs::remove_file(&env.paths.settings_file);
    env.add_account("gamma@example.com", "Gamma", "ya29.secret-gamma-777", "1//rt-sec-g", now + 3600);

    let wrong_import = env.run_with_stdin(
        &["backup", "import", backup_str, "--merge", "--passphrase-stdin", "--json"],
        "wrong-passphrase\n",
    );
    assert!(!wrong_import.status.success(), "backup import must reject wrong passphrase");

    let imp = env.run_ok_json_stdin(
        &["backup", "import", backup_str, "--merge", "--passphrase-stdin", "--json"],
        "correct-horse-battery-staple\n",
    );
    assert_eq!(imp["data"]["secrets_restored"].as_u64(), Some(2));

    let vault = Vault::new(env.paths.clone());
    let dec_alpha = vault.get("account:alpha@example.com").expect("vault").expect("alpha secret");
    let dec_gamma = vault.get("account:gamma@example.com").expect("vault").expect("gamma secret");
    assert!(dec_alpha.contains("ya29.secret-alpha-999"));
    assert!(dec_gamma.contains("ya29.secret-gamma-777"));
}

#[test]
fn e2e_logwatch_429_tailer_failover_dedupe_and_ack_restart() {
    let env = E2eEnv::new("logwatch");
    let now = agy_core::paths::wall_unix_secs();
    env.add_account("alpha@example.com", "Alpha", "ya29.alpha-lw", "1//rt-alpha-lw", now + 3600);
    env.add_account("beta@example.com", "Beta", "ya29.beta-lw", "1//rt-beta-lw", now + 3600);
    env.seed_quota("alpha@example.com", 82.0, 78.0, None, now);
    env.seed_quota("beta@example.com", 96.0, 94.0, None, now);
    let _ = env.run_ok_json(&["switch", "alpha@example.com", "--json"]);
    let _ = env.run_ok_json(&["switch-mode", "auto", "--json"]);

    let cli_log = PathBuf::from(env.paths.cli_log_file());
    std::fs::create_dir_all(cli_log.parent().expect("cli.log parent")).expect("mkdir log parent");
    std::fs::write(
        &cli_log,
        "2026-11-23T07:00:00Z ERROR claude-sonnet-4 RESOURCE_EXHAUSTED (code 429): Individual quota reached\n",
    )
    .expect("seed historical 429 line");

    let init_poll = env.run_ok_json(&["watch", "--once", "--json"]);
    assert!(init_poll["data"]["failover"].is_null(), "initial EOF cursor poll must skip historical lines");
    assert_eq!(init_poll["data"]["active"].as_str(), Some("alpha@example.com"));

    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&cli_log).expect("append cli.log");
        writeln!(
            f,
            "2026-11-23T08:05:00Z ERROR claude-sonnet-4 RESOURCE_EXHAUSTED (code 429): Individual quota reached"
        )
        .expect("append live 429");
    }
    let rotated = env.run_ok_json(&["watch", "--once", "--json"]);
    assert_eq!(rotated["data"]["failover"]["outcome"].as_str(), Some("switched"));
    assert_eq!(rotated["data"]["failover"]["previous"].as_str(), Some("alpha@example.com"));
    assert_eq!(rotated["data"]["failover"]["switched_to"].as_str(), Some("beta@example.com"));
    assert_eq!(rotated["data"]["active"].as_str(), Some("beta@example.com"));
    assert_eq!(rotated["data"]["runtime"]["restart_agy_needed"].as_bool(), Some(true));

    let store = Store::new(env.paths.clone());
    let accounts = store.load().expect("reload accounts");
    assert!(!accounts.get("alpha@example.com").expect("alpha").cooldowns.is_empty());

    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&cli_log).expect("append cli.log");
        writeln!(
            f,
            "2026-11-23T08:05:01Z ERROR claude-sonnet-4 RESOURCE_EXHAUSTED (code 429): Individual quota reached"
        )
        .expect("append repeat burst 429");
    }
    let dedup = env.run_ok_json(&["watch", "--once", "--json"]);
    assert_eq!(dedup["data"]["failover"]["outcome"].as_str(), Some("already_switched"));
    assert_eq!(dedup["data"]["active"].as_str(), Some("beta@example.com"));

    let ack = env.run_ok_json(&["ack-restart", "--json"]);
    assert_eq!(ack["data"]["restart_agy_needed"].as_bool(), Some(false));
    assert_eq!(ack["data"]["runtime"]["restart_agy_needed"].as_bool(), Some(false));
}

#[test]
fn e2e_headless_tui_breakpoints_gauges_hitmap_and_diff_ansi() {
    let env = E2eEnv::new("tui");
    let now = agy_core::paths::wall_unix_secs();
    env.add_account("alpha@example.com", "Alpha Primary", "ya29.alpha-tui", "1//rt-a-tui", now + 3600);
    env.add_account("beta@example.com", "Beta Standby", "ya29.beta-tui", "1//rt-b-tui", now + 3600);
    env.seed_quota("alpha@example.com", 84.0, 72.0, Some(91.0), now);
    env.seed_quota("beta@example.com", 22.0, 25.0, None, now);
    let _ = env.run_ok_json(&["switch", "alpha@example.com", "--json"]);

    for (dims, expected_bp, side_by_side) in [
        ("140x40", "Wide", true),
        ("100x30", "Medium", true),
        ("80x24", "Stacked", false),
        ("40x16", "Compact", false),
    ] {
        let frame = env.run_ok_json(&["__dump-frame", dims, "--json"]);
        let data = &frame["data"];
        assert_eq!(data["breakpoint"].as_str(), Some(expected_bp), "breakpoint for {dims}");
        let plain = data["plain"].as_str().expect("plain frame");
        assert!(plain.contains("AGY-SWAP"), "header brand missing at {dims}");
        assert!(plain.contains("alpha@example.com"), "active account missing at {dims}");
        assert!(plain.contains("READY"), "READY badge missing at {dims}");
        assert!(plain.contains('\u{2588}') || plain.contains('\u{2591}'), "gauge blocks missing at {dims}");
        assert!(data["hit_regions"].as_u64().unwrap_or(0) >= 5, "hit regions missing at {dims}");
        assert!(data["pointer_cells"].as_u64().unwrap_or(0) > 0, "clickable cells missing at {dims}");
        if side_by_side {
            assert!(data["col_resize_cells"].as_u64().unwrap_or(0) > 0, "split divider missing at {dims}");
        } else {
            assert!(data["row_resize_cells"].as_u64().unwrap_or(0) > 0, "stack divider missing at {dims}");
        }
        let ansi = data["ansi"].as_str().expect("ansi frame");
        assert!(ansi.starts_with("\x1b[?2026h"), "missing DECSET 2026 begin at {dims}");
        assert!(ansi.ends_with("\x1b[?2026l"), "missing DECSET 2026 end at {dims}");
    }

    let ascii_frame = env.run_ok_json(&["__dump-frame", "80x24", "--ascii", "--json"]);
    let ascii_plain = ascii_frame["data"]["plain"].as_str().expect("ascii plain");
    assert!(!ascii_plain.contains('\u{2588}'), "ASCII frame must not emit Unicode block gauges");
    assert!(ascii_plain.contains('#') || ascii_plain.contains('-'));

    let mut surf_a = Surface::new(40, 10);
    let mut hits = HitMap::new();
    {
        let mut f = Frame::new(&mut surf_a, &mut hits, false);
        f.surface.put_str(0, 0, 40, "AGY-SWAP Surface Check", Style::new().bold());
        f.surface.draw_gauge(Rect::new(0, 1, 20, 1), 62.5, Style::new(), Style::new(), false);
        f.hit(HitId(10), Rect::new(0, 0, 40, 4), PointerShape::Pointer);
        f.hit(HitId(99), Rect::new(8, 1, 16, 2), PointerShape::Default);
    }
    assert_eq!(hits.hit_test(10, 1), Some((HitId(99), PointerShape::Default)));
    assert_eq!(hits.hit_test(2, 1), Some((HitId(10), PointerShape::Pointer)));
    let mut full_ansi = Vec::new();
    diff_ansi(None, &surf_a, true, &mut full_ansi);
    let mut surf_b = surf_a.clone();
    surf_b.set_char(0, 2, 'X', Style::new());
    let mut delta_ansi = Vec::new();
    diff_ansi(Some(&surf_a), &surf_b, true, &mut delta_ansi);
    assert!(delta_ansi.len() < full_ansi.len(), "incremental diff_ansi must beat full redraw");
}

#[test]
fn e2e_concurrent_use_account_isolation_and_harvest() {
    let env = E2eEnv::new("concurrent_iso");
    let now = agy_core::paths::wall_unix_secs();
    env.add_account("acct1@example.com", "Account One", "ya29.acct1-v1", "1//rt-acct1", now + 1800);
    env.add_account("acct2@example.com", "Account Two", "ya29.acct2-v1", "1//rt-acct2", now + 1800);
    let _ = env.run_ok_json(&["alias", "set", "work", "acct2@example.com", "--json"]);

    let acct3_live = make_oauth_token("acct3@example.com", "ya29.acct3-v1", "1//rt-acct3", now + 1800);
    SessionManager::new(env.paths.clone())
        .switch_to("acct3@example.com", &acct3_live)
        .expect("seed active ~/.gemini session for acct3");
    let imported = env.run_ok_json(&["import-current", "--alias", "ide-main", "--name", "Account Three", "--json"]);
    assert_eq!(imported["data"]["email"].as_str(), Some("acct3@example.com"));
    assert_eq!(imported["data"]["alias"].as_str(), Some("ide-main"));
    assert_eq!(imported["data"]["active"].as_bool(), Some(true));

    env.seed_quota("acct1@example.com", 91.0, 83.0, Some(95.0), now);
    env.seed_quota("acct2@example.com", 67.0, 58.0, Some(80.0), now);
    env.seed_quota("acct3@example.com", 34.0, 29.0, None, now);

    let ver = env.run(&["version"]);
    assert!(ver.status.success());
    assert_eq!(
        String::from_utf8_lossy(&ver.stdout).trim(),
        format!("agy-swap-rs v{}", agy_core::VERSION)
    );

    for disallowed in [
        &[][..],
        &["-p", "hello"][..],
        &["run", "now"][..],
        &["switch"][..],
        &["remove"][..],
    ] {
        let out = env.run(disallowed);
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 without --use-account for {disallowed:?}, stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr_txt = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr_txt.contains("--use-account"),
            "stderr must name --use-account for {disallowed:?}, got: {stderr_txt}"
        );
    }

    let default_paths = Paths::from_home(env.home.to_str().expect("home utf8"));
    assert!(
        default_paths.config_dir.ends_with("/.config/agy-swap-rs"),
        "default config_dir must live in ~/.config/agy-swap-rs, never inside ~/.gemini: {}",
        default_paths.config_dir
    );
    std::fs::create_dir_all(env.home.join(".gemini/config")).expect("mkdir real .gemini/config");
    std::fs::write(env.home.join(".gemini/config/hooks.json"), b"{\"hooks\":{}}\n")
        .expect("seed real hooks.json");

    let mock_agy = env.root.join("bin/agy");
    let script = concat!(
        "#!/bin/sh\n",
        "set -eu\n",
        "report=\"$1\"\n",
        "ready=\"$2\"\n",
        "go=\"$3\"\n",
        "refreshed=\"$4\"\n",
        "printf '{\"isolated\":true}\\n' > \"$HOME/.gemini/config/isolated-write.json\"\n",
        "{\n",
        "  printf 'HOME=%s\\n' \"${HOME:-}\"\n",
        "  printf 'WSL_INTEROP=%s\\n' \"${WSL_INTEROP:-}\"\n",
        "  printf 'AGY_SWAP_SKIP_SYNC=%s\\n' \"${AGY_SWAP_SKIP_SYNC:-}\"\n",
        "  printf 'ACTIVE=%s\\n' \"$(cat \"$HOME/.gemini/google_accounts.json\")\"\n",
        "  printf 'TOKEN=%s\\n' \"$(cat \"$HOME/.gemini/antigravity-cli/antigravity-oauth-token\")\"\n",
        "} > \"$report\"\n",
        ": > \"$ready\"\n",
        "i=0\n",
        "while [ ! -f \"$go\" ] && [ \"$i\" -lt 120 ]; do\n",
        "  sleep 0.05\n",
        "  i=$((i + 1))\n",
        "done\n",
        "cp \"$refreshed\" \"$HOME/.gemini/antigravity-cli/antigravity-oauth-token\"\n",
        "chmod 600 \"$HOME/.gemini/antigravity-cli/antigravity-oauth-token\"\n",
        "exit 0\n",
    );
    std::fs::write(&mock_agy, script).expect("write mock agy");
    std::fs::set_permissions(&mock_agy, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 0755 mock agy");

    let report1 = env.root.join("report1.txt");
    let report2 = env.root.join("report2.txt");
    let ready1 = env.root.join("ready1");
    let ready2 = env.root.join("ready2");
    let go_file = env.root.join("go");
    let ref1_file = env.root.join("ref1.json");
    let ref2_file = env.root.join("ref2.json");
    std::fs::write(
        &ref1_file,
        make_oauth_token("acct1@example.com", "ya29.acct1-refreshed-v2", "1//rt-acct1", now + 7200),
    )
    .expect("write ref1");
    std::fs::write(
        &ref2_file,
        make_oauth_token("acct2@example.com", "ya29.acct2-refreshed-v2", "1//rt-acct2", now + 7200),
    )
    .expect("write ref2");

    let child1 = env
        .cmd()
        .args([
            "--use-account=1",
            "--",
            report1.to_str().unwrap(),
            ready1.to_str().unwrap(),
            go_file.to_str().unwrap(),
            ref1_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated child1");

    let child2 = env
        .cmd()
        .args([
            "run",
            "--use-account=work",
            "--",
            report2.to_str().unwrap(),
            ready2.to_str().unwrap(),
            go_file.to_str().unwrap(),
            ref2_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated child2");

    for _ in 0..120 {
        if ready1.exists() && ready2.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(ready1.exists() && ready2.exists(), "both concurrent isolated agy sessions must start");

    assert_eq!(agy_core::isolate::active_isolated_sessions(&env.paths, "acct1@example.com"), 1);
    assert_eq!(agy_core::isolate::active_isolated_sessions(&env.paths, "acct2@example.com"), 1);
    assert_eq!(agy_core::isolate::active_isolated_sessions(&env.paths, "acct3@example.com"), 0);

    let frame = env.run_ok_json(&["__dump-frame", "140x40", "--json"]);
    let plain = frame["data"]["plain"].as_str().expect("140x40 plain frame");
    assert!(plain.contains("AGY-SWAP-RS"), "140x40 frame must show AGY-SWAP-RS header");
    assert!(plain.contains("ALL-ACCOUNTS USAGE MATRIX"), "140x40 frame must show multi-account usage matrix");
    assert!(plain.contains("acct1@example.com"), "matrix must list acct1");
    assert!(plain.contains("acct2@example.com"), "matrix must list acct2");
    assert!(plain.contains("acct3@example.com"), "matrix must list acct3");
    assert!(plain.contains("[RUN]"), "live isolated sessions must render [RUN] indicator");

    std::fs::write(&go_file, b"go\n").expect("release barrier");
    let out1 = child1.wait_with_output().expect("wait child1");
    let out2 = child2.wait_with_output().expect("wait child2");
    assert!(out1.status.success(), "child1 failed: {}", String::from_utf8_lossy(&out1.stderr));
    assert!(out2.status.success(), "child2 failed: {}", String::from_utf8_lossy(&out2.stderr));

    assert_eq!(agy_core::isolate::active_isolated_sessions(&env.paths, "acct1@example.com"), 0);
    assert_eq!(agy_core::isolate::active_isolated_sessions(&env.paths, "acct2@example.com"), 0);

    let rep1 = std::fs::read_to_string(&report1).expect("read report1");
    let rep2 = std::fs::read_to_string(&report2).expect("read report2");
    let home1 = rep1.lines().find_map(|l| l.strip_prefix("HOME=")).expect("HOME in report1");
    let home2 = rep2.lines().find_map(|l| l.strip_prefix("HOME=")).expect("HOME in report2");
    let cfg_prefix = env.config_dir.to_str().expect("cfg utf8");
    assert_ne!(home1, home2, "isolated accounts must have distinct overlay HOMEs");
    assert!(home1.starts_with(cfg_prefix) && home1.contains("/homes/"));
    assert!(home2.starts_with(cfg_prefix) && home2.contains("/homes/"));
    assert_ne!(home1, env.home.to_str().unwrap());
    assert_ne!(home2, env.home.to_str().unwrap());
    assert!(rep1.contains("WSL_INTEROP=1") && rep1.contains("AGY_SWAP_SKIP_SYNC=1"));
    assert!(rep2.contains("WSL_INTEROP=1") && rep2.contains("AGY_SWAP_SKIP_SYNC=1"));
    assert!(rep1.contains("acct1@example.com") && rep1.contains("ya29.acct1-v1"));
    assert!(!rep1.contains("acct2@example.com") && !rep1.contains("acct3@example.com"));
    assert!(rep2.contains("acct2@example.com") && rep2.contains("ya29.acct2-v1"));
    assert!(!rep2.contains("acct1@example.com") && !rep2.contains("acct3@example.com"));

    let real_gemini_tok = std::fs::read_to_string(&env.paths.agy_oauth_file).expect("read real ~/.gemini token");
    assert!(real_gemini_tok.contains("ya29.acct3-v1"), "real ~/.gemini session must remain untouched");
    assert!(
        !env.home.join(".gemini/config/isolated-write.json").exists(),
        "isolated agy writes inside $HOME/.gemini/config must never leak into real ~/.gemini/config"
    );
    assert!(
        PathBuf::from(home1).join(".gemini/config/hooks.json").exists(),
        "isolated agy overlay must receive copied hooks.json"
    );
    assert_eq!(
        SessionManager::new(env.paths.clone()).current_email().as_deref(),
        Some("acct3@example.com")
    );

    let vault = Vault::new(env.paths.clone());
    let v1 = vault.get("account:acct1@example.com").expect("vault 1").expect("acct1 secret");
    let v2 = vault.get("account:acct2@example.com").expect("vault 2").expect("acct2 secret");
    assert!(v1.contains("ya29.acct1-refreshed-v2"), "isolated exit must harvest refreshed acct1 token");
    assert!(v2.contains("ya29.acct2-refreshed-v2"), "isolated exit must harvest refreshed acct2 token");
}
