//! Active Antigravity OAuth session switcher, rollback journal, IDE sync, and launcher guard.

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

use eko::command::Command;
use eko::file::File;
use eko::path::Path;
use serde_json::{Map, Value};

use crate::model::{normalize_email, Account, Accounts};
use crate::oauth::TokenBundle;
use crate::paths::{clean_path_str, hex_encode, join_path, sha256_hex, wall_unix_ns, Paths};
use crate::store::{atomic_write_mode, atomic_write_private, ensure_private_dir, FileLock, Store};
use crate::vault::{keychain_delete, keychain_get, keychain_set, Vault};
use crate::{Error, Result};

const GEMINI_KEYRING_SERVICE: &str = "gemini";
const GEMINI_KEYRING_ACCOUNT: &str = "antigravity";

fn use_keychain_session_store() -> bool {
    matches!(
        eko::env::var("AGY_SWAP_SESSION_STORE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "keychain" | "os"
    )
}

fn current_swap_exe() -> Option<String> {
    let bytes = eko::env::current_exe()?;
    let text = core::str::from_utf8(&bytes).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("/deps/") || lower.ends_with(".test") {
        return None;
    }
    let tmp = eko::env::temp_dir();
    if let Ok(tmp_str) = core::str::from_utf8(&tmp) {
        let clean_tmp = clean_path_str(tmp_str);
        if !clean_tmp.is_empty() && clean_tmp != "/" && text.starts_with(&clean_tmp) {
            return None;
        }
    }
    Some(text.to_string())
}

fn should_mirror_os_keyring(paths: &Paths) -> bool {
    if let Some(raw) = eko::env::var("AGY_SWAP_MIRROR_OS_KEYRING") {
        match raw.trim().to_ascii_lowercase().as_str() {
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
    if paths.home.is_empty()
        || paths.home.contains("/tmp/")
        || paths.home.contains("/var/folders/")
        || paths.home.contains(".tmp")
    {
        return false;
    }
    current_swap_exe().is_some()
}

fn snapshot_files(paths: &[String]) -> Result<Vec<(String, Option<Vec<u8>>)>> {
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        if let Ok(meta) = eko::file::symlink_metadata(path) {
            if meta.is_dir() {
                out.push((path.clone(), None));
                continue;
            }
        }
        match eko::file::read(path) {
            Ok(bytes) => out.push((path.clone(), Some(bytes))),
            Err(err) if err.is_not_found() => out.push((path.clone(), None)),
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Ok(out)
}

fn restore_snapshot(snapshot: &[(String, Option<Vec<u8>>)]) {
    for (path, content) in snapshot {
        match content {
            Some(bytes) => {
                let _ = atomic_write_private(path, bytes);
            }
            None => {
                if let Ok(meta) = eko::file::symlink_metadata(path) {
                    if !meta.is_dir() {
                        eko::file::remove_file(path);
                    }
                }
            }
        }
    }
}

fn sync_ide_onboarding_email(home: &str, email: &str) {
    let Some(norm_email) = normalize_email(email) else {
        return;
    };
    if home.trim().is_empty() {
        return;
    }
    let db_candidates = [
        join_path(
            home,
            "Library/Application Support/Antigravity IDE/User/globalStorage/state.vscdb",
        ),
        join_path(
            home,
            ".config/Antigravity IDE/User/globalStorage/state.vscdb",
        ),
    ];
    let select_sql = "SELECT value FROM ItemTable WHERE key = 'google.google-antigravity';";
    for db_path in &db_candidates {
        if !eko::file::exists(db_path) {
            continue;
        }
        let Some(out) = Command::new("sqlite3")
            .args(["-cmd", ".timeout 1500", db_path.as_str(), select_sql])
            .output()
        else {
            return;
        };
        if !out.success() {
            continue;
        }
        let stdout_text = String::from_utf8_lossy(&out.stdout);
        let trimmed = stdout_text.trim();
        let json_slice = match trimmed.find('{') {
            Some(idx) => &trimmed[idx..],
            None => continue,
        };
        let Ok(Value::Object(mut outer)) = serde_json::from_str::<Value>(json_slice) else {
            continue;
        };
        let Some(Value::Object(mut storage)) = outer.remove("antigravity-storage") else {
            continue;
        };
        if storage
            .get("agy.onboarding.lastLoginUsername")
            .and_then(Value::as_str)
            .is_some_and(|cur| cur.eq_ignore_ascii_case(&norm_email))
        {
            continue;
        }
        storage.insert(
            "agy.onboarding.lastLoginUsername".to_string(),
            Value::String(norm_email.clone()),
        );
        outer.insert("antigravity-storage".to_string(), Value::Object(storage));
        let Ok(updated_bytes) = serde_json::to_vec(&Value::Object(outer)) else {
            continue;
        };
        let hex_val = hex_encode(&updated_bytes);
        let update_sql = format!(
            "UPDATE ItemTable SET value = CAST(X'{hex_val}' AS TEXT) WHERE key = 'google.google-antigravity';"
        );
        let _ = Command::new("sqlite3")
            .args([
                "-cmd",
                ".timeout 1500",
                db_path.as_str(),
                update_sql.as_str(),
            ])
            .output();
    }
}

fn is_native_executable(header: &[u8]) -> bool {
    if header.len() < 4 {
        return false;
    }
    matches!(
        &header[..4],
        [0x7f, b'E', b'L', b'F']
            | [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
    )
}

fn read_header_bytes(path: &str, max_bytes: usize) -> Option<Vec<u8>> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn shell_quote_double(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn extract_wrapper_real_command(script: &str) -> Option<String> {
    for line in script.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("real_command=") else {
            continue;
        };
        let val = rest.trim().trim_matches('"');
        if val.is_empty() || val == "$HOME/.local/libexec/agy" {
            return None;
        }
        let unescaped = val
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
            .replace("\\$", "$")
            .replace("\\`", "`");
        return Some(unescaped);
    }
    None
}

fn build_agy_launcher_script(
    real_command: Option<&str>,
    preferred_swap: Option<&str>,
    reload_marker: &str,
    skip_perms_by_default: bool,
) -> String {
    let real_expr = match real_command.map(str::trim).filter(|s| !s.is_empty()) {
        Some(cmd) => shell_quote_double(cmd),
        None => "\"$HOME/.local/libexec/agy\"".to_string(),
    };
    let swap_expr = match preferred_swap.map(str::trim).filter(|s| !s.is_empty()) {
        Some(cmd) => shell_quote_double(cmd),
        None => "\"$HOME/.local/bin/agy-swap-rs\"".to_string(),
    };
    let marker_expr = if reload_marker.trim().is_empty() {
        "\"\"".to_string()
    } else {
        shell_quote_double(reload_marker.trim())
    };
    let exec_block = if skip_perms_by_default {
        "if [ \"${AGY_NORMAL_MODE:-0}\" = \"1\" ]; then\n  \"$real_command\" \"$@\"\nelse\n  \"$real_command\" --dangerously-skip-permissions \"$@\"\nfi"
    } else {
        "\"$real_command\" \"$@\""
    };
    format!(
        "#!/bin/sh\n# Managed by agy-swap session guard\nreal_command={real_expr}\ncase \"${{1:-}}\" in\n  --version|-v|--help)\n    exec \"$real_command\" \"$@\"\n    ;;\nesac\nswap_command={swap_expr}\nreload_marker={marker_expr}\nif [ ! -x \"$swap_command\" ]; then\n  for candidate in \"$HOME/.local/bin/agy-swap-rs\" \"$HOME/.cargo/bin/agy-swap-rs\" /opt/homebrew/bin/agy-swap-rs /usr/local/bin/agy-swap-rs \"$HOME/.local/bin/agy-swap\" /opt/homebrew/bin/agy-swap /usr/local/bin/agy-swap \"$HOME/.cargo/bin/agy-swap\"; do\n    if [ -x \"$candidate\" ]; then\n      swap_command=\"$candidate\"\n      break\n    fi\n  done\nfi\nif [ ! -x \"$swap_command\" ]; then\n  swap_command=\"$(command -v agy-swap-rs 2>/dev/null || command -v agy-swap 2>/dev/null || true)\"\nfi\nif [ \"${{AGY_SWAP_SKIP_SYNC:-0}}\" != \"1\" ] && [ -n \"$swap_command\" ] && [ -x \"$swap_command\" ]; then\n  \"$swap_command\" --sync-session >/dev/null 2>&1 || true\nfi\nexport WSL_INTEROP=\"${{WSL_INTEROP:-1}}\"\ncase \" $* \" in\n  *\" --hub \"*)\n    stopping=0\n    hub_pid=\"\"\n    window_start=\"$(date +%s)\"\n    window_restarts=0\n    trap 'stopping=1; if [ -n \"$hub_pid\" ]; then kill -TERM \"$hub_pid\" 2>/dev/null || true; wait \"$hub_pid\" 2>/dev/null || true; fi; exit 0' TERM INT HUP\n    while [ \"$stopping\" -eq 0 ]; do\n      marker_before=\"$(cat \"$reload_marker\" 2>/dev/null || true)\"\n      \"$real_command\" \"$@\" &\n      hub_pid=$!\n      wait \"$hub_pid\"\n      status=$?\n      hub_pid=\"\"\n      if [ \"$stopping\" -ne 0 ]; then\n        exit 0\n      fi\n      marker_after=\"$(cat \"$reload_marker\" 2>/dev/null || true)\"\n      if [ -z \"$reload_marker\" ] || [ \"$marker_after\" = \"$marker_before\" ]; then\n        exit \"$status\"\n      fi\n      now=\"$(date +%s)\"\n      if [ $((now - window_start)) -ge 10 ]; then\n        window_start=\"$now\"\n        window_restarts=0\n      fi\n      window_restarts=$((window_restarts + 1))\n      if [ \"$window_restarts\" -ge 10 ]; then\n        exit \"$status\"\n      fi\n      sleep 0.1\n      if [ \"${{AGY_SWAP_SKIP_SYNC:-0}}\" != \"1\" ] && [ -n \"$swap_command\" ] && [ -x \"$swap_command\" ]; then\n        \"$swap_command\" --sync-session >/dev/null 2>&1 || true\n      fi\n    done\n    exit 0\n    ;;\nesac\n{exec_block}\nstatus=$?\nif [ \"${{AGY_SWAP_SKIP_SYNC:-0}}\" != \"1\" ] && [ -n \"$swap_command\" ] && [ -x \"$swap_command\" ]; then\n  \"$swap_command\" --sync-session >/dev/null 2>&1 || true\nfi\nexit \"$status\"\n"
    )
}

fn move_or_copy_executable(src: &str, dst: &str) -> Result<()> {
    if let Some(parent) = Path::new(dst).parent().and_then(|p| p.to_str()) {
        if !parent.is_empty() {
            eko::file::create_dir_all(parent)?;
        }
    }
    if eko::file::rename(src, dst).is_ok() {
        if let Ok(f) = File::open(dst) {
            let _ = f.set_permissions_mode(0o755);
        }
        return Ok(());
    }
    let bytes = eko::file::read(src)?;
    atomic_write_mode(dst, &bytes, 0o755)?;
    eko::file::remove_file(src);
    Ok(())
}

fn lookup_saved_token(account: &Account, vault: &Vault) -> Option<String> {
    let primary = account.secret_key();
    if let Ok(Some(secret)) = vault.get(&primary) {
        if !secret.trim().is_empty() {
            return Some(secret);
        }
    }
    let fallback = format!("account:{}", account.email);
    if fallback != primary {
        if let Ok(Some(secret)) = vault.get(&fallback) {
            if !secret.trim().is_empty() {
                return Some(secret);
            }
        }
    }
    account
        .legacy_token_data
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn bundle_strictly_fresher(existing: &TokenBundle, candidate: &TokenBundle) -> bool {
    if sha256_hex(existing.raw_json.as_bytes()) == sha256_hex(candidate.raw_json.as_bytes()) {
        return false;
    }
    if candidate.access_token.trim().is_empty() {
        return false;
    }
    match (existing.expires_at_unix, candidate.expires_at_unix) {
        (Some(old_exp), Some(new_exp)) => new_exp > old_exp,
        (None, Some(_)) => true,
        _ => existing.access_token.trim().is_empty(),
    }
}

/// Manager for `~/.gemini` active OAuth session files, keyring sync, and `agy` wrapper guards.
#[derive(Debug, Clone)]
pub struct SessionManager {
    paths: Paths,
}

impl SessionManager {
    #[must_use]
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    fn oauth_surface_paths(&self) -> [String; 3] {
        [
            self.paths.agy_oauth_file.clone(),
            self.paths.ide_oauth_file(),
            self.paths.jetski_oauth_file(),
        ]
    }

    fn all_session_file_paths(&self) -> Vec<String> {
        vec![
            self.paths.agy_oauth_file.clone(),
            self.paths.ide_oauth_file(),
            self.paths.jetski_oauth_file(),
            self.paths.oauth_creds_file(),
            self.paths.google_accounts_file(),
        ]
    }

    fn ensure_keyring_bypass_markers(&self) {
        if use_keychain_session_store() {
            return;
        }
        let mut seen = Vec::new();
        for surface in self.oauth_surface_paths() {
            let Some(parent) = Path::new(&surface).parent().and_then(|p| p.to_str()) else {
                continue;
            };
            if parent.is_empty() {
                continue;
            }
            let marker = join_path(parent, "cache/antigravity-keyring-unavailable");
            if seen.iter().any(|m| m == &marker) {
                continue;
            }
            seen.push(marker.clone());
            let _ = crate::isolate::write_keyring_bypass_marker_2036(parent);
        }
    }

    fn stored_active_email(&self) -> Option<String> {
        let ga_path = self.paths.google_accounts_file();
        let raw = eko::file::read_to_string(&ga_path).ok()?;
        let parsed: Value = serde_json::from_str(&raw).ok()?;
        parsed
            .get("active")
            .and_then(Value::as_str)
            .and_then(normalize_email)
    }

    fn read_surface_bundle(&self) -> Option<TokenBundle> {
        let mut best: Option<TokenBundle> = None;
        let candidates = [
            self.paths.agy_oauth_file.clone(),
            self.paths.ide_oauth_file(),
            self.paths.jetski_oauth_file(),
            self.paths.oauth_creds_file(),
        ];
        for path in &candidates {
            let Ok(raw) = eko::file::read_to_string(path) else {
                continue;
            };
            let Ok(bundle) = TokenBundle::parse(&raw) else {
                continue;
            };
            match &best {
                None => best = Some(bundle),
                Some(cur) => {
                    if cur.refresh_token.is_some()
                        && cur.refresh_token == bundle.refresh_token
                        && bundle_strictly_fresher(cur, &bundle)
                    {
                        best = Some(bundle);
                    }
                }
            }
        }
        best
    }

    /// Read the active OAuth token JSON from `~/.gemini` surface files (or OS keyring when configured).
    #[must_use]
    pub fn current_token(&self) -> Option<String> {
        if let Some(bundle) = self.read_surface_bundle() {
            return Some(bundle.raw_json);
        }
        if use_keychain_session_store() {
            if let Ok(Some(raw)) = keychain_get(GEMINI_KEYRING_SERVICE, GEMINI_KEYRING_ACCOUNT) {
                if let Ok(bundle) = TokenBundle::parse(&raw) {
                    return Some(bundle.raw_json);
                }
            }
        }
        None
    }

    /// Read the currently active account email from `google_accounts.json` or active token claims.
    #[must_use]
    pub fn current_email(&self) -> Option<String> {
        if let Some(email) = self.stored_active_email() {
            return Some(email);
        }
        self.read_surface_bundle().and_then(|b| b.email_hint)
    }

    fn build_google_accounts_bytes(&self, email: &str) -> Result<Vec<u8>> {
        let ga_path = self.paths.google_accounts_file();
        let mut old_emails: Vec<Value> = Vec::new();
        if let Ok(raw) = eko::file::read_to_string(&ga_path) {
            if let Ok(Value::Object(existing)) = serde_json::from_str::<Value>(&raw) {
                if let Some(prev_active) = existing
                    .get("active")
                    .and_then(Value::as_str)
                    .and_then(normalize_email)
                {
                    if !prev_active.eq_ignore_ascii_case(email) {
                        old_emails.push(Value::String(prev_active));
                    }
                }
                if let Some(Value::Array(items)) = existing.get("old") {
                    for item in items {
                        if let Some(s) = item.as_str().and_then(normalize_email) {
                            if !s.eq_ignore_ascii_case(email)
                                && !old_emails
                                    .iter()
                                    .any(|e| e.as_str().is_some_and(|x| x.eq_ignore_ascii_case(&s)))
                            {
                                old_emails.push(Value::String(s));
                            }
                        }
                    }
                }
            }
        }
        let mut ga = Map::new();
        ga.insert("active".to_string(), Value::String(email.to_string()));
        ga.insert("old".to_string(), Value::Array(old_emails));
        let mut bytes = serde_json::to_vec_pretty(&Value::Object(ga))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn write_session_files_atomic(&self, email: &str, bundle: &TokenBundle) -> Result<()> {
        let targets = self.all_session_file_paths();
        let snapshot = snapshot_files(&targets)?;
        let envelope_val: Value = serde_json::from_str(&bundle.raw_json)?;
        let mut envelope_bytes = serde_json::to_vec_pretty(&envelope_val)?;
        envelope_bytes.push(b'\n');

        let mut flat_bytes = bundle.to_flat_credentials_json()?.into_bytes();
        if !flat_bytes.ends_with(b"\n") {
            flat_bytes.push(b'\n');
        }
        let ga_bytes = self.build_google_accounts_bytes(email)?;

        let write_res = (|| -> Result<()> {
            for surface_path in self.oauth_surface_paths() {
                atomic_write_private(&surface_path, &envelope_bytes)?;
            }
            atomic_write_private(&self.paths.oauth_creds_file(), &flat_bytes)?;
            atomic_write_private(&self.paths.google_accounts_file(), &ga_bytes)?;
            Ok(())
        })();

        if let Err(err) = write_res {
            restore_snapshot(&snapshot);
            return Err(err);
        }
        Ok(())
    }

    /// Touch `hub_reload_file` (`0600`) so `agy` hub wrapper processes reload credentials.
    pub fn touch_hub_reload(&self) -> Result<()> {
        if self.paths.hub_reload_file.trim().is_empty() {
            return Ok(());
        }
        let payload = format!("{}\n", wall_unix_ns());
        atomic_write_private(&self.paths.hub_reload_file, payload.as_bytes())
    }

    /// Atomically switch `~/.gemini` active OAuth session files to `(email, token)` with rollback on failure.
    pub fn switch_to(&self, email: &str, token: &str) -> Result<()> {
        let norm_email = normalize_email(email)
            .ok_or_else(|| Error::InvalidInput(format!("invalid account email {email:?}")))?;
        let bundle = TokenBundle::parse(token)?;
        if let Some(ref hint) = bundle.email_hint {
            if !hint.eq_ignore_ascii_case(&norm_email) {
                return Err(Error::Auth(format!(
                    "OAuth token identity {hint} does not match target email {norm_email}"
                )));
            }
        }
        ensure_private_dir(&self.paths.config_dir)?;
        let _guard = FileLock::acquire(&self.paths.session_lock_file())?;
        let prev_email = self.stored_active_email();
        let prev_refresh = self.read_surface_bundle().and_then(|b| b.refresh_token);

        self.write_session_files_atomic(&norm_email, &bundle)?;
        self.ensure_keyring_bypass_markers();

        let email_changed = prev_email
            .as_deref()
            .map(|p| !p.eq_ignore_ascii_case(&norm_email))
            .unwrap_or(true);
        if email_changed {
            sync_ide_onboarding_email(&self.paths.home, &norm_email);
        }

        let mirror_keyring = should_mirror_os_keyring(&self.paths) || use_keychain_session_store();
        if mirror_keyring {
            let keyring_val = bundle.to_keyring_string();
            let _ = keychain_set(
                GEMINI_KEYRING_SERVICE,
                GEMINI_KEYRING_ACCOUNT,
                &keyring_val,
                true,
            );
        }

        let refresh_changed = prev_refresh
            .as_deref()
            .is_some_and(|old_r| bundle.refresh_token.as_deref() != Some(old_r));
        if email_changed || refresh_changed {
            let _ = self.touch_hub_reload();
            if should_mirror_os_keyring(&self.paths) {
                let _ = Command::new("pkill")
                    .args(["-TERM", "-f", r"(\.agy\.real|libexec/agy).*--hub"])
                    .output();
            }
        }
        Ok(())
    }

    /// Clear `~/.gemini` active OAuth session files and mirrored OS keyring entry.
    pub fn logout(&self) -> Result<()> {
        let _guard = if eko::file::exists(&self.paths.config_dir) {
            Some(FileLock::acquire(&self.paths.session_lock_file())?)
        } else {
            None
        };
        if should_mirror_os_keyring(&self.paths) || use_keychain_session_store() {
            let _ = keychain_delete(GEMINI_KEYRING_SERVICE, GEMINI_KEYRING_ACCOUNT);
        }
        for path in self.all_session_file_paths() {
            eko::file::remove_file(&path);
            if eko::file::exists(&path) {
                return Err(Error::Io(eko::file::Error::other(format!(
                    "failed to remove session file {path}"
                ))));
            }
        }
        if eko::file::exists(&self.paths.gemini_dir) {
            self.ensure_keyring_bypass_markers();
            let _ = self.touch_hub_reload();
        }
        Ok(())
    }

    /// Synchronize `<agy_bin>.version.json` sidecar `size`, `mtimeMs`, and `ino` when present.
    pub fn sync_version_sidecar(&self, agy_bin: &str) -> Result<()> {
        let trimmed = agy_bin.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let sidecar_path = format!("{trimmed}.version.json");
        if !eko::file::exists(&sidecar_path) {
            return Ok(());
        }
        let raw = eko::file::read_to_string(&sidecar_path)?;
        let Ok(Value::Object(mut sidecar)) = serde_json::from_str::<Value>(&raw) else {
            return Ok(());
        };
        let c = Path::new(trimmed).as_c();
        let mut st: eko::libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { eko::libc::stat(c.as_ptr().cast(), &mut st) } != 0 {
            return Ok(());
        }
        if (st.st_mode & eko::libc::S_IFMT) == eko::libc::S_IFDIR {
            return Ok(());
        }
        let want_size = st.st_size;
        let want_mtime_ms = st.st_mtime * 1000 + (st.st_mtime_nsec as i64) / 1_000_000;
        let same = sidecar.get("size").and_then(Value::as_i64) == Some(want_size)
            && sidecar.get("mtimeMs").and_then(Value::as_i64) == Some(want_mtime_ms)
            && sidecar.get("ino").and_then(Value::as_i64) == Some(0);
        if same {
            return Ok(());
        }
        sidecar.insert("size".to_string(), Value::from(want_size));
        sidecar.insert("mtimeMs".to_string(), Value::from(want_mtime_ms));
        sidecar.insert("ino".to_string(), Value::from(0));
        let mut encoded = serde_json::to_vec_pretty(&Value::Object(sidecar))?;
        encoded.push(b'\n');
        atomic_write_private(&sidecar_path, &encoded)
    }

    /// Install or refresh the POSIX `agy` launcher wrapper (`--sync-session`) at `agy_bin`.
    pub fn install_agy_wrapper(&self, agy_bin: &str) -> Result<bool> {
        let trimmed = clean_path_str(agy_bin);
        if trimmed.is_empty() {
            return Ok(false);
        }
        let Ok(lmeta) = eko::file::symlink_metadata(&trimmed) else {
            return Ok(false);
        };
        if lmeta.is_dir() {
            return Ok(false);
        }
        let preferred_swap = current_swap_exe();
        let default_bin = join_path(&self.paths.home, ".local/bin/agy");
        let default_libexec = join_path(&self.paths.home, ".local/libexec/agy");

        let is_symlink =
            (lmeta.mode() as eko::libc::mode_t & eko::libc::S_IFMT) == eko::libc::S_IFLNK;
        if is_symlink {
            let Ok(resolved_pb) = eko::file::canonicalize(&trimmed) else {
                return Ok(false);
            };
            let Some(resolved) = resolved_pb.as_path().to_str().map(clean_path_str) else {
                return Ok(false);
            };
            if resolved.is_empty() || resolved == trimmed {
                return Ok(false);
            }
            let Some(header) = read_header_bytes(&resolved, 8192) else {
                return Ok(false);
            };
            if !is_native_executable(&header) {
                return Ok(false);
            }
            let script = build_agy_launcher_script(
                Some(&resolved),
                preferred_swap.as_deref(),
                &self.paths.hub_reload_file,
                false,
            );
            atomic_write_mode(&trimmed, script.as_bytes(), 0o755)?;
            let _ = self.sync_version_sidecar(&trimmed);
            return Ok(true);
        }

        let Some(header) = read_header_bytes(&trimmed, 8192) else {
            return Ok(false);
        };
        if header.is_empty() {
            return Ok(false);
        }
        let (backing_bin, explicit_real_ref) =
            if trimmed == default_bin && !default_libexec.is_empty() {
                (default_libexec, None)
            } else {
                let dir = Path::new(&trimmed)
                    .parent()
                    .and_then(|p| p.to_str())
                    .unwrap_or(".");
                let real_path = join_path(dir, ".agy.real");
                (real_path.clone(), Some(real_path))
            };

        if is_native_executable(&header) {
            move_or_copy_executable(&trimmed, &backing_bin)?;
            let script = build_agy_launcher_script(
                explicit_real_ref.as_deref(),
                preferred_swap.as_deref(),
                &self.paths.hub_reload_file,
                false,
            );
            atomic_write_mode(&trimmed, script.as_bytes(), 0o755)?;
            let _ = self.sync_version_sidecar(&trimmed);
            return Ok(true);
        }

        let text = String::from_utf8_lossy(&header);
        let managed = text.starts_with("#!")
            && (text.contains("Managed by agy-swap session guard")
                || text.contains(".local/libexec/agy"));
        if !managed {
            return Ok(false);
        }
        let up_to_date = text.contains("--sync-session")
            && text.contains("WSL_INTEROP")
            && text.contains("hub_pid")
            && text.contains("reload_marker=");
        if up_to_date {
            let _ = self.sync_version_sidecar(&trimmed);
            return Ok(false);
        }
        let real_ref = extract_wrapper_real_command(&text).or(explicit_real_ref);
        let skip_perms =
            text.contains("AGY_NORMAL_MODE") || text.contains("--dangerously-skip-permissions");
        let script = build_agy_launcher_script(
            real_ref.as_deref(),
            preferred_swap.as_deref(),
            &self.paths.hub_reload_file,
            skip_perms,
        );
        atomic_write_mode(&trimmed, script.as_bytes(), 0o755)?;
        let _ = self.sync_version_sidecar(&trimmed);
        Ok(true)
    }

    /// Ensure launcher guards on `~/.local/bin/agy`, `~/.gemini/bin/agy`, and `AGY_SWAP_AGY_BIN`.
    pub fn ensure_agy_wrappers(&self) -> usize {
        if self.paths.home.trim().is_empty() {
            return 0;
        }
        let mut candidates = vec![
            join_path(&self.paths.home, ".local/bin/agy"),
            join_path(&self.paths.home, ".gemini/bin/agy"),
        ];
        if let Some(env_bin) = eko::env::var("AGY_SWAP_AGY_BIN") {
            let clean = clean_path_str(&env_bin);
            if !clean.is_empty() && !candidates.iter().any(|c| c == &clean) {
                candidates.push(clean);
            }
        }
        let mut updated = 0usize;
        for cand in candidates {
            if self.install_agy_wrapper(&cand).unwrap_or(false) {
                updated += 1;
            }
        }
        updated
    }

    fn match_account_for_bundle(
        &self,
        accounts: &Accounts,
        vault: &Vault,
        bundle: &TokenBundle,
    ) -> Option<String> {
        if let Some(ref hint) = bundle.email_hint {
            if let Some(resolved) = accounts.resolve(hint) {
                return Some(resolved.to_string());
            }
        }
        let cand_hash = sha256_hex(bundle.raw_json.as_bytes());
        for email in &accounts.order {
            let Some(acc) = accounts.get(email) else {
                continue;
            };
            let Some(saved_raw) = lookup_saved_token(acc, vault) else {
                continue;
            };
            if let Ok(saved_bundle) = TokenBundle::parse(&saved_raw) {
                if sha256_hex(saved_bundle.raw_json.as_bytes()) == cand_hash {
                    return Some(acc.email.clone());
                }
            }
        }
        let cand_refresh = bundle.refresh_token.as_deref().filter(|r| !r.is_empty())?;
        let mut matched: Option<String> = None;
        for email in &accounts.order {
            let Some(acc) = accounts.get(email) else {
                continue;
            };
            let Some(saved_raw) = lookup_saved_token(acc, vault) else {
                continue;
            };
            if let Ok(saved_bundle) = TokenBundle::parse(&saved_raw) {
                if saved_bundle.refresh_token.as_deref() == Some(cand_refresh) {
                    if matched
                        .as_deref()
                        .is_some_and(|m| !m.eq_ignore_ascii_case(&acc.email))
                    {
                        return None;
                    }
                    matched = Some(acc.email.clone());
                }
            }
        }
        matched
    }

    /// Read `~/.gemini` surface tokens and harvest any strictly fresher token into `vault` without mutating `~/.gemini`.
    pub fn reconcile_active_session(&self, store: &Store, vault: &Vault) -> Result<Option<String>> {
        let accounts = store.load()?;
        if accounts.is_empty() {
            return Ok(self.current_email());
        }
        ensure_private_dir(&self.paths.config_dir)?;
        let _guard = FileLock::acquire(&self.paths.session_lock_file())?;

        let mut matched_active: Option<String> = None;
        for surface_path in self.oauth_surface_paths() {
            let Ok(raw) = eko::file::read_to_string(&surface_path) else {
                continue;
            };
            let Ok(surface_bundle) = TokenBundle::parse(&raw) else {
                continue;
            };
            let Some(owner_email) =
                self.match_account_for_bundle(&accounts, vault, &surface_bundle)
            else {
                continue;
            };
            if matched_active.is_none() {
                matched_active = Some(owner_email.clone());
            }
            if let Some(acc) = accounts.get(&owner_email) {
                let should_harvest = match lookup_saved_token(acc, vault)
                    .and_then(|s| TokenBundle::parse(&s).ok())
                {
                    None => !surface_bundle.access_token.trim().is_empty(),
                    Some(existing) => bundle_strictly_fresher(&existing, &surface_bundle),
                };
                if should_harvest {
                    let _ = vault.set(&acc.secret_key(), &surface_bundle.raw_json);
                }
            }
        }

        let intended_email = self
            .stored_active_email()
            .and_then(|e| accounts.resolve(&e).map(ToString::to_string))
            .or(matched_active);
        Ok(intended_email.or_else(|| self.current_email()))
    }
}
