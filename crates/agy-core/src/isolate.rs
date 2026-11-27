//! Per-account isolated HOME overlays, interactive TTY child execution, and token refresh harvesting.

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

use eko::file::File;
use eko::path::Path;
use serde_json::{Map, Value};

use crate::model::{normalize_email, Account};
use crate::oauth::{resolve_agy_executable, TokenBundle};
use crate::paths::{clean_path_str, join_path, sha256_hex, Paths};
use crate::policy::lookup_account_secret;
use crate::store::{atomic_write_private, ensure_private_dir, stat_mtime_ns, FileLock, Store};
use crate::vault::Vault;
use crate::{Error, Result};

/// Far-future Unix timestamp (`2036-01-01T00:00:00Z`) for `antigravity-keyring-unavailable`.
pub const KEYRING_BYPASS_2036_UNIX: i64 = 2_082_758_400;

const ENOEXEC_ERRNO: i32 = 8;

unsafe extern "C" {
    fn futimens(fd: eko::libc::c_int, times: *const eko::libc::timespec) -> eko::libc::c_int;
    fn symlink(
        target: *const eko::libc::c_char,
        linkpath: *const eko::libc::c_char,
    ) -> eko::libc::c_int;
}

/// Compute a deterministic filesystem-safe directory slug for `email`.
#[must_use]
pub fn account_overlay_slug(email: &str) -> String {
    let norm = normalize_email(email).unwrap_or_else(|| email.trim().to_ascii_lowercase());
    let mut slug = String::with_capacity(norm.len() + 12);
    for ch in norm.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            slug.push(ch);
        } else if ch == '@' {
            slug.push_str("-at-");
        } else {
            slug.push('-');
        }
    }
    while slug.starts_with('.') || slug.starts_with('-') {
        slug.remove(0);
    }
    if slug.is_empty() {
        slug.push_str("account");
    }
    if slug.len() > 64 {
        slug.truncate(64);
    }
    let digest = sha256_hex(norm.as_bytes());
    format!("{slug}-{}", &digest[..8])
}

/// Return `<config_dir>/homes/<slug>` for `email`.
pub fn overlay_home_dir(paths: &Paths, email: &str) -> Result<String> {
    let norm = normalize_email(email)
        .ok_or_else(|| Error::InvalidInput(format!("invalid account email {email:?}")))?;
    let slug = account_overlay_slug(&norm);
    Ok(join_path(&paths.config_dir, &format!("homes/{slug}")))
}

fn is_executable_regular(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }
    match eko::file::metadata(trimmed) {
        Ok(meta) => !meta.is_dir() && (meta.mode() & 0o111) != 0,
        Err(_) => false,
    }
}

fn resolve_program_in_env(program: &str, env_overrides: &[(&str, &str)]) -> Result<String> {
    let trimmed = program.trim();
    if trimmed.is_empty() || trimmed.as_bytes().contains(&0) {
        return Err(Error::InvalidInput(
            "executable name must not be empty".to_string(),
        ));
    }
    if trimmed.contains('/') {
        if is_executable_regular(trimmed) {
            return Ok(trimmed.to_string());
        }
        return Err(Error::NotFound(format!("executable {trimmed:?} not found")));
    }
    let override_path = env_overrides
        .iter()
        .rev()
        .find(|(k, _)| *k == "PATH")
        .map(|(_, v)| (*v).to_string())
        .or_else(|| eko::env::var("PATH"));
    if let Some(path_val) = override_path {
        for dir in path_val.split(':') {
            let d = dir.trim();
            if d.is_empty() {
                continue;
            }
            let cand = join_path(d, trimmed);
            if is_executable_regular(&cand) {
                return Ok(cand);
            }
        }
    }
    Err(Error::NotFound(format!(
        "executable {trimmed:?} not found in PATH"
    )))
}

fn to_c_vec(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.contains(&0) {
        return Err(Error::InvalidInput(
            "NUL byte in process argument or env".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.extend_from_slice(bytes);
    out.push(0);
    Ok(out)
}

fn build_merged_env(env_overrides: &[(&str, &str)]) -> Result<Vec<Vec<u8>>> {
    let mut env_entries: Vec<Vec<u8>> = eko::env::environ();
    for &(key, val) in env_overrides {
        if key.is_empty()
            || key.as_bytes().contains(&b'=')
            || key.as_bytes().contains(&0)
            || val.as_bytes().contains(&0)
        {
            return Err(Error::InvalidInput(
                "invalid environment variable override".to_string(),
            ));
        }
        let mut kv = Vec::with_capacity(key.len() + 1 + val.len());
        kv.extend_from_slice(key.as_bytes());
        kv.push(b'=');
        let prefix_len = kv.len();
        kv.extend_from_slice(val.as_bytes());
        if let Some(slot) = env_entries.iter_mut().find(|existing| {
            existing.len() >= prefix_len && existing[..prefix_len] == kv[..prefix_len]
        }) {
            *slot = kv;
        } else {
            env_entries.push(kv);
        }
    }
    for entry in &mut env_entries {
        if entry.last() != Some(&0) {
            entry.push(0);
        }
    }
    Ok(env_entries)
}

/// Spawn an interactive child process inheriting real TTY descriptors `0, 1, 2`.
pub fn spawn_interactive_tty(
    program: &str,
    args: &[String],
    env_overrides: &[(&str, &str)],
    cwd: Option<&str>,
) -> Result<i32> {
    let resolved = resolve_program_in_env(program, env_overrides)?;
    let prog_c = to_c_vec(&resolved)?;
    let sh_c = b"/bin/sh\0".to_vec();
    let cwd_c = match cwd.map(str::trim).filter(|d| !d.is_empty()) {
        Some(dir) => Some(to_c_vec(dir)?),
        None => None,
    };

    let mut argv_c: Vec<Vec<u8>> = Vec::with_capacity(args.len() + 1);
    argv_c.push(prog_c.clone());
    for arg in args {
        argv_c.push(to_c_vec(arg)?);
    }
    let mut argv_ptrs: Vec<*const eko::libc::c_char> = Vec::with_capacity(argv_c.len() + 1);
    for entry in &argv_c {
        argv_ptrs.push(entry.as_ptr().cast());
    }
    argv_ptrs.push(core::ptr::null());

    let mut sh_argv_ptrs: Vec<*const eko::libc::c_char> = Vec::with_capacity(argv_c.len() + 2);
    sh_argv_ptrs.push(sh_c.as_ptr().cast());
    for entry in &argv_c {
        sh_argv_ptrs.push(entry.as_ptr().cast());
    }
    sh_argv_ptrs.push(core::ptr::null());

    let env_entries = build_merged_env(env_overrides)?;
    let mut env_ptrs: Vec<*const eko::libc::c_char> = Vec::with_capacity(env_entries.len() + 1);
    for entry in &env_entries {
        env_ptrs.push(entry.as_ptr().cast());
    }
    env_ptrs.push(core::ptr::null());

    let pid = unsafe { eko::libc::fork() };
    if pid < 0 {
        return Err(Error::Sys(eko::Errno::current()));
    }
    if pid == 0 {
        unsafe {
            if let Some(ref dir_c) = cwd_c {
                if eko::libc::chdir(dir_c.as_ptr().cast()) != 0 {
                    eko::libc::_exit(127);
                }
            }
            eko::libc::execve(
                prog_c.as_ptr().cast(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            );
            if eko::Errno::current().0 == ENOEXEC_ERRNO {
                eko::libc::execve(
                    sh_c.as_ptr().cast(),
                    sh_argv_ptrs.as_ptr(),
                    env_ptrs.as_ptr(),
                );
            }
            eko::libc::_exit(127);
        }
    }

    let mut status: eko::libc::c_int = 0;
    loop {
        let rc = unsafe { eko::libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = eko::Errno::current();
            if err.interrupted() {
                continue;
            }
            return Err(Error::Sys(err));
        }
        if rc == pid {
            break;
        }
    }
    if eko::libc::WIFEXITED(status) {
        Ok(eko::libc::WEXITSTATUS(status))
    } else {
        Ok(128 + eko::libc::WTERMSIG(status))
    }
}

fn spawn_captured(
    program: &str,
    args: &[String],
    env_overrides: &[(&str, &str)],
    cwd: &str,
    stdout_path: &str,
    stderr_path: &str,
) -> Result<i32> {
    let resolved = resolve_program_in_env(program, env_overrides)?;
    let prog_c = to_c_vec(&resolved)?;
    let sh_c = b"/bin/sh\0".to_vec();
    let cwd_c = match Some(cwd.trim()).filter(|d| !d.is_empty()) {
        Some(dir) => Some(to_c_vec(dir)?),
        None => None,
    };
    let out_trimmed = stdout_path.trim();
    let err_trimmed = stderr_path.trim();
    if out_trimmed.is_empty() || err_trimmed.is_empty() {
        return Err(Error::InvalidInput(
            "stdout and stderr capture paths must not be empty".to_string(),
        ));
    }
    let stdout_c = to_c_vec(out_trimmed)?;
    let stderr_c = to_c_vec(err_trimmed)?;
    let devnull_c = b"/dev/null\0";

    let mut argv_c: Vec<Vec<u8>> = Vec::with_capacity(args.len() + 1);
    argv_c.push(prog_c.clone());
    for arg in args {
        argv_c.push(to_c_vec(arg)?);
    }
    let mut argv_ptrs: Vec<*const eko::libc::c_char> = Vec::with_capacity(argv_c.len() + 1);
    for entry in &argv_c {
        argv_ptrs.push(entry.as_ptr().cast());
    }
    argv_ptrs.push(core::ptr::null());

    let mut sh_argv_ptrs: Vec<*const eko::libc::c_char> = Vec::with_capacity(argv_c.len() + 2);
    sh_argv_ptrs.push(sh_c.as_ptr().cast());
    for entry in &argv_c {
        sh_argv_ptrs.push(entry.as_ptr().cast());
    }
    sh_argv_ptrs.push(core::ptr::null());

    let env_entries = build_merged_env(env_overrides)?;
    let mut env_ptrs: Vec<*const eko::libc::c_char> = Vec::with_capacity(env_entries.len() + 1);
    for entry in &env_entries {
        env_ptrs.push(entry.as_ptr().cast());
    }
    env_ptrs.push(core::ptr::null());

    let pid = unsafe { eko::libc::fork() };
    if pid < 0 {
        return Err(Error::Sys(eko::Errno::current()));
    }
    if pid == 0 {
        unsafe {
            if let Some(ref dir_c) = cwd_c {
                if eko::libc::chdir(dir_c.as_ptr().cast()) != 0 {
                    eko::libc::_exit(127);
                }
            }
            let fd_in = eko::libc::open2(devnull_c.as_ptr().cast(), eko::libc::O_RDONLY);
            if fd_in < 0 {
                eko::libc::_exit(127);
            }
            if fd_in != 0 {
                if eko::libc::dup2(fd_in, 0) < 0 {
                    eko::libc::_exit(127);
                }
                let _ = eko::libc::close(fd_in);
            }

            let out_flags = eko::libc::O_WRONLY | eko::libc::O_CREAT | eko::libc::O_TRUNC;
            let fd_out = eko::libc::open3(
                stdout_c.as_ptr().cast(),
                out_flags,
                0o600 as eko::libc::mode_t,
            );
            if fd_out < 0 {
                eko::libc::_exit(127);
            }
            if fd_out != 1 {
                if eko::libc::dup2(fd_out, 1) < 0 {
                    eko::libc::_exit(127);
                }
                let _ = eko::libc::close(fd_out);
            }

            let fd_err = eko::libc::open3(
                stderr_c.as_ptr().cast(),
                out_flags,
                0o600 as eko::libc::mode_t,
            );
            if fd_err < 0 {
                eko::libc::_exit(127);
            }
            if fd_err != 2 {
                if eko::libc::dup2(fd_err, 2) < 0 {
                    eko::libc::_exit(127);
                }
                let _ = eko::libc::close(fd_err);
            }

            eko::libc::execve(
                prog_c.as_ptr().cast(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            );
            if eko::Errno::current().0 == ENOEXEC_ERRNO {
                eko::libc::execve(
                    sh_c.as_ptr().cast(),
                    sh_argv_ptrs.as_ptr(),
                    env_ptrs.as_ptr(),
                );
            }
            eko::libc::_exit(127);
        }
    }

    let mut status: eko::libc::c_int = 0;
    loop {
        let rc = unsafe { eko::libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = eko::Errno::current();
            if err.interrupted() {
                continue;
            }
            return Err(Error::Sys(err));
        }
        if rc == pid {
            break;
        }
    }
    if eko::libc::WIFEXITED(status) {
        Ok(eko::libc::WEXITSTATUS(status))
    } else {
        Ok(128 + eko::libc::WTERMSIG(status))
    }
}

fn write_single_bypass_marker_2036(base_dir: &str) -> Result<()> {
    let cache_dir = join_path(base_dir, "cache");
    ensure_private_dir(&cache_dir)?;
    let marker_path = join_path(&cache_dir, "antigravity-keyring-unavailable");
    atomic_write_private(&marker_path, b"file-session\n")?;
    let file = File::open_rw(&marker_path)?;
    let future_ts = [
        eko::libc::timespec {
            tv_sec: KEYRING_BYPASS_2036_UNIX as _,
            tv_nsec: 0,
        },
        eko::libc::timespec {
            tv_sec: KEYRING_BYPASS_2036_UNIX as _,
            tv_nsec: 0,
        },
    ];
    if unsafe { futimens(file.as_raw_fd(), future_ts.as_ptr()) } != 0 {
        return Err(Error::Sys(eko::Errno::current()));
    }
    Ok(())
}

/// Write `cache/antigravity-keyring-unavailable` with `atime`/`mtime` set to `2036-01-01`.
pub fn write_keyring_bypass_marker_2036(gemini_or_cli_dir: &str) -> Result<()> {
    let clean = clean_path_str(gemini_or_cli_dir);
    if clean.is_empty() {
        return Err(Error::InvalidInput(
            "marker base directory is empty".to_string(),
        ));
    }
    write_single_bypass_marker_2036(&clean)?;
    if clean == ".gemini" || clean.ends_with("/.gemini") {
        write_single_bypass_marker_2036(&join_path(&clean, "antigravity-cli"))?;
    }
    Ok(())
}

fn ensure_symlink_best_effort(target: &str, link_path: &str) {
    if target.is_empty() || link_path.is_empty() || target == link_path {
        return;
    }
    if eko::file::symlink_metadata(target).is_err() {
        return;
    }
    if let Ok(existing) = eko::file::symlink_metadata(link_path) {
        let is_link =
            (existing.mode() as eko::libc::mode_t & eko::libc::S_IFMT) == eko::libc::S_IFLNK;
        if !is_link {
            return;
        }
        if let Ok(cur_target) = eko::file::read_link(link_path) {
            if cur_target.as_path().to_str() == Some(target) {
                return;
            }
        }
        eko::file::remove_file(link_path);
    }
    let target_c = Path::new(target).as_c();
    let link_c = Path::new(link_path).as_c();
    unsafe {
        let _ = symlink(target_c.as_ptr().cast(), link_c.as_ptr().cast());
    }
}

fn copy_private_file_if_present(src: &str, dst: &str) {
    if src.is_empty() || dst.is_empty() || src == dst {
        return;
    }
    if let Ok(existing) = eko::file::symlink_metadata(dst) {
        let is_link =
            (existing.mode() as eko::libc::mode_t & eko::libc::S_IFMT) == eko::libc::S_IFLNK;
        if is_link {
            eko::file::remove_file(dst);
        }
    }
    if let Ok(meta) = eko::file::metadata(src) {
        if meta.is_dir() || meta.len() > 4 * 1024 * 1024 {
            return;
        }
        if let Ok(bytes) = eko::file::read(src) {
            let _ = atomic_write_private(dst, &bytes);
        }
    }
}

fn seed_isolated_gemini_config(real_gemini_dir: &str, overlay_gemini_dir: &str) -> Result<()> {
    if let Ok(existing_cfg) = eko::file::symlink_metadata(join_path(overlay_gemini_dir, "config")) {
        let is_link =
            (existing_cfg.mode() as eko::libc::mode_t & eko::libc::S_IFMT) == eko::libc::S_IFLNK;
        if is_link {
            eko::file::remove_file(join_path(overlay_gemini_dir, "config"));
        }
    }
    for legacy_link in ["skills", "plugins", "mcp_config.json", "GEMINI.md"] {
        let p = join_path(overlay_gemini_dir, legacy_link);
        if let Ok(meta) = eko::file::symlink_metadata(&p) {
            if (meta.mode() as eko::libc::mode_t & eko::libc::S_IFMT) == eko::libc::S_IFLNK {
                eko::file::remove_file(&p);
            }
        }
    }

    let overlay_cfg = join_path(overlay_gemini_dir, "config");
    ensure_private_dir(&overlay_cfg)?;

    if real_gemini_dir.trim().is_empty() {
        return Ok(());
    }
    for top_file in ["GEMINI.md", "mcp_config.json", "settings.json"] {
        copy_private_file_if_present(
            &join_path(real_gemini_dir, top_file),
            &join_path(overlay_gemini_dir, top_file),
        );
    }
    let real_cfg = join_path(real_gemini_dir, "config");
    for cfg_file in [
        ".migrated",
        "GEMINI.md",
        "hooks.json",
        "ban-python-hook.ts",
        "mcp_config.json",
    ] {
        copy_private_file_if_present(
            &join_path(&real_cfg, cfg_file),
            &join_path(&overlay_cfg, cfg_file),
        );
    }
    Ok(())
}

/// Prepare `<config_dir>/homes/<slug>/` (`0700`) with isolated `.gemini` OAuth files and host symlinks.
pub fn prepare_account_overlay_home(paths: &Paths, email: &str, token_raw: &str) -> Result<String> {
    let norm_email = normalize_email(email)
        .ok_or_else(|| Error::InvalidInput(format!("invalid account email {email:?}")))?;
    let bundle = TokenBundle::parse(token_raw)?;
    if let Some(ref hint) = bundle.email_hint {
        if !hint.eq_ignore_ascii_case(&norm_email) {
            return Err(Error::Auth(format!(
                "OAuth token identity {hint} does not match {norm_email}"
            )));
        }
    }

    ensure_private_dir(&paths.config_dir)?;
    ensure_private_dir(&join_path(&paths.config_dir, "homes"))?;
    let overlay = overlay_home_dir(paths, &norm_email)?;
    ensure_private_dir(&overlay)?;

    if !paths.home.trim().is_empty() {
        for dot_entry in [
            ".cargo",
            ".rustup",
            ".gitconfig",
            ".ssh",
            ".config",
            ".local",
            ".claude",
            ".bun",
            "Library",
        ] {
            let src = join_path(&paths.home, dot_entry);
            let dst = join_path(&overlay, dot_entry);
            ensure_symlink_best_effort(&src, &dst);
        }
    }

    let overlay_gemini = join_path(&overlay, ".gemini");
    let overlay_cli_dir = join_path(&overlay_gemini, "antigravity-cli");
    let overlay_ide_dir = join_path(&overlay_gemini, "antigravity");
    ensure_private_dir(&overlay_gemini)?;
    ensure_private_dir(&overlay_cli_dir)?;
    ensure_private_dir(&join_path(&overlay_cli_dir, "log"))?;
    ensure_private_dir(&overlay_ide_dir)?;

    seed_isolated_gemini_config(&paths.gemini_dir, &overlay_gemini)?;

    let envelope_val: Value = serde_json::from_str(&bundle.raw_json)?;
    let mut envelope_bytes = serde_json::to_vec_pretty(&envelope_val)?;
    envelope_bytes.push(b'\n');

    let mut flat_bytes = bundle.to_flat_credentials_json()?.into_bytes();
    if !flat_bytes.ends_with(b"\n") {
        flat_bytes.push(b'\n');
    }

    let mut ga = Map::new();
    ga.insert("active".to_string(), Value::String(norm_email));
    ga.insert("old".to_string(), Value::Array(Vec::new()));
    let mut ga_bytes = serde_json::to_vec_pretty(&Value::Object(ga))?;
    ga_bytes.push(b'\n');

    atomic_write_private(
        &join_path(&overlay_cli_dir, "antigravity-oauth-token"),
        &envelope_bytes,
    )?;
    atomic_write_private(
        &join_path(&overlay_ide_dir, "antigravity-oauth-token"),
        &envelope_bytes,
    )?;
    atomic_write_private(
        &join_path(&overlay_gemini, "jetski-standalone-oauth-token"),
        &envelope_bytes,
    )?;
    atomic_write_private(&join_path(&overlay_gemini, "oauth_creds.json"), &flat_bytes)?;
    atomic_write_private(
        &join_path(&overlay_gemini, "google_accounts.json"),
        &ga_bytes,
    )?;

    write_keyring_bypass_marker_2036(&overlay_gemini)?;
    write_keyring_bypass_marker_2036(&overlay_ide_dir)?;

    let cli_cache_dir = join_path(&overlay_cli_dir, "cache");
    ensure_private_dir(&cli_cache_dir)?;
    let onboarding_path = join_path(&cli_cache_dir, "onboarding.json");
    if !eko::file::exists(&onboarding_path) {
        let _ = atomic_write_private(
            &onboarding_path,
            b"{\n  \"consumerOnboardingComplete\": true,\n  \"enterpriseOnboardingComplete\": false,\n  \"onboardingComplete\": true\n}\n",
        );
    }
    let nux_path = join_path(&cli_cache_dir, "nux_state.json");
    if !eko::file::exists(&nux_path) {
        let _ = atomic_write_private(&nux_path, b"{\"dismissed\":[56,73]}\n");
    }
    if !paths.gemini_dir.trim().is_empty() {
        let real_cli_settings = join_path(&paths.gemini_dir, "antigravity-cli/settings.json");
        let overlay_cli_settings = join_path(&overlay_cli_dir, "settings.json");
        if !eko::file::exists(&overlay_cli_settings) && eko::file::exists(&real_cli_settings) {
            if let Ok(settings_bytes) = eko::file::read(&real_cli_settings) {
                let _ = atomic_write_private(&overlay_cli_settings, &settings_bytes);
            }
        }
    }
    Ok(overlay)
}

fn is_overlay_bundle_fresher(
    vault_bundle: &TokenBundle,
    cand_bundle: &TokenBundle,
    cand_path: &str,
    vault_file_path: &str,
) -> bool {
    if cand_bundle.access_token.trim().is_empty() {
        return false;
    }
    if sha256_hex(vault_bundle.raw_json.as_bytes()) == sha256_hex(cand_bundle.raw_json.as_bytes()) {
        return false;
    }
    match (vault_bundle.expires_at_unix, cand_bundle.expires_at_unix) {
        (Some(old_exp), Some(new_exp)) if new_exp > old_exp => return true,
        (Some(old_exp), Some(new_exp)) if new_exp < old_exp => return false,
        (None, Some(_)) => return true,
        _ => {}
    }
    if cand_bundle.access_token != vault_bundle.access_token {
        let cand_ns = stat_mtime_ns(cand_path).unwrap_or(0);
        let vault_ns = stat_mtime_ns(vault_file_path).unwrap_or(0);
        return cand_ns >= vault_ns;
    }
    false
}

/// Harvest any strictly fresher OAuth token from `<config_dir>/homes/<slug>/.gemini/` back into `vault`.
pub fn harvest_overlay_home(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    email: &str,
) -> Result<bool> {
    let accounts = store.load().unwrap_or_default();
    let norm_email = accounts
        .resolve(email)
        .map(ToString::to_string)
        .or_else(|| normalize_email(email))
        .ok_or_else(|| Error::InvalidInput(format!("invalid account email {email:?}")))?;
    let overlay = overlay_home_dir(paths, &norm_email)?;
    let overlay_gemini = join_path(&overlay, ".gemini");
    if !eko::file::exists(&overlay_gemini) {
        return Ok(false);
    }

    let vault_key = accounts
        .get(&norm_email)
        .map(Account::secret_key)
        .unwrap_or_else(|| format!("account:{norm_email}"));
    let existing_bundle = accounts
        .get(&norm_email)
        .and_then(|acc| lookup_account_secret(vault, acc).ok().flatten())
        .map(|(_, secret)| secret)
        .or_else(|| vault.get(&vault_key).ok().flatten())
        .and_then(|raw| TokenBundle::parse(&raw).ok());

    let surface_candidates = [
        join_path(&overlay_gemini, "antigravity-cli/antigravity-oauth-token"),
        join_path(&overlay_gemini, "antigravity/antigravity-oauth-token"),
        join_path(&overlay_gemini, "jetski-standalone-oauth-token"),
        join_path(&overlay_gemini, "oauth_creds.json"),
    ];

    let mut best: Option<(String, TokenBundle)> = None;
    for cand_path in &surface_candidates {
        let Ok(raw) = eko::file::read_to_string(cand_path) else {
            continue;
        };
        let Ok(cand) = TokenBundle::parse(&raw) else {
            continue;
        };
        if let Some(ref hint) = cand.email_hint {
            if !hint.eq_ignore_ascii_case(&norm_email) {
                continue;
            }
        }
        let fresher_than_current = match &best {
            None => match &existing_bundle {
                None => !cand.access_token.trim().is_empty(),
                Some(cur) => is_overlay_bundle_fresher(cur, &cand, cand_path, &paths.vault_file),
            },
            Some((prev_path, prev_b)) => {
                is_overlay_bundle_fresher(prev_b, &cand, cand_path, prev_path)
            }
        };
        if fresher_than_current {
            best = Some((cand_path.clone(), cand));
        }
    }

    let Some((_, harvested)) = best else {
        return Ok(false);
    };
    vault.set(&vault_key, &harvested.raw_json)?;
    let canonical_key = format!("account:{norm_email}");
    if canonical_key != vault_key {
        let _ = vault.set(&canonical_key, &harvested.raw_json);
    }
    Ok(true)
}

/// Count live isolated `--use-account` sessions holding `.active-<pid>.lock` in `<overlay>`.
#[must_use]
pub fn active_isolated_sessions(paths: &Paths, email: &str) -> usize {
    let Ok(overlay) = overlay_home_dir(paths, email) else {
        return 0;
    };
    if !eko::file::exists(&overlay) {
        return 0;
    }
    let Ok(entries) = eko::fs::read_dir(&overlay) else {
        return 0;
    };
    let mut count = 0usize;
    for entry in entries {
        let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with(".active-") || !name.ends_with(".lock") {
            continue;
        }
        let Some(lock_path) = entry.as_path().to_str() else {
            continue;
        };
        let c = Path::new(lock_path).as_c();
        let mut fd = unsafe { eko::libc::open2(c.as_ptr().cast(), eko::libc::O_RDWR) };
        if fd < 0 {
            fd = unsafe { eko::libc::open2(c.as_ptr().cast(), eko::libc::O_RDONLY) };
        }
        if fd < 0 {
            continue;
        }
        match eko::file::flock_exclusive(fd, true) {
            Ok(()) => {
                eko::file::remove_file(lock_path);
                let _ = eko::file::flock_unlock(fd);
            }
            Err(err) if err.0 == eko::libc::EAGAIN || err.0 == eko::libc::EWOULDBLOCK => {
                count += 1;
            }
            Err(_) => {}
        }
        unsafe {
            let _ = eko::libc::close(fd);
        }
    }
    count
}

fn unwrap_session_guard_target(paths: &Paths, candidate: &str) -> String {
    let clean = clean_path_str(candidate);
    if let Some(parent) = Path::new(&clean).parent().and_then(|p| p.to_str()) {
        let sibling_real = join_path(parent, ".agy.real");
        if is_executable_regular(&sibling_real) {
            return sibling_real;
        }
    }
    if !paths.home.trim().is_empty() && clean == join_path(&paths.home, ".local/bin/agy") {
        let libexec = join_path(&paths.home, ".local/libexec/agy");
        if is_executable_regular(&libexec) {
            return libexec;
        }
    }
    if let Ok(mut f) = File::open(&clean) {
        let mut hdr = [0u8; 4096];
        if let Ok(n) = f.read(&mut hdr) {
            let text = String::from_utf8_lossy(&hdr[..n]);
            if text.contains("Managed by agy-swap session guard") {
                for line in text.lines() {
                    if let Some(rest) = line.trim().strip_prefix("real_command=") {
                        let raw = rest.trim().trim_matches('"');
                        let expanded = if raw.starts_with("$HOME/") && !paths.home.is_empty() {
                            join_path(&paths.home, &raw["$HOME/".len()..])
                        } else {
                            raw.to_string()
                        };
                        if is_executable_regular(&expanded) {
                            return expanded;
                        }
                    }
                }
            }
        }
    }
    clean
}

fn resolve_real_agy_binary(paths: &Paths) -> Result<String> {
    if let Some(found) = resolve_agy_executable(paths) {
        return Ok(unwrap_session_guard_target(paths, &found));
    }
    if !paths.home.trim().is_empty() {
        for fallback in [
            join_path(&paths.home, ".local/libexec/agy"),
            join_path(&paths.home, ".gemini/bin/.agy.real"),
            join_path(&paths.home, ".local/bin/.agy.real"),
        ] {
            if is_executable_regular(&fallback) {
                return Ok(fallback);
            }
        }
    }
    Err(Error::NotFound(
        "Antigravity CLI ('agy') was not found; run 'agy-swap-rs install-agy'".to_string(),
    ))
}

fn run_isolated_agy_with<F>(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    email: &str,
    spawn: F,
) -> Result<(i32, String)>
where
    F: FnOnce(&str, &[(&str, &str)]) -> Result<i32>,
{
    let accounts = store.load()?;
    let norm_email = accounts
        .resolve(email)
        .map(ToString::to_string)
        .or_else(|| normalize_email(email))
        .ok_or_else(|| Error::NotFound(format!("account {email:?} not found")))?;

    let _ = harvest_overlay_home(paths, store, vault, &norm_email);

    let token_raw = accounts
        .get(&norm_email)
        .and_then(|acc| lookup_account_secret(vault, acc).ok().flatten())
        .map(|(_, secret)| secret)
        .or_else(|| vault.get(&format!("account:{norm_email}")).ok().flatten())
        .ok_or_else(|| Error::Auth(format!("no saved OAuth token for {norm_email}")))?;

    let overlay_home = prepare_account_overlay_home(paths, &norm_email, &token_raw)?;
    let pid = unsafe { eko::libc::getpid() };
    let active_lock_path = join_path(&overlay_home, &format!(".active-{pid}.lock"));
    let active_guard = FileLock::acquire(&active_lock_path)?;

    let agy_bin = resolve_real_agy_binary(paths)?;
    let cargo_home = join_path(&paths.home, ".cargo");
    let rustup_home = join_path(&paths.home, ".rustup");
    let git_config_global = join_path(&paths.home, ".gitconfig");

    #[allow(unused_mut)]
    let mut env_overrides: Vec<(&str, &str)> = vec![
        ("HOME", overlay_home.as_str()),
        ("WSL_INTEROP", "1"),
        ("AGY_SWAP_SKIP_SYNC", "1"),
        ("CARGO_HOME", cargo_home.as_str()),
        ("RUSTUP_HOME", rustup_home.as_str()),
        ("GIT_CONFIG_GLOBAL", git_config_global.as_str()),
    ];
    #[cfg(target_os = "linux")]
    {
        env_overrides.push(("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null"));
    }

    let spawn_res = spawn(&agy_bin, &env_overrides);
    drop(active_guard);
    eko::file::remove_file(&active_lock_path);
    let _ = harvest_overlay_home(paths, store, vault, &norm_email);
    spawn_res.map(|code| (code, overlay_home))
}

/// Run `agy` interactively inside `<config_dir>/homes/<slug>/` without mutating global `~/.gemini`.
pub fn run_isolated_agy(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    email: &str,
    agy_args: &[String],
) -> Result<i32> {
    let (code, _) = run_isolated_agy_with(paths, store, vault, email, |agy_bin, env_overrides| {
        spawn_interactive_tty(agy_bin, agy_args, env_overrides, None)
    })?;
    Ok(code)
}

/// Where a non-interactive `agy` run works and writes its output.
pub struct Capture<'a> {
    /// Working directory of the child.
    pub cwd: &'a str,
    /// File that receives stdout (created or truncated, mode 0600).
    pub stdout_path: &'a str,
    /// File that receives stderr (created or truncated, mode 0600).
    pub stderr_path: &'a str,
}

/// Like `run_isolated_agy`, but non-interactive: runs `agy` in `capture.cwd` with stdout and stderr redirected to files; returns `(exit_code, overlay_home)`.
pub fn run_isolated_agy_capture(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    email: &str,
    agy_args: &[String],
    capture: &Capture<'_>,
) -> Result<(i32, String)> {
    run_isolated_agy_with(paths, store, vault, email, |agy_bin, env_overrides| {
        spawn_captured(
            agy_bin,
            agy_args,
            env_overrides,
            capture.cwd,
            capture.stdout_path,
            capture.stderr_path,
        )
    })
}

fn has_image_extension(name: &str) -> bool {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    if stem.is_empty() {
        return false;
    }
    ext.eq_ignore_ascii_case("jpg")
        || ext.eq_ignore_ascii_case("jpeg")
        || ext.eq_ignore_ascii_case("png")
        || ext.eq_ignore_ascii_case("webp")
}

/// Image files (jpg, jpeg, png, webp) under `<overlay_home>/.gemini/antigravity-cli/brain/` at depth 1 (`<conv>/x`) and depth 2 (`<conv>/.tempmediaStorage/x`), skipping `.user_uploaded`; each as `(path, mtime_unix_ns, conversation_id)`.
#[must_use]
pub fn brain_images(overlay_home: &str) -> Vec<(String, i64, String)> {
    let mut out = Vec::new();
    let trimmed = overlay_home.trim();
    if trimmed.is_empty() {
        return out;
    }
    let brain_dir = join_path(trimmed, ".gemini/antigravity-cli/brain");
    let Ok(conv_entries) = eko::fs::read_dir(&brain_dir) else {
        return out;
    };
    for conv_entry in conv_entries {
        let Some(conv_id) = conv_entry.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if conv_id.is_empty() || conv_id == ".user_uploaded" {
            continue;
        }
        let Some(conv_path) = conv_entry.as_path().to_str() else {
            continue;
        };
        let Ok(conv_meta) = eko::file::metadata(conv_path) else {
            continue;
        };
        if !conv_meta.is_dir() {
            continue;
        }
        let Ok(entries) = eko::fs::read_dir(conv_path) else {
            continue;
        };
        for entry in entries {
            let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name == ".user_uploaded" {
                continue;
            }
            let Some(entry_path) = entry.as_path().to_str() else {
                continue;
            };
            let Ok(meta) = eko::file::metadata(entry_path) else {
                continue;
            };
            if meta.is_file() && has_image_extension(name) {
                let mtime_ns = stat_mtime_ns(entry_path)
                    .unwrap_or_else(|_| meta.modified_secs().saturating_mul(1_000_000_000));
                out.push((entry_path.to_string(), mtime_ns, conv_id.to_string()));
            } else if meta.is_dir() && name == ".tempmediaStorage" {
                let Ok(sub_entries) = eko::fs::read_dir(entry_path) else {
                    continue;
                };
                for sub in sub_entries {
                    let Some(sub_name) = sub.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    if sub_name == ".user_uploaded" {
                        continue;
                    }
                    let Some(sub_path) = sub.as_path().to_str() else {
                        continue;
                    };
                    let Ok(sub_meta) = eko::file::metadata(sub_path) else {
                        continue;
                    };
                    if sub_meta.is_file() && has_image_extension(sub_name) {
                        let mtime_ns = stat_mtime_ns(sub_path).unwrap_or_else(|_| {
                            sub_meta.modified_secs().saturating_mul(1_000_000_000)
                        });
                        out.push((sub_path.to_string(), mtime_ns, conv_id.to_string()));
                    }
                }
            }
        }
    }
    out
}
