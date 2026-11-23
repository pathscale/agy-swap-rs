//! Secret credential storage supporting 0600 file vault and OS keychain backends.

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

use eko::command::Command;
use serde::{Deserialize, Serialize};

use crate::model::{Accounts, normalize_email};
use crate::paths::Paths;
use crate::store::{FileLock, atomic_write_private, ensure_private_dir};
use crate::{Error, Result};

const VAULT_KEYCHAIN_SERVICE: &str = "agy-swap";

/// Active secret backend selected via `AGY_SWAP_VAULT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultMode {
    File,
    Keychain,
}

impl VaultMode {
    #[must_use]
    pub fn from_env_value(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "keychain" | "os" | "keyring" => Self::Keychain,
            _ => Self::File,
        }
    }

    #[must_use]
    pub fn detect() -> Self {
        match eko::env::var("AGY_SWAP_VAULT") {
            Some(val) => Self::from_env_value(&val),
            None => Self::File,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Keychain => "keychain",
        }
    }
}

impl Default for VaultMode {
    fn default() -> Self {
        Self::File
    }
}

impl fmt::Display for VaultMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn read_vault_map(vault_file: &str) -> Result<BTreeMap<String, String>> {
    let raw = match eko::file::read(vault_file) {
        Ok(bytes) => bytes,
        Err(err) if err.is_not_found() => return Ok(BTreeMap::new()),
        Err(err) => return Err(Error::Io(err)),
    };
    let text = core::str::from_utf8(&raw)
        .map_err(|_| Error::Json("vault.json is not valid UTF-8".to_string()))?;
    if text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str::<BTreeMap<String, String>>(text).map_err(Error::from)
}

fn write_vault_map(vault_file: &str, map: &BTreeMap<String, String>) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(map)?;
    encoded.push(b'\n');
    atomic_write_private(vault_file, &encoded)
}

#[cfg(target_os = "macos")]
pub(crate) fn keychain_get(service: &str, account: &str) -> Result<Option<String>> {
    if service.is_empty() || account.is_empty() {
        return Ok(None);
    }
    let Some(out) = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-a", account, "-s", service, "-w"])
        .output()
    else {
        return Err(Error::Auth("failed to invoke /usr/bin/security".to_string()));
    };
    if !out.success() {
        return Ok(None);
    }
    let secret = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if secret.is_empty() {
        Ok(None)
    } else {
        Ok(Some(secret))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn keychain_set(
    service: &str,
    account: &str,
    secret: &str,
    allow_any_app: bool,
) -> Result<()> {
    if service.is_empty() || account.is_empty() || secret.is_empty() {
        return Err(Error::InvalidInput(
            "keychain service, account, and secret must be non-empty".to_string(),
        ));
    }
    let exists = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-a", account, "-s", service])
        .output()
        .is_some_and(|o| o.success());
    let cmd = if exists {
        Command::new("/usr/bin/security").args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-w",
            secret,
        ])
    } else if allow_any_app {
        Command::new("/usr/bin/security").args([
            "add-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            secret,
            "-A",
        ])
    } else {
        Command::new("/usr/bin/security").args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-w",
            secret,
        ])
    };
    let Some(out) = cmd.output() else {
        return Err(Error::Auth("failed to invoke /usr/bin/security".to_string()));
    };
    if out.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(Error::Auth(format!(
            "macOS Keychain write failed (exit {}) - {detail}",
            out.code
        )))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn keychain_delete(service: &str, account: &str) -> Result<()> {
    if service.is_empty() || account.is_empty() {
        return Ok(());
    }
    let _ = Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-a", account, "-s", service])
        .output();
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn keychain_get(service: &str, account: &str) -> Result<Option<String>> {
    if service.is_empty() || account.is_empty() {
        return Ok(None);
    }
    for attr in ["username", "account"] {
        if let Some(out) = Command::new("secret-tool")
            .args(["lookup", "service", service, attr, account])
            .output()
        {
            if out.success() {
                let secret = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !secret.is_empty() {
                    return Ok(Some(secret));
                }
            }
        }
    }
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn keychain_set(
    service: &str,
    account: &str,
    secret: &str,
    _allow_any_app: bool,
) -> Result<()> {
    if service.is_empty() || account.is_empty() || secret.is_empty() {
        return Err(Error::InvalidInput(
            "secret-tool service, account, and secret must be non-empty".to_string(),
        ));
    }
    let script = "printf '%s' \"$AGY_SWAP_SECRET_VAL\" | secret-tool store --label=\"$AGY_SWAP_SECRET_SVC\" service \"$AGY_SWAP_SECRET_SVC\" username \"$AGY_SWAP_SECRET_ACC\" account \"$AGY_SWAP_SECRET_ACC\"";
    let Some(out) = Command::new("/bin/sh")
        .args(["-c", script])
        .env("AGY_SWAP_SECRET_SVC", service)
        .env("AGY_SWAP_SECRET_ACC", account)
        .env("AGY_SWAP_SECRET_VAL", secret)
        .output()
    else {
        return Err(Error::Auth("failed to invoke secret-tool".to_string()));
    };
    if out.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(Error::Auth(format!(
            "secret-tool store failed (exit {}) - {detail}",
            out.code
        )))
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn keychain_delete(service: &str, account: &str) -> Result<()> {
    if service.is_empty() || account.is_empty() {
        return Ok(());
    }
    for attr in ["username", "account"] {
        let _ = Command::new("secret-tool")
            .args(["clear", "service", service, attr, account])
            .output();
    }
    Ok(())
}

/// Credential vault storing long-lived OAuth tokens outside `accounts.json`.
#[derive(Debug, Clone)]
pub struct Vault {
    paths: Paths,
    mode: VaultMode,
}

impl Vault {
    #[must_use]
    pub fn new(paths: Paths) -> Self {
        Self::with_mode(paths, VaultMode::detect())
    }

    #[must_use]
    pub fn with_mode(paths: Paths, mode: VaultMode) -> Self {
        Self { paths, mode }
    }

    #[must_use]
    pub const fn mode(&self) -> VaultMode {
        self.mode
    }

    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self.mode {
            VaultMode::File => format!("{} (0600 file vault)", self.paths.vault_file),
            VaultMode::Keychain => "OS credential store (AGY_SWAP_VAULT=keychain)".to_string(),
        }
    }

    #[must_use]
    pub fn key_for_email(email: &str) -> String {
        let normalized = normalize_email(email).unwrap_or_else(|| email.trim().to_ascii_lowercase());
        format!("account:{normalized}")
    }

    /// Look up a secret by `key`, returning `Ok(None)` when absent.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        let k = key.trim();
        if k.is_empty() {
            return Ok(None);
        }
        match self.mode {
            VaultMode::File => {
                if !eko::file::exists(&self.paths.vault_file) {
                    return Ok(None);
                }
                let _guard = if eko::file::exists(&self.paths.config_dir) {
                    FileLock::acquire(&self.paths.vault_lock).ok()
                } else {
                    None
                };
                let map = read_vault_map(&self.paths.vault_file)?;
                Ok(map.get(k).cloned().filter(|v| !v.is_empty()))
            }
            VaultMode::Keychain => keychain_get(VAULT_KEYCHAIN_SERVICE, k),
        }
    }

    /// Store or update `secret` at `key`.
    pub fn set(&self, key: &str, secret: &str) -> Result<()> {
        let k = key.trim();
        let s = secret.trim();
        if k.is_empty() || s.is_empty() {
            return Err(Error::InvalidInput(
                "vault key and secret must not be empty".to_string(),
            ));
        }
        match self.mode {
            VaultMode::File => {
                ensure_private_dir(&self.paths.config_dir)?;
                let _guard = FileLock::acquire(&self.paths.vault_lock)?;
                let mut map = read_vault_map(&self.paths.vault_file)?;
                map.insert(k.to_string(), s.to_string());
                write_vault_map(&self.paths.vault_file, &map)
            }
            VaultMode::Keychain => keychain_set(VAULT_KEYCHAIN_SERVICE, k, s, false),
        }
    }

    /// Delete `key` from the vault if present.
    pub fn delete(&self, key: &str) -> Result<()> {
        let k = key.trim();
        if k.is_empty() {
            return Ok(());
        }
        match self.mode {
            VaultMode::File => {
                if !eko::file::exists(&self.paths.vault_file) {
                    return Ok(());
                }
                ensure_private_dir(&self.paths.config_dir)?;
                let _guard = FileLock::acquire(&self.paths.vault_lock)?;
                let mut map = read_vault_map(&self.paths.vault_file)?;
                if map.remove(k).is_some() {
                    write_vault_map(&self.paths.vault_file, &map)?;
                }
                Ok(())
            }
            VaultMode::Keychain => keychain_delete(VAULT_KEYCHAIN_SERVICE, k),
        }
    }

    /// Migrate inline `legacy_token_data` entries from `accounts` into this vault.
    pub fn migrate_legacy(&self, accounts: &mut Accounts) -> Result<usize> {
        let emails = accounts.order.clone();
        let mut migrated = 0usize;
        for email in emails {
            let Some(acc) = accounts.get_mut(&email) else {
                continue;
            };
            let Some(raw) = acc
                .legacy_token_data
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(ToString::to_string)
            else {
                acc.legacy_token_data = None;
                continue;
            };
            let key = acc.secret_key();
            self.set(&key, &raw)?;
            acc.vault_ref = Some(key);
            acc.legacy_token_data = None;
            migrated += 1;
        }
        Ok(migrated)
    }
}
