//! File-locked atomic persistence for accounts.json, settings.json, and bounded history.

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
use core::sync::atomic::{AtomicU64, Ordering};

use eko::file::File;
use eko::path::Path;
use serde_json::{Map, Value};

use crate::model::{normalize_email, Accounts, HistoryEntry, Settings};
use crate::paths::{
    format_rfc3339_utc, join_path, parse_rfc3339_unix, sha256_hex, wall_unix_ns, Paths,
};
use crate::{Error, Result};

const REVISION_ABSENT: i64 = -1;
const DEFAULT_MAX_HISTORY_BYTES: usize = 8 * 1024 * 1024;

static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(1);

fn set_dir_mode(path: &str, mode: u32) -> Result<()> {
    let c = Path::new(path).as_c();
    let fd = unsafe { eko::libc::open2(c.as_ptr().cast(), eko::libc::O_RDONLY) };
    if fd < 0 {
        return Err(Error::Sys(eko::Errno::current()));
    }
    let chmod_res = eko::file::fchmod(fd, mode);
    unsafe {
        let _ = eko::libc::close(fd);
    }
    chmod_res.map_err(Error::Sys)
}

/// Create `path` and all missing parents, enforcing `0700` permissions on the leaf directory.
pub fn ensure_private_dir(path: &str) -> Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    eko::file::create_dir_all(trimmed)?;
    set_dir_mode(trimmed, 0o700)
}

fn fsync_dir_best_effort(dir_path: &str) {
    if dir_path.is_empty() {
        return;
    }
    let c = Path::new(dir_path).as_c();
    let fd = unsafe { eko::libc::open2(c.as_ptr().cast(), eko::libc::O_RDONLY) };
    if fd >= 0 {
        unsafe {
            let _ = eko::libc::fsync(fd);
            let _ = eko::libc::close(fd);
        }
    }
}

pub(crate) fn stat_mtime_ns(path: &str) -> Result<i64> {
    let c = Path::new(path).as_c();
    let mut st: eko::libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { eko::libc::stat(c.as_ptr().cast(), &mut st) } != 0 {
        return Err(Error::Sys(eko::Errno::current()));
    }
    let ns = (st.st_mtime as i128) * 1_000_000_000 + (st.st_mtime_nsec as i128);
    Ok(if ns <= 0 { 1 } else { ns as i64 })
}

/// Advisory cross-process file lock backed by `flock(2)` on a `.lock` file.
pub struct FileLock {
    file: File,
}

impl FileLock {
    fn open_lock_file(lock_path: &str) -> Result<File> {
        let trimmed = lock_path.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidInput(
                "lock path must not be empty".to_string(),
            ));
        }
        if let Some(parent) = Path::new(trimmed).parent().and_then(|p| p.to_str()) {
            if !parent.is_empty() {
                ensure_private_dir(parent)?;
            }
        }
        let c = Path::new(trimmed).as_c();
        let fd = unsafe {
            eko::libc::open3(
                c.as_ptr().cast(),
                eko::libc::O_RDWR | eko::libc::O_CREAT,
                0o600 as eko::libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(Error::Io(eko::file::Error::from_errno(
                eko::Errno::current(),
                "open lock",
            )));
        }
        let _ = eko::file::set_cloexec(fd, true);
        let file = unsafe { File::from_raw_fd(fd) };
        let _ = file.set_permissions_mode(0o600);
        Ok(file)
    }

    /// Acquire an exclusive blocking `flock(2)` on `lock_path`.
    pub fn acquire(lock_path: &str) -> Result<Self> {
        let file = Self::open_lock_file(lock_path)?;
        loop {
            match eko::file::flock_exclusive(file.as_raw_fd(), false) {
                Ok(()) => return Ok(Self { file }),
                Err(err) if err.interrupted() => continue,
                Err(err) => {
                    return Err(Error::Io(eko::file::Error::from_errno(err, "flock")));
                }
            }
        }
    }

    /// Attempt a non-blocking exclusive `flock(2)` on `lock_path`.
    pub fn try_acquire(lock_path: &str) -> Result<Option<Self>> {
        let file = Self::open_lock_file(lock_path)?;
        loop {
            match eko::file::flock_exclusive(file.as_raw_fd(), true) {
                Ok(()) => return Ok(Some(Self { file })),
                Err(err) if err.interrupted() => continue,
                Err(err) if err.0 == eko::libc::EAGAIN || err.0 == eko::libc::EWOULDBLOCK => {
                    return Ok(None);
                }
                Err(err) => {
                    return Err(Error::Io(eko::file::Error::from_errno(err, "flock")));
                }
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Atomically write `bytes` to `path` with explicit file mode `mode` via sibling temp + fsync + rename.
pub fn atomic_write_mode(path: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidInput(
            "target path must not be empty".to_string(),
        ));
    }
    if let Ok(meta) = eko::file::symlink_metadata(trimmed) {
        if meta.is_dir() {
            return Err(Error::Io(eko::file::Error::from_errno(
                eko::Errno(eko::libc::EISDIR),
                "atomic_write",
            )));
        }
    }
    let p = Path::new(trimmed);
    let parent = p
        .parent()
        .and_then(|d| d.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(".");
    if (mode & 0o077) == 0 && parent != "." && parent != "/" {
        ensure_private_dir(parent)?;
    } else if parent != "." && parent != "/" {
        eko::file::create_dir_all(parent)?;
    }
    let base_name = p
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("state");
    let pid = unsafe { eko::libc::getpid() };

    let mut created: Option<(String, File)> = None;
    let mut last_errno = eko::Errno(eko::libc::EEXIST);
    let mut attempt = 0usize;
    while attempt < 32 {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("{parent}/.{base_name}.tmp.{pid}.{seq}");
        let c = Path::new(&candidate).as_c();
        let fd = unsafe {
            eko::libc::open3(
                c.as_ptr().cast(),
                eko::libc::O_WRONLY | eko::libc::O_CREAT | eko::libc::O_EXCL,
                mode as eko::libc::mode_t,
            )
        };
        if fd >= 0 {
            let _ = eko::file::set_cloexec(fd, true);
            let file = unsafe { File::from_raw_fd(fd) };
            created = Some((candidate, file));
            break;
        }
        last_errno = eko::Errno::current();
        if last_errno.0 != eko::libc::EEXIST {
            break;
        }
        attempt += 1;
    }

    let Some((tmp_path, mut tmp_file)) = created else {
        return Err(Error::Io(eko::file::Error::from_errno(
            last_errno,
            "open temp",
        )));
    };

    let write_res = (|| -> Result<()> {
        tmp_file.set_permissions_mode(mode)?;
        tmp_file.write_all(bytes)?;
        tmp_file.sync_all()?;
        Ok(())
    })();
    drop(tmp_file);

    if let Err(err) = write_res {
        eko::file::remove_file(&tmp_path);
        return Err(err);
    }
    if let Err(err) = eko::file::rename(&tmp_path, trimmed) {
        eko::file::remove_file(&tmp_path);
        return Err(Error::Io(err));
    }
    fsync_dir_best_effort(parent);
    Ok(())
}

/// Atomically write `bytes` to `path` with `0600` owner-only permissions.
pub fn atomic_write_private(path: &str, bytes: &[u8]) -> Result<()> {
    atomic_write_mode(path, bytes, 0o600)
}

fn parse_history_line(line: &str) -> Option<HistoryEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(entry) = serde_json::from_str::<HistoryEntry>(trimmed) {
        return Some(entry);
    }
    let val: Value = serde_json::from_str(trimmed).ok()?;
    let obj = val.as_object()?;
    let kind = obj
        .get("kind")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    let timestamp_unix = obj
        .get("timestamp_unix")
        .or_else(|| obj.get("at_unix"))
        .or_else(|| obj.get("ts_unix"))
        .and_then(Value::as_i64)
        .or_else(|| {
            obj.get("at")
                .or_else(|| obj.get("timestamp"))
                .and_then(|v| {
                    v.as_i64().or_else(|| {
                        v.as_str().and_then(|s| {
                            parse_rfc3339_unix(s).or_else(|| s.trim().parse::<i64>().ok())
                        })
                    })
                })
        })
        .unwrap_or(0);
    let email = obj
        .get("email")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|e| normalize_email(e).unwrap_or_else(|| e.to_string()));
    let detail = obj
        .get("detail")
        .or_else(|| obj.get("message"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_default();
    Some(HistoryEntry {
        timestamp_unix,
        kind,
        email,
        detail,
    })
}

/// Persistent storage handle for `accounts.json`, `settings.json`, and `history-v1.jsonl`.
#[derive(Debug, Clone)]
pub struct Store {
    paths: Paths,
}

impl Store {
    #[must_use]
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Load ordered accounts from `accounts.json` and record revision metadata.
    pub fn load(&self) -> Result<Accounts> {
        let raw = match eko::file::read(&self.paths.accounts_file) {
            Ok(bytes) => bytes,
            Err(err) if err.is_not_found() => {
                let mut empty = Accounts::new();
                empty.revision_ns = REVISION_ABSENT;
                return Ok(empty);
            }
            Err(err) => return Err(Error::Io(err)),
        };
        let mtime_ns =
            stat_mtime_ns(&self.paths.accounts_file).unwrap_or_else(|_| wall_unix_ns().max(1));
        if raw.is_empty() {
            let mut empty = Accounts::new();
            empty.revision_ns = mtime_ns;
            empty.revision_hash = sha256_hex(&raw);
            return Ok(empty);
        }
        let _ = core::str::from_utf8(&raw)
            .map_err(|_| Error::Json("accounts.json is not valid UTF-8".to_string()))?;
        let mut accounts = Accounts::decode_ordered_json(&raw)?;
        accounts.revision_ns = mtime_ns;
        accounts.revision_hash = sha256_hex(&raw);
        Ok(accounts)
    }

    /// Atomically save `accounts` (`0600`) under an exclusive lock with optimistic conflict check.
    pub fn save(&self, accounts: &mut Accounts) -> Result<()> {
        ensure_private_dir(&self.paths.config_dir)?;
        let _guard = FileLock::acquire(&self.paths.accounts_lock)?;
        let disk_bytes = match eko::file::read(&self.paths.accounts_file) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.is_not_found() => None,
            Err(err) => return Err(Error::Io(err)),
        };
        if accounts.revision_ns == REVISION_ABSENT {
            if disk_bytes.is_some() {
                return Err(Error::Conflict);
            }
        } else if !accounts.revision_hash.is_empty() {
            match &disk_bytes {
                None => return Err(Error::Conflict),
                Some(existing) => {
                    if sha256_hex(existing) != accounts.revision_hash {
                        return Err(Error::Conflict);
                    }
                }
            }
        }
        if let Some(ref existing) = disk_bytes {
            if !existing.is_empty() {
                let _ = atomic_write_private(&self.paths.accounts_backup_file(), existing);
            }
        }
        let encoded = accounts.encode_ordered_json()?;
        atomic_write_private(&self.paths.accounts_file, &encoded)?;
        accounts.revision_ns =
            stat_mtime_ns(&self.paths.accounts_file).unwrap_or_else(|_| wall_unix_ns().max(1));
        accounts.revision_hash = sha256_hex(&encoded);
        Ok(())
    }

    /// Load `settings.json` (or legacy `config.json`), returning defaults when absent.
    pub fn load_settings(&self) -> Result<Settings> {
        let legacy_cfg = join_path(&self.paths.config_dir, "config.json");
        let target = if eko::file::exists(&self.paths.settings_file) {
            &self.paths.settings_file
        } else if eko::file::exists(&legacy_cfg) {
            &legacy_cfg
        } else {
            return Ok(Settings::default());
        };
        let raw = match eko::file::read_to_string(target) {
            Ok(s) => s,
            Err(err) if err.is_not_found() => return Ok(Settings::default()),
            Err(err) => return Err(Error::Io(err)),
        };
        if raw.trim().is_empty() {
            return Ok(Settings::default());
        }
        serde_json::from_str::<Settings>(&raw).map_err(Error::from)
    }

    /// Persist `settings.json` atomically (`0600`) under an exclusive lock.
    pub fn save_settings(&self, s: &Settings) -> Result<()> {
        ensure_private_dir(&self.paths.config_dir)?;
        let lock_path = format!("{}.lock", self.paths.settings_file);
        let _guard = FileLock::acquire(&lock_path)?;
        let mut encoded = serde_json::to_vec_pretty(s)?;
        encoded.push(b'\n');
        atomic_write_private(&self.paths.settings_file, &encoded)
    }

    /// Append a bounded audit event (`0600`) to `history-v1.jsonl`.
    pub fn append_history(&self, entry: &HistoryEntry) -> Result<()> {
        ensure_private_dir(&self.paths.config_dir)?;
        let lock_path = format!("{}.lock", self.paths.history_file);
        let _guard = FileLock::acquire(&lock_path)?;
        let mut map = Map::new();
        map.insert("schema".to_string(), Value::from(1));
        map.insert(
            "at".to_string(),
            Value::String(format_rfc3339_utc(entry.timestamp_unix)),
        );
        map.insert(
            "timestamp_unix".to_string(),
            Value::from(entry.timestamp_unix),
        );
        map.insert("kind".to_string(), Value::String(entry.kind.clone()));
        if let Some(ref em) = entry.email {
            if !em.is_empty() {
                map.insert("email".to_string(), Value::String(em.clone()));
            }
        }
        if !entry.detail.is_empty() {
            map.insert("detail".to_string(), Value::String(entry.detail.clone()));
        }
        let mut line = serde_json::to_vec(&Value::Object(map))?;
        line.push(b'\n');

        let c = Path::new(&self.paths.history_file).as_c();
        let fd = unsafe {
            eko::libc::open3(
                c.as_ptr().cast(),
                eko::libc::O_WRONLY | eko::libc::O_CREAT | eko::libc::O_APPEND,
                0o600 as eko::libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(Error::Io(eko::file::Error::from_errno(
                eko::Errno::current(),
                "append history",
            )));
        }
        let _ = eko::file::set_cloexec(fd, true);
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.set_permissions_mode(0o600)?;
        file.write_all(&line)?;
        file.sync_all()?;
        let size = file.len().unwrap_or(0) as usize;
        drop(file);

        if size > DEFAULT_MAX_HISTORY_BYTES {
            if let Ok(raw) = eko::file::read_to_string(&self.paths.history_file) {
                let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
                let keep_from = lines.len() / 2;
                let mut trimmed = String::new();
                for l in &lines[keep_from..] {
                    trimmed.push_str(l);
                    trimmed.push('\n');
                }
                let _ = atomic_write_private(&self.paths.history_file, trimmed.as_bytes());
            }
        }
        Ok(())
    }

    /// Read up to `limit` newest history events (newest first; `0` reads all retained events).
    pub fn read_history(&self, limit: usize) -> Result<Vec<HistoryEntry>> {
        let legacy = join_path(&self.paths.config_dir, "history.jsonl");
        let target = if eko::file::exists(&self.paths.history_file) {
            &self.paths.history_file
        } else if eko::file::exists(&legacy) {
            &legacy
        } else {
            return Ok(Vec::new());
        };
        let raw = match eko::file::read_to_string(target) {
            Ok(s) => s,
            Err(err) if err.is_not_found() => return Ok(Vec::new()),
            Err(err) => return Err(Error::Io(err)),
        };
        let cap = if limit == 0 { usize::MAX } else { limit };
        let lines: Vec<&str> = raw.lines().collect();
        let mut out = Vec::new();
        let mut idx = lines.len();
        while idx > 0 && out.len() < cap {
            idx -= 1;
            if let Some(entry) = parse_history_line(lines[idx]) {
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// Remove persisted history log files under the history lock.
    pub fn clear_history(&self) -> Result<()> {
        if eko::file::exists(&self.paths.config_dir) {
            let lock_path = format!("{}.lock", self.paths.history_file);
            let _guard = FileLock::acquire(&lock_path)?;
            eko::file::remove_file(&self.paths.history_file);
            eko::file::remove_file(join_path(&self.paths.config_dir, "history.jsonl"));
        }
        Ok(())
    }
}
