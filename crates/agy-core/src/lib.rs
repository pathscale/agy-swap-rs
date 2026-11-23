#![no_std]

extern crate alloc;

#[allow(unused_imports)]
use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

pub mod backup;
pub mod http;
pub mod isolate;
pub mod logwatch;
pub mod model;
pub mod oauth;
pub mod ops;
pub mod paths;
pub mod policy;
pub mod quota;
pub mod session;
pub mod store;
pub mod vault;

pub use backup::BackupBundle;
pub use http::{HttpClient, HttpResponse};
pub use isolate::{
    active_isolated_sessions, harvest_overlay_home, prepare_account_overlay_home,
    run_isolated_agy, spawn_interactive_tty, write_keyring_bypass_marker_2036,
};
pub use logwatch::{FailoverResult, SwitchRuntime, SwitchRuntimeState};
pub use model::{
    Account, Accounts, Badge, HistoryEntry, ModelFamily, PoolQuota, PoolWindow, QuotaSnapshot,
    Settings,
};
pub use oauth::TokenBundle;
pub use ops::{DoctorCheck, ForecastEntry};
pub use paths::{Paths, SemVer, wall_unix_secs};
pub use policy::{
    BindMode, DirectoryBinding, PoolFailoverPolicy, PoolMatchMode, Profile, RankingPolicy,
    Recommendation, RouteDecision, RouteStrategy, SwitchMode,
};
pub use quota::QuotaService;
pub use session::SessionManager;
pub use store::{FileLock, Store, atomic_write_private};
pub use vault::{Vault, VaultMode};

pub const VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Io(eko::file::Error),
    Sys(eko::Errno),
    Json(String),
    Conflict,
    InvalidInput(String),
    Auth(String),
    VerifyRequired { email: String, url: String },
    Network(String),
    RateLimited { retry_after_secs: u64 },
    Crypto(String),
    NotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error - {err}"),
            Self::Sys(err) => write!(f, "system error - {err}"),
            Self::Json(msg) => write!(f, "JSON error - {msg}"),
            Self::Conflict => f.write_str("store modified concurrently - retry operation"),
            Self::InvalidInput(msg) => write!(f, "invalid input - {msg}"),
            Self::Auth(msg) => write!(f, "authentication error - {msg}"),
            Self::VerifyRequired { email, url } => {
                if url.is_empty() {
                    write!(f, "Google verification required for {email}")
                } else {
                    write!(f, "Google verification required for {email} - {url}")
                }
            }
            Self::Network(msg) => write!(f, "network error - {msg}"),
            Self::RateLimited { retry_after_secs } => {
                write!(f, "rate limited - retry after {retry_after_secs}s")
            }
            Self::Crypto(msg) => write!(f, "crypto error - {msg}"),
            Self::NotFound(msg) => write!(f, "not found - {msg}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<eko::file::Error> for Error {
    fn from(err: eko::file::Error) -> Self {
        Self::Io(err)
    }
}

impl From<eko::Errno> for Error {
    fn from(err: eko::Errno) -> Self {
        Self::Sys(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

pub type Result<T> = core::result::Result<T, Error>;
