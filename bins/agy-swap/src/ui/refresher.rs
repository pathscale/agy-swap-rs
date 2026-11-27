//! Quota refreshes off the UI thread. A refresh is network-bound (an OAuth refresh plus quota calls per account),
//! so running it inline froze the deck: the first key after start waited for the startup refresh, and moving the
//! selection made that account due and stalled the next tick. A single worker thread now owns its own HTTP client
//! and does the work; the deck only submits jobs and applies outcomes.

use std::string::String;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use agy_core::{
    http::HttpClient, isolate::harvest_overlay_home, quota::QuotaService, Accounts, Paths, Store,
    Vault,
};

pub(crate) enum Job {
    /// Refresh every account.
    All { force: bool },
    /// Refresh one account.
    One(String),
    /// Refresh the first due account among `candidates` (already filtered and ordered by the deck).
    Due {
        candidates: Vec<String>,
        active: Option<String>,
    },
}

pub(crate) enum Outcome {
    All {
        ok: usize,
        err: usize,
        first_err: String,
    },
    One {
        email: String,
        err: Option<String>,
    },
    Due,
    Failed(String),
}

pub(crate) struct Refresher {
    tx: Sender<Job>,
    rx: Receiver<Outcome>,
    pending: usize,
}

static REFRESHER: OnceLock<Mutex<Refresher>> = OnceLock::new();

/// The process-wide refresher, started on first use with copies of the deck's handles.
pub(crate) fn with<R>(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    f: impl FnOnce(&mut Refresher) -> R,
) -> R {
    let cell = REFRESHER.get_or_init(|| {
        Mutex::new(Refresher::spawn(
            paths.clone(),
            store.clone(),
            vault.clone(),
        ))
    });
    let mut guard = cell
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut guard)
}

impl Refresher {
    fn spawn(paths: Paths, store: Store, vault: Vault) -> Self {
        let (tx, jobs) = channel::<Job>();
        let (done, rx) = channel::<Outcome>();
        std::thread::Builder::new()
            .name("quota-refresh".into())
            .spawn(move || {
                let mut svc: Option<QuotaService> = None;
                while let Ok(job) = jobs.recv() {
                    let out = match svc.as_mut() {
                        Some(s) => run(s, &paths, &store, &vault, job),
                        None => match HttpClient::new() {
                            Ok(http) => run(
                                svc.insert(QuotaService::new(http)),
                                &paths,
                                &store,
                                &vault,
                                job,
                            ),
                            Err(err) => Outcome::Failed(err.to_string()),
                        },
                    };
                    if done.send(out).is_err() {
                        break;
                    }
                }
            })
            .ok();
        Self { tx, rx, pending: 0 }
    }

    pub(crate) fn busy(&self) -> bool {
        self.pending > 0
    }

    pub(crate) fn submit(&mut self, job: Job) {
        if self.tx.send(job).is_ok() {
            self.pending += 1;
        }
    }

    pub(crate) fn try_recv(&mut self) -> Option<Outcome> {
        match self.rx.try_recv() {
            Ok(out) => {
                self.pending = self.pending.saturating_sub(1);
                Some(out)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.pending = 0;
                None
            }
        }
    }
}

/// Put freshly refreshed accounts back into the latest accounts file, so edits the deck saved meanwhile survive.
fn save_refreshed(store: &Store, refreshed: &Accounts, emails: &[String]) {
    let mut latest = store.load().unwrap_or_else(|_| refreshed.clone());
    for email in emails {
        if let (Some(src), Some(dst)) = (refreshed.get(email), latest.get_mut(email)) {
            *dst = src.clone();
        }
    }
    let _ = store.save(&mut latest);
}

fn run(svc: &mut QuotaService, paths: &Paths, store: &Store, vault: &Vault, job: Job) -> Outcome {
    let now_unix = agy_core::wall_unix_secs();
    let Ok(mut accounts) = store.load() else {
        return Outcome::Failed("cannot read accounts".into());
    };
    match job {
        Job::All { force } => {
            for email in accounts.order.clone() {
                let _ = harvest_overlay_home(paths, store, vault, &email);
            }
            accounts = store.load().unwrap_or(accounts);
            let results = svc.refresh_all(&mut accounts, vault, force, now_unix);
            let (mut ok, mut err, mut first_err) = (0, 0, String::new());
            let mut emails = Vec::new();
            for (email, res) in results {
                match res {
                    Ok(()) => ok += 1,
                    Err(e) => {
                        if first_err.is_empty() {
                            first_err = e.to_string();
                        }
                        err += 1;
                    }
                }
                emails.push(email);
            }
            save_refreshed(store, &accounts, &emails);
            Outcome::All { ok, err, first_err }
        }
        Job::One(email) => {
            let _ = harvest_overlay_home(paths, store, vault, &email);
            accounts = store.load().unwrap_or(accounts);
            let Some(acc) = accounts.get_mut(&email) else {
                return Outcome::One {
                    email,
                    err: Some("account not found".into()),
                };
            };
            let err = svc
                .refresh_account(acc, vault, now_unix)
                .err()
                .map(|e| e.to_string());
            save_refreshed(store, &accounts, core::slice::from_ref(&email));
            Outcome::One { email, err }
        }
        Job::Due { candidates, active } => {
            let target = candidates.into_iter().find(|em| {
                accounts.get(em).is_some_and(|acc| {
                    let is_active = active
                        .as_deref()
                        .is_some_and(|a| a.eq_ignore_ascii_case(&acc.email));
                    svc.is_due(acc, is_active, now_unix)
                })
            });
            if let Some(email) = target {
                let _ = harvest_overlay_home(paths, store, vault, &email);
                accounts = store.load().unwrap_or(accounts);
                if let Some(acc) = accounts.get_mut(&email) {
                    let _ = svc.refresh_account(acc, vault, now_unix);
                    save_refreshed(store, &accounts, core::slice::from_ref(&email));
                }
            }
            Outcome::Due
        }
    }
}
