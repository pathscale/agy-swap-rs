pub(crate) extern crate alloc;

pub mod deck;
mod refresher;
pub mod state;
pub mod theme;
pub mod views;

use self::alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use self::state::{
    load_runtime_file, lookup_account_token, open_vault, vault_key_for, warm_isolated_map,
    ActiveView, DeckState, DividerDrag, HitTarget, KeycapAction, LastClick, Modal, PaletteCommand,
    ToastLevel,
};
use self::theme::Theme;
use agy_core::{
    atomic_write_private,
    backup::export_backup_to_file,
    http::HttpClient,
    isolate::{harvest_overlay_home, run_isolated_agy},
    logwatch::{ack_restart, init_log_cursors_at_eof, poll_logs_once},
    oauth::{
        ensure_valid_token, fetch_verified_email, import_current_session, login_via_agy_cli,
        TokenBundle,
    },
    ops::run_doctor,
    policy::{select_next, Profile, SwitchMode},
    quota::QuotaService,
    Account, Accounts, Badge, HistoryEntry, Paths, SessionManager, Store, Vault,
};
use agy_tui::{
    Breakpoint, Event, Frame, HitMap, Key, Modifiers, MouseEvent, MouseKind, PointerShape, Rect,
    Surface, Terminal,
};

pub fn render_snapshot_with_hits(
    state: &DeckState,
    w: u16,
    h: u16,
    ascii: bool,
) -> (Surface, HitMap) {
    let theme = Theme::detect(ascii);
    let mut surface = Surface::new(w, h);
    let mut hits = HitMap::new();
    {
        let mut frame = Frame::new(&mut surface, &mut hits, theme.env.ascii);
        deck::render_deck(&mut frame, state, &theme);
    }
    (surface, hits)
}

pub fn render_snapshot_surface(state: &DeckState, w: u16, h: u16, ascii: bool) -> Surface {
    render_snapshot_with_hits(state, w, h, ascii).0
}

pub fn render_frame_for_size(paths: &Paths, w: u16, h: u16, ascii: bool) -> String {
    let state = DeckState::load(paths);
    render_snapshot_surface(&state, w, h, ascii).dump_plain()
}

fn is_offline() -> bool {
    match eko::env::var("AGY_SWAP_OFFLINE") {
        Some(v) => {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        }
        None => false,
    }
}

fn open_https_browser(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("refusing to open non-HTTPS verification URL".to_string());
    }
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(target_os = "macos"))]
    let opener = "xdg-open";
    match eko::command::Command::new(opener)
        .arg(url.as_bytes())
        .output()
    {
        Some(out) if out.success() => Ok(()),
        Some(out) => Err(format!("{opener} exited with code {}", out.code)),
        None => Err(format!("failed to execute {opener}")),
    }
}

fn record_history(store: &Store, kind: &str, email: Option<String>, detail: &str) {
    let entry = HistoryEntry::now(kind, email, detail);
    let _ = store.append_history(&entry);
}

fn ensure_quota_service(slot: &mut Option<QuotaService>) -> Result<&mut QuotaService, String> {
    if slot.is_none() {
        let http = HttpClient::new().map_err(|e| e.to_string())?;
        *slot = Some(QuotaService::new(http));
    }
    slot.as_mut()
        .ok_or_else(|| "quota service unavailable".to_string())
}

fn select_email_in_state(state: &mut DeckState, target_email: &str) {
    let vis = state.visible_emails();
    if let Some(pos) = vis
        .iter()
        .position(|e| e.eq_ignore_ascii_case(target_email))
    {
        state.selected = pos;
        state.armed_row_click = None;
    }
}

fn do_switch_account(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    email: &str,
    now_ms: u64,
) {
    let accounts = store.load().unwrap_or_else(|_| state.accounts.clone());
    let resolved = accounts
        .resolve(email)
        .map(ToString::to_string)
        .unwrap_or_else(|| email.to_string());
    let Some(acc) = accounts.get(&resolved) else {
        state.show_toast(
            format!("Account {email} not found"),
            ToastLevel::Error,
            now_ms,
        );
        return;
    };
    let Some(token) = lookup_account_token(acc, vault) else {
        state.show_toast(
            format!(
                "No OAuth token in vault for {} - press a to login",
                acc.email
            ),
            ToastLevel::Error,
            now_ms,
        );
        return;
    };
    let prev = state.active_email.clone();
    match session.switch_to(&acc.email, &token) {
        Ok(()) => {
            record_history(
                store,
                "switch",
                Some(acc.email.clone()),
                prev.as_deref().unwrap_or("none"),
            );
            let switched_email = acc.email.clone();
            state.reload_from_disk(paths);
            select_email_in_state(state, &switched_email);
            state.show_toast(
                format!("Switched ~/.gemini to {switched_email} (restart IDE to apply)"),
                ToastLevel::Success,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(format!("Switch failed - {err}"), ToastLevel::Error, now_ms);
        }
    }
}

fn do_delete_account(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    state: &mut DeckState,
    email: &str,
    now_ms: u64,
) {
    let mut accounts = store.load().unwrap_or_else(|_| state.accounts.clone());
    let Some(removed) = accounts.remove(email) else {
        state.show_toast(
            format!("Account {email} not found"),
            ToastLevel::Warn,
            now_ms,
        );
        return;
    };
    if let Err(err) = store.save(&mut accounts) {
        state.show_toast(format!("Remove failed - {err}"), ToastLevel::Error, now_ms);
        return;
    }
    let vkey = vault_key_for(&removed);
    let _ = vault.delete(&vkey);
    let _ = vault.delete(&format!("account:{}", removed.email));
    record_history(
        store,
        "remove",
        Some(removed.email.clone()),
        "removed from operator deck",
    );
    state.reload_from_disk(paths);
    state.show_toast(
        format!("Removed {}", removed.email),
        ToastLevel::Info,
        now_ms,
    );
}

fn do_rotate_next(store: &Store, state: &mut DeckState, now_ms: u64) {
    let accounts = store.load().unwrap_or_else(|_| state.accounts.clone());
    if accounts.is_empty() {
        state.show_toast(
            "No saved accounts - press a to login",
            ToastLevel::Warn,
            now_ms,
        );
        return;
    }
    let settings = store.load_settings().unwrap_or_default();
    let now_unix = agy_core::wall_unix_secs();
    let Some(next_email) = select_next(
        &accounts,
        state.active_email.as_deref(),
        settings.prefer_family,
        settings.default_policy,
        settings.min_remaining_pct,
        now_unix,
    ) else {
        state.show_toast(
            "No eligible standby account available",
            ToastLevel::Warn,
            now_ms,
        );
        return;
    };
    select_email_in_state(state, &next_email);
    state.modal_button_idx = 0;
    state.modal = Modal::ConfirmSwitch { email: next_email };
}

fn harvest_all_overlays(paths: &Paths, store: &Store, vault: &Vault, accounts: &Accounts) -> bool {
    let mut any = false;
    for email in &accounts.order {
        if matches!(harvest_overlay_home(paths, store, vault, email), Ok(true)) {
            any = true;
        }
    }
    any
}

fn needs_initial_quota_refresh(state: &DeckState) -> bool {
    if state.accounts.is_empty() {
        return false;
    }
    for email in &state.accounts.order {
        let Some(acc) = state.accounts.get(email) else {
            continue;
        };
        if acc.disabled || acc.verify_url.is_some() || !state.has_token(acc) {
            continue;
        }
        match acc.quota.as_ref() {
            None => return true,
            Some(q) if state.now_unix.saturating_sub(q.fetched_at_unix) > 60 => return true,
            Some(_) => {}
        }
    }
    false
}

fn do_launch_isolated_agy(
    term: &mut Terminal,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    state: &mut DeckState,
    email: &str,
    now_ms: u64,
) {
    let target = email.to_string();
    let empty_args: [String; 0] = [];
    let suspended =
        term.suspend_for_child(|| run_isolated_agy(paths, store, vault, &target, &empty_args));
    let _ = harvest_overlay_home(paths, store, vault, &target);
    state.reload_from_disk(paths);
    select_email_in_state(state, &target);
    match suspended {
        Ok(Ok(code)) => {
            record_history(
                store,
                "isolated_run",
                Some(target.clone()),
                &format!("exit={code}"),
            );
            state.reload_from_disk(paths);
            select_email_in_state(state, &target);
            state.show_toast(
                format!("Isolated agy ({target}) exited with status {code}"),
                if code == 0 {
                    ToastLevel::Success
                } else {
                    ToastLevel::Warn
                },
                now_ms,
            );
        }
        Ok(Err(err)) => {
            state.show_toast(
                format!("Isolated agy failed - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(
                format!("Terminal suspend error - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

fn do_refresh_all(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    state: &mut DeckState,
    _quota_svc: &mut Option<QuotaService>,
    force: bool,
    now_ms: u64,
) {
    if is_offline() {
        state.show_toast(
            "Offline mode enabled (AGY_SWAP_OFFLINE=1)",
            ToastLevel::Warn,
            now_ms,
        );
        return;
    }
    if state.accounts.is_empty() {
        state.show_toast("No saved accounts to refresh", ToastLevel::Info, now_ms);
        return;
    }
    // runs on the refresh thread; the outcome arrives through apply_refresh_outcomes
    refresher::with(paths, store, vault, |r| {
        r.submit(refresher::Job::All { force })
    });
    state.refreshing = true;
}

fn do_refresh_selected(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    state: &mut DeckState,
    _quota_svc: &mut Option<QuotaService>,
    now_ms: u64,
) {
    let Some(email) = state.selected_email() else {
        state.show_toast("No account selected", ToastLevel::Info, now_ms);
        return;
    };
    if is_offline() {
        state.show_toast(
            "Offline mode enabled (AGY_SWAP_OFFLINE=1)",
            ToastLevel::Warn,
            now_ms,
        );
        return;
    }
    refresher::with(paths, store, vault, |r| {
        r.submit(refresher::Job::One(email))
    });
    state.refreshing = true;
}

/// Queue a background refresh of the first due account (active first, then the selected one, then the rest).
/// Never blocks: nothing is queued while a refresh is still running.
fn do_refresh_one_due(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    state: &mut DeckState,
    _quota_svc: &mut Option<QuotaService>,
) -> bool {
    if is_offline()
        || state.accounts.is_empty()
        || refresher::with(paths, store, vault, |r| r.busy())
    {
        return false;
    }
    let mut candidates: Vec<String> = Vec::new();
    let push = |em: &str, list: &mut Vec<String>| {
        if !list.iter().any(|c| c.eq_ignore_ascii_case(em)) {
            list.push(em.to_string());
        }
    };
    if let Some(ref act) = state.active_email {
        push(act, &mut candidates);
    }
    if let Some(sel) = state.selected_email() {
        push(&sel, &mut candidates);
    }
    for em in &state.accounts.order {
        push(em, &mut candidates);
    }
    candidates.retain(|em| {
        state
            .accounts
            .get(em)
            .is_some_and(|acc| !acc.disabled && acc.verify_url.is_none() && state.has_token(acc))
    });
    if candidates.is_empty() {
        return false;
    }
    let active = state.active_email.clone();
    refresher::with(paths, store, vault, |r| {
        r.submit(refresher::Job::Due { candidates, active })
    });
    false
}

/// Apply finished background refreshes: reload, toast, clear the busy flag. Returns true when the deck must redraw.
fn apply_refresh_outcomes(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    state: &mut DeckState,
    now_ms: u64,
) -> bool {
    let mut changed = false;
    while let Some(out) = refresher::with(paths, store, vault, |r| r.try_recv()) {
        changed = true;
        state.reload_from_disk(paths);
        match out {
            refresher::Outcome::All { ok, err: 0, .. } => {
                state.show_toast(
                    format!("Refreshed {ok} account(s)"),
                    ToastLevel::Success,
                    now_ms,
                );
            }
            refresher::Outcome::All { ok, err, first_err } => {
                state.show_toast(
                    format!("Refreshed {ok}, failed {err} - {first_err}"),
                    ToastLevel::Warn,
                    now_ms,
                );
            }
            refresher::Outcome::One { email, err: None } => {
                state.show_toast(
                    format!("Refreshed quota for {email}"),
                    ToastLevel::Success,
                    now_ms,
                );
            }
            refresher::Outcome::One {
                email,
                err: Some(e),
            } => {
                state.show_toast(
                    format!("Refresh {email} failed - {e}"),
                    ToastLevel::Warn,
                    now_ms,
                );
            }
            refresher::Outcome::Due => {}
            refresher::Outcome::Failed(e) => {
                state.show_toast(
                    format!("HTTP client failed - {e}"),
                    ToastLevel::Error,
                    now_ms,
                );
            }
        }
    }
    if changed && !refresher::with(paths, store, vault, |r| r.busy()) {
        state.refreshing = false;
    }
    changed
}

fn do_migrate_vault(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    state: &mut DeckState,
    now_ms: u64,
) {
    let mut accounts = store.load().unwrap_or_else(|_| state.accounts.clone());
    match vault.migrate_legacy(&mut accounts) {
        Ok(count) => {
            if let Err(err) = store.save(&mut accounts) {
                state.show_toast(
                    format!("Vault migrated but store save failed - {err}"),
                    ToastLevel::Error,
                    now_ms,
                );
                return;
            }
            state.reload_from_disk(paths);
            state.show_toast(
                format!("Migrated {count} legacy token(s) into vault"),
                ToastLevel::Success,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(
                format!("Vault migration failed - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

fn do_toggle_switch_mode(store: &Store, state: &mut DeckState, now_ms: u64) {
    state.switch_mode = match state.switch_mode {
        SwitchMode::Auto => SwitchMode::Manual,
        SwitchMode::Manual => SwitchMode::Auto,
    };
    match state.persist_settings(store) {
        Ok(()) => {
            let lbl = match state.switch_mode {
                SwitchMode::Auto => "auto",
                SwitchMode::Manual => "manual",
            };
            state.show_toast(
                format!("Switch mode set to {lbl}"),
                ToastLevel::Success,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(
                format!("Failed to save mode - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

fn do_verify_or_toggle_mode(store: &Store, state: &mut DeckState, now_ms: u64) {
    if state.view == ActiveView::Settings {
        do_toggle_switch_mode(store, state, now_ms);
        return;
    }
    if let Some(acc) = state.selected_account() {
        if state.account_badge(acc) == Badge::Verify || acc.verify_url.is_some() {
            let url_opt = acc.verify_url.clone().filter(|u| !u.trim().is_empty());
            if let Some(url) = url_opt {
                match open_https_browser(&url) {
                    Ok(()) => state.show_toast(
                        format!("Opened verification URL - {url}"),
                        ToastLevel::Info,
                        now_ms,
                    ),
                    Err(_) => {
                        state.show_toast(format!("Verify URL: {url}"), ToastLevel::Warn, now_ms)
                    }
                }
            } else {
                state.show_toast(
                    "Account needs Google verification - run agy-swap-rs verify",
                    ToastLevel::Warn,
                    now_ms,
                );
            }
            return;
        }
    }
    do_toggle_switch_mode(store, state, now_ms);
}

fn do_ack_restart(paths: &Paths, state: &mut DeckState, now_ms: u64) {
    match ack_restart(paths) {
        Ok(rt) => {
            state.runtime = rt;
            state.show_toast("Cleared agy restart banner", ToastLevel::Success, now_ms);
        }
        Err(err) => {
            state.show_toast(
                format!("Ack restart failed - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

fn do_export_backup_meta(store: &Store, vault: &Vault, state: &mut DeckState, now_ms: u64) {
    let now_unix = agy_core::wall_unix_secs();
    let target = state.backup_path.clone();
    match export_backup_to_file(&target, store, vault, false, None, now_unix) {
        Ok(bundle) => {
            state.show_toast(
                format!(
                    "Exported {} account(s) (redacted) to {target}",
                    bundle.accounts.len()
                ),
                ToastLevel::Success,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(
                format!("Backup export failed - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

fn do_quick_create_profile(paths: &Paths, store: &Store, state: &mut DeckState, now_ms: u64) {
    let Some(email) = state.selected_email() else {
        state.show_toast(
            "Select an account on Dashboard first",
            ToastLevel::Warn,
            now_ms,
        );
        return;
    };
    let mut settings = store.load_settings().unwrap_or_default();
    let base_name: String = email
        .split('@')
        .next()
        .unwrap_or("default")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(24)
        .collect();
    let prof_name = if base_name.is_empty() {
        format!("profile-{}", settings.profiles.len() + 1)
    } else if settings.profiles.contains_key(&base_name) {
        format!("{base_name}-{}", settings.profiles.len() + 1)
    } else {
        base_name
    };
    let reserves: Vec<String> = state
        .accounts
        .order
        .iter()
        .filter(|e| !e.eq_ignore_ascii_case(&email))
        .take(2)
        .cloned()
        .collect();
    let prof = Profile {
        name: prof_name.clone(),
        primary: email.clone(),
        family: None,
        policy: settings.default_policy,
        reserves,
        threshold_pct: settings.min_remaining_pct,
    };
    settings.profiles.insert(prof_name.clone(), prof);
    match store.save_settings(&settings) {
        Ok(()) => {
            state.reload_from_disk(paths);
            state.show_toast(
                format!("Created profile '{prof_name}' -> {email}"),
                ToastLevel::Success,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(
                format!("Profile save failed - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

fn do_delete_selected_profile(paths: &Paths, store: &Store, state: &mut DeckState, now_ms: u64) {
    let mut settings = store.load_settings().unwrap_or_default();
    if settings.profiles.is_empty() {
        return;
    }
    let names: Vec<String> = settings.profiles.keys().cloned().collect();
    let idx = state.subview_cursor.min(names.len().saturating_sub(1));
    let Some(name) = names.get(idx).cloned() else {
        return;
    };
    settings.profiles.remove(&name);
    match store.save_settings(&settings) {
        Ok(()) => {
            state.subview_cursor = state.subview_cursor.saturating_sub(1);
            state.reload_from_disk(paths);
            state.show_toast(
                format!("Removed profile '{name}'"),
                ToastLevel::Info,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(
                format!("Remove profile failed - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

fn do_clear_history(paths: &Paths, state: &mut DeckState, now_ms: u64) {
    match atomic_write_private(&paths.history_file, b"") {
        Ok(()) => {
            state.subview_cursor = 0;
            state.detail_scroll = 0;
            state.reload_from_disk(paths);
            state.show_toast("Cleared local history log", ToastLevel::Info, now_ms);
        }
        Err(err) => {
            state.show_toast(
                format!("Clear history failed - {err}"),
                ToastLevel::Error,
                now_ms,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn save_onboarded_bundle(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    bundle: TokenBundle,
    history_kind: &str,
    history_detail: &str,
    is_import: bool,
    now_ms: u64,
) {
    let now_unix = agy_core::wall_unix_secs();
    let mut bundle = bundle;
    let resolved_identity = if !is_offline() {
        if let Ok(http) = HttpClient::new() {
            if bundle.is_expired(now_unix) && bundle.refresh_token.is_some() {
                if let Ok((fresh, _)) = ensure_valid_token(&http, &bundle.raw_json, now_unix) {
                    bundle = fresh;
                }
            }
            fetch_verified_email(&http, &bundle.access_token).ok()
        } else {
            None
        }
    } else {
        None
    };
    let fallback_email = bundle.email_hint.clone().or_else(|| {
        if is_import {
            session.current_email()
        } else {
            None
        }
    });
    let (email, name) = match (resolved_identity, fallback_email) {
        (Some((em, nm)), _) => (em.to_ascii_lowercase(), nm),
        (None, Some(em)) => (em.to_ascii_lowercase(), "Google User".to_string()),
        (None, None) => {
            state.show_toast(
                "Could not verify account email from OAuth token",
                ToastLevel::Error,
                now_ms,
            );
            return;
        }
    };
    let vault_key = format!("account:{email}");
    if let Err(err) = vault.set(&vault_key, &bundle.raw_json) {
        state.show_toast(
            format!("Vault write failed - {err}"),
            ToastLevel::Error,
            now_ms,
        );
        return;
    }
    let mut accounts = store.load().unwrap_or_else(|_| Accounts::new());
    let mut acc = accounts.get(&email).cloned().unwrap_or_else(|| Account {
        email: email.clone(),
        name: name.clone(),
        aliases: Vec::new(),
        tags: Vec::new(),
        vault_ref: Some(vault_key.clone()),
        legacy_token_data: None,
        verify_url: None,
        last_error: None,
        disabled: false,
        cooldowns: BTreeMap::new(),
        reserve_threshold_pct: None,
        quota: None,
    });
    if acc.name.is_empty() || name != "Google User" {
        acc.name = name;
    }
    acc.vault_ref = Some(vault_key);
    acc.legacy_token_data = None;
    acc.verify_url = None;
    acc.last_error = None;
    if !is_offline() {
        if let Ok(svc) = ensure_quota_service(quota_svc) {
            let _ = svc.refresh_account(&mut acc, vault, now_unix);
        }
    }
    accounts.upsert(acc);
    if let Err(err) = store.save(&mut accounts) {
        state.show_toast(
            format!("Store save failed - {err}"),
            ToastLevel::Error,
            now_ms,
        );
        return;
    }
    record_history(store, history_kind, Some(email.clone()), history_detail);
    state.reload_from_disk(paths);
    select_email_in_state(state, &email);
    let msg = if is_import {
        format!("Imported current session for {email}")
    } else {
        format!("Saved {email} (default ~/.gemini untouched - Enter to launch agy)")
    };
    state.show_toast(msg, ToastLevel::Success, now_ms);
}

#[allow(clippy::too_many_arguments)]
fn do_interactive_login(
    term: &mut Terminal,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    now_ms: u64,
) {
    let suspended = term.suspend_for_child(|| login_via_agy_cli(paths));
    let bundle = match suspended {
        Ok(Ok(b)) => b,
        Ok(Err(err)) => {
            state.show_toast(
                format!("Login cancelled or failed - {err}"),
                ToastLevel::Warn,
                now_ms,
            );
            return;
        }
        Err(err) => {
            state.show_toast(
                format!("Terminal suspend error - {err}"),
                ToastLevel::Error,
                now_ms,
            );
            return;
        }
    };
    save_onboarded_bundle(
        paths,
        store,
        vault,
        session,
        state,
        quota_svc,
        bundle,
        "add",
        "interactive login",
        false,
        now_ms,
    );
}

#[allow(clippy::too_many_arguments)]
fn do_import_current(
    term: &mut Terminal,
    theme: &Theme,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    now_ms: u64,
) {
    state.refreshing = true;
    let _ = term.draw(theme.env.ascii, |f| deck::render_deck(f, state, theme));
    match import_current_session(paths, session) {
        Ok(bundle) => {
            save_onboarded_bundle(
                paths,
                store,
                vault,
                session,
                state,
                quota_svc,
                bundle,
                "import_current",
                "imported ~/.gemini session",
                true,
                now_ms,
            );
        }
        Err(err) => {
            state.show_toast(format!("Import failed - {err}"), ToastLevel::Warn, now_ms);
        }
    }
    state.refreshing = false;
}

fn switch_view(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    target: ActiveView,
) {
    if state.view == ActiveView::FailoverPolicy
        && target != ActiveView::FailoverPolicy
        && state.policy_draft.dirty
    {
        state.policy_draft.dirty = false;
        state.reload_from_disk(paths);
    }
    state.view = target;
    state.detail_scroll = 0;
    state.subview_cursor = 0;
    if target == ActiveView::Doctor {
        state.doctor_checks = run_doctor(paths, store, vault, session);
    } else if target == ActiveView::FailoverPolicy {
        state.sync_policy_pools();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_palette_command(
    cmd: PaletteCommand,
    term: &mut Terminal,
    theme: &Theme,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    stacked: bool,
    now_ms: u64,
) -> bool {
    match cmd {
        PaletteCommand::GoView(v) => switch_view(paths, store, vault, session, state, v),
        PaletteCommand::LaunchIsolated => {
            if let Some(email) = state.selected_email() {
                do_launch_isolated_agy(term, paths, store, vault, state, &email, now_ms);
            } else {
                state.show_toast("No account selected", ToastLevel::Warn, now_ms);
            }
        }
        PaletteCommand::SwitchSelected => {
            if let Some(email) = state.selected_email() {
                state.modal_button_idx = 1;
                state.modal = Modal::ConfirmSwitch { email };
            } else {
                state.show_toast("No account selected", ToastLevel::Warn, now_ms);
            }
        }
        PaletteCommand::NextAccount => {
            do_rotate_next(store, state, now_ms);
        }
        PaletteCommand::RefreshQuota => {
            state.refreshing = true;
            let _ = term.draw(theme.env.ascii, |f| deck::render_deck(f, state, theme));
            do_refresh_all(paths, store, vault, state, quota_svc, true, now_ms);
        }
        PaletteCommand::RefreshSelected => {
            state.refreshing = true;
            let _ = term.draw(theme.env.ascii, |f| deck::render_deck(f, state, theme));
            do_refresh_selected(paths, store, vault, state, quota_svc, now_ms);
        }
        PaletteCommand::AddAccount => {
            state.modal_button_idx = 0;
            state.modal = Modal::AddAccountHint;
        }
        PaletteCommand::ImportCurrent => {
            do_import_current(
                term, theme, paths, store, vault, session, state, quota_svc, now_ms,
            );
        }
        PaletteCommand::DeleteSelected => {
            if let Some(email) = state.selected_email() {
                state.modal_button_idx = 0;
                state.modal = Modal::ConfirmDelete { email };
            } else {
                state.show_toast("No account selected", ToastLevel::Warn, now_ms);
            }
        }
        PaletteCommand::OpenVerify => {
            if let Some(acc) = state.selected_account() {
                if let Some(url) = acc.verify_url.clone().filter(|u| !u.trim().is_empty()) {
                    let _ = open_https_browser(&url);
                    state.show_toast(format!("Verify URL: {url}"), ToastLevel::Info, now_ms);
                } else {
                    state.show_toast(
                        "Selected account has no pending Google verification URL",
                        ToastLevel::Info,
                        now_ms,
                    );
                }
            }
        }
        PaletteCommand::MigrateVault => {
            do_migrate_vault(paths, store, vault, state, now_ms);
        }
        PaletteCommand::ToggleSwitchMode => {
            do_toggle_switch_mode(store, state, now_ms);
        }
        PaletteCommand::AckRestart => {
            do_ack_restart(paths, state, now_ms);
        }
        PaletteCommand::RunDoctor => {
            switch_view(paths, store, vault, session, state, ActiveView::Doctor);
            state.show_toast("Doctor diagnostics updated", ToastLevel::Info, now_ms);
        }
        PaletteCommand::BackupExportMeta => {
            do_export_backup_meta(store, vault, state, now_ms);
        }
        PaletteCommand::SplitNarrow => {
            state.adjust_split(-4, stacked);
            let _ = state.persist_settings(store);
        }
        PaletteCommand::SplitWiden => {
            state.adjust_split(4, stacked);
            let _ = state.persist_settings(store);
        }
        PaletteCommand::SplitReset => {
            state.reset_split(stacked);
            let _ = state.persist_settings(store);
        }
        PaletteCommand::ShortcutGuide => {
            state.modal = Modal::ShortcutGuide;
        }
        PaletteCommand::Quit => return true,
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn run_keycap_action(
    act: KeycapAction,
    term: &mut Terminal,
    theme: &Theme,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    stacked: bool,
    now_ms: u64,
) -> bool {
    match act {
        KeycapAction::MoveUp => {
            if state.view == ActiveView::Dashboard {
                state.move_selection(-1);
            } else {
                state.detail_scroll = state.detail_scroll.saturating_sub(1);
                state.subview_cursor = state.subview_cursor.saturating_sub(1);
            }
        }
        KeycapAction::MoveDown => {
            if state.view == ActiveView::Dashboard {
                state.move_selection(1);
            } else {
                state.detail_scroll = state.detail_scroll.saturating_add(1);
                state.subview_cursor = state.subview_cursor.saturating_add(1);
            }
        }
        KeycapAction::Confirm => {
            if let Some(email) = state.selected_email() {
                state.modal_button_idx = 0;
                state.modal = Modal::ConfirmSwitch { email };
            }
        }
        KeycapAction::Palette => {
            state.modal = Modal::CommandPalette {
                query: String::new(),
                selected: 0,
            };
        }
        KeycapAction::Help => {
            state.modal = Modal::ShortcutGuide;
        }
        KeycapAction::Quit => return true,
        KeycapAction::Filter => {
            state.filter_backup = state.filter.clone();
            state.selected_before_filter = state.selected;
            state.modal = Modal::FilterInput;
        }
        KeycapAction::Refresh => {
            if state.view == ActiveView::Doctor {
                state.doctor_checks = run_doctor(paths, store, vault, session);
                state.show_toast("Doctor diagnostics updated", ToastLevel::Info, now_ms);
            } else {
                state.refreshing = true;
                let _ = term.draw(theme.env.ascii, |f| deck::render_deck(f, state, theme));
                do_refresh_all(paths, store, vault, state, quota_svc, true, now_ms);
            }
        }
        KeycapAction::Next => do_rotate_next(store, state, now_ms),
        KeycapAction::Add => {
            state.modal_button_idx = 0;
            state.modal = Modal::AddAccountHint;
        }
        KeycapAction::Delete => {
            if let Some(email) = state.selected_email() {
                state.modal_button_idx = 0;
                state.modal = Modal::ConfirmDelete { email };
            }
        }
        KeycapAction::Verify => do_verify_or_toggle_mode(store, state, now_ms),
        KeycapAction::AckRestart => do_ack_restart(paths, state, now_ms),
        KeycapAction::SplitNarrow => {
            state.adjust_split(-4, stacked);
            let _ = state.persist_settings(store);
        }
        KeycapAction::SplitWiden => {
            state.adjust_split(4, stacked);
            let _ = state.persist_settings(store);
        }
        KeycapAction::SplitReset => {
            state.reset_split(stacked);
            let _ = state.persist_settings(store);
        }
        KeycapAction::BackDashboard => {
            switch_view(paths, store, vault, session, state, ActiveView::Dashboard);
        }
        KeycapAction::PolicyToggle => state.policy_toggle_current(),
        KeycapAction::PolicyMode => state.policy_toggle_match(),
        KeycapAction::PolicySave => match state.persist_settings(store) {
            Ok(()) => state.show_toast("Saved pool failover policy", ToastLevel::Success, now_ms),
            Err(e) => state.show_toast(format!("Save failed - {e}"), ToastLevel::Error, now_ms),
        },
        KeycapAction::BackupExport => do_export_backup_meta(store, vault, state, now_ms),
        KeycapAction::ImportCurrent => {
            do_import_current(
                term, theme, paths, store, vault, session, state, quota_svc, now_ms,
            );
        }
        KeycapAction::LaunchIsolated => {
            if let Some(email) = state.selected_email() {
                do_launch_isolated_agy(term, paths, store, vault, state, &email, now_ms);
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn confirm_active_modal(
    term: &mut Terminal,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    now_ms: u64,
) {
    let current = core::mem::replace(&mut state.modal, Modal::None);
    match current {
        Modal::ConfirmSwitch { email } => {
            do_launch_isolated_agy(term, paths, store, vault, state, &email, now_ms);
        }
        Modal::ConfirmDelete { email } => {
            do_delete_account(paths, store, vault, state, &email, now_ms);
        }
        Modal::AddAccountHint => {
            do_interactive_login(term, paths, store, vault, session, state, quota_svc, now_ms);
        }
        Modal::None | Modal::FilterInput | Modal::CommandPalette { .. } | Modal::ShortcutGuide => {}
    }
}

fn toggle_view(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    target: ActiveView,
) {
    let dest = if state.view == target {
        ActiveView::Dashboard
    } else {
        target
    };
    switch_view(paths, store, vault, session, state, dest);
}

#[allow(clippy::too_many_arguments)]
fn handle_key_event(
    key: Key,
    mods: Modifiers,
    term: &mut Terminal,
    theme: &Theme,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    stacked: bool,
    now_ms: u64,
) -> bool {
    if mods.ctrl && matches!(key, Key::Char('c' | 'C' | 'd' | 'D')) {
        return true;
    }
    if mods.ctrl && matches!(key, Key::Char('k' | 'K')) {
        state.modal = Modal::CommandPalette {
            query: String::new(),
            selected: 0,
        };
        return false;
    }

    if state.modal == Modal::FilterInput {
        match key {
            Key::Esc => {
                state.filter = state.filter_backup.clone();
                state.selected = state.selected_before_filter;
                state.clamp_selection();
                state.modal = Modal::None;
            }
            Key::Enter => {
                state.clamp_selection();
                state.modal = Modal::None;
            }
            Key::Backspace => {
                state.filter.pop();
                state.selected = 0;
                state.clamp_selection();
            }
            Key::Char('u' | 'U') if mods.ctrl => {
                state.filter.clear();
                state.selected = 0;
                state.clamp_selection();
            }
            Key::Char(ch) if !mods.ctrl && !mods.alt => {
                state.filter.push(ch);
                state.selected = 0;
                state.clamp_selection();
            }
            _ => {}
        }
        return false;
    }

    if let Modal::CommandPalette {
        ref query,
        selected,
    } = state.modal
    {
        let mut q = query.clone();
        let mut sel = selected;
        let items = state.filtered_palette(&q);
        match key {
            Key::Esc => {
                state.modal = Modal::None;
            }
            Key::Up | Key::BackTab => {
                if !items.is_empty() {
                    let cur = sel.min(items.len() - 1);
                    sel = if cur == 0 { items.len() - 1 } else { cur - 1 };
                }
                state.modal = Modal::CommandPalette {
                    query: q,
                    selected: sel,
                };
            }
            Key::Down | Key::Tab => {
                if !items.is_empty() {
                    let cur = sel.min(items.len() - 1);
                    sel = (cur + 1) % items.len();
                }
                state.modal = Modal::CommandPalette {
                    query: q,
                    selected: sel,
                };
            }
            Key::Char('p' | 'P') if mods.ctrl => {
                if !items.is_empty() {
                    let cur = sel.min(items.len() - 1);
                    sel = if cur == 0 { items.len() - 1 } else { cur - 1 };
                }
                state.modal = Modal::CommandPalette {
                    query: q,
                    selected: sel,
                };
            }
            Key::Char('n' | 'N') if mods.ctrl => {
                if !items.is_empty() {
                    let cur = sel.min(items.len() - 1);
                    sel = (cur + 1) % items.len();
                }
                state.modal = Modal::CommandPalette {
                    query: q,
                    selected: sel,
                };
            }
            Key::Backspace => {
                q.pop();
                state.modal = Modal::CommandPalette {
                    query: q,
                    selected: 0,
                };
            }
            Key::Char('u' | 'U') if mods.ctrl => {
                q.clear();
                state.modal = Modal::CommandPalette {
                    query: q,
                    selected: 0,
                };
            }
            Key::Enter => {
                state.modal = Modal::None;
                if !items.is_empty() {
                    let entry = items[sel.min(items.len() - 1)];
                    return run_palette_command(
                        entry.cmd, term, theme, paths, store, vault, session, state, quota_svc,
                        stacked, now_ms,
                    );
                }
            }
            Key::Char(ch) if !mods.ctrl && !mods.alt => {
                q.push(ch);
                state.modal = Modal::CommandPalette {
                    query: q,
                    selected: 0,
                };
            }
            _ => {}
        }
        return false;
    }

    if let Modal::ConfirmSwitch { ref email } = state.modal {
        let target = email.clone();
        match key {
            Key::Esc | Key::Char('n' | 'N' | 'q' | 'Q') => {
                state.modal = Modal::None;
            }
            Key::Char('y' | 'Y' | 'o' | 'O') => {
                state.modal = Modal::None;
                do_launch_isolated_agy(term, paths, store, vault, state, &target, now_ms);
            }
            Key::Left | Key::BackTab | Key::Char('h') => {
                state.modal_button_idx = (state.modal_button_idx + 2) % 3;
            }
            Key::Right | Key::Tab | Key::Char('l') => {
                state.modal_button_idx = (state.modal_button_idx + 1) % 3;
            }
            Key::Enter | Key::Char(' ') => {
                let idx = state.modal_button_idx;
                state.modal = Modal::None;
                match idx {
                    0 => do_launch_isolated_agy(term, paths, store, vault, state, &target, now_ms),
                    1 => do_switch_account(paths, store, vault, session, state, &target, now_ms),
                    _ => {}
                }
            }
            _ => {}
        }
        return false;
    }

    if matches!(
        state.modal,
        Modal::ConfirmDelete { .. } | Modal::AddAccountHint
    ) {
        match key {
            Key::Esc | Key::Char('n' | 'N' | 'q' | 'Q') => {
                state.modal = Modal::None;
            }
            Key::Char('y' | 'Y') => {
                confirm_active_modal(term, paths, store, vault, session, state, quota_svc, now_ms);
            }
            Key::Left | Key::Right | Key::Tab | Key::BackTab | Key::Char('h' | 'l') => {
                state.modal_button_idx = if state.modal_button_idx == 0 { 1 } else { 0 };
            }
            Key::Enter | Key::Char(' ') => {
                if state.modal_button_idx == 0 {
                    confirm_active_modal(
                        term, paths, store, vault, session, state, quota_svc, now_ms,
                    );
                } else {
                    state.modal = Modal::None;
                }
            }
            _ => {}
        }
        return false;
    }

    if state.modal == Modal::ShortcutGuide {
        if matches!(
            key,
            Key::Esc | Key::Enter | Key::Char('?' | 'q' | 'Q' | ' ')
        ) {
            state.modal = Modal::None;
        }
        return false;
    }

    if state.view == ActiveView::FailoverPolicy {
        match key {
            Key::Esc | Key::Char('g' | 'G' | 'f' | 'F') => {
                switch_view(paths, store, vault, session, state, ActiveView::Dashboard);
            }
            Key::Char('q' | 'Q') => return true,
            Key::Char(':') => {
                state.modal = Modal::CommandPalette {
                    query: String::new(),
                    selected: 0,
                };
            }
            Key::Char('?') => state.modal = Modal::ShortcutGuide,
            Key::Up | Key::Char('k') => {
                state.policy_draft.cursor = state.policy_draft.cursor.saturating_sub(1);
            }
            Key::Down | Key::Char('j') => {
                let max = state.policy_draft.known_pools.len().saturating_sub(1);
                state.policy_draft.cursor = (state.policy_draft.cursor + 1).min(max);
            }
            Key::Char(' ') => state.policy_toggle_current(),
            Key::Char('a' | 'A') => state.policy_select_all(),
            Key::Char('c' | 'C') => state.policy_clear_all(),
            Key::Char('m' | 'M') => state.policy_toggle_match(),
            Key::Char('e' | 'E') => state.policy_toggle_enabled(),
            Key::Char('+' | '=') => state.policy_adjust_threshold(5),
            Key::Char('-' | '_') => state.policy_adjust_threshold(-5),
            Key::Char('[') => state.policy_adjust_max_age(-60),
            Key::Char(']') => state.policy_adjust_max_age(60),
            Key::Char('s' | 'S') | Key::Enter => match state.persist_settings(store) {
                Ok(()) => {
                    state.show_toast("Saved pool failover policy", ToastLevel::Success, now_ms)
                }
                Err(e) => state.show_toast(format!("Save failed - {e}"), ToastLevel::Error, now_ms),
            },
            _ => {}
        }
        return false;
    }

    if state.view == ActiveView::Profiles {
        if matches!(key, Key::Char('c' | 'C')) {
            do_quick_create_profile(paths, store, state, now_ms);
            return false;
        }
        if matches!(key, Key::Char('d' | 'D')) {
            do_delete_selected_profile(paths, store, state, now_ms);
            return false;
        }
    } else if state.view == ActiveView::History && matches!(key, Key::Char('c' | 'C')) {
        do_clear_history(paths, state, now_ms);
        return false;
    } else if state.view == ActiveView::Backup && matches!(key, Key::Char('x' | 'X')) {
        do_export_backup_meta(store, vault, state, now_ms);
        return false;
    } else if state.view == ActiveView::Doctor && matches!(key, Key::Char('r' | 'R') | Key::Enter) {
        state.doctor_checks = run_doctor(paths, store, vault, session);
        state.show_toast("Doctor diagnostics updated", ToastLevel::Info, now_ms);
        return false;
    }

    match key {
        Key::Char('q' | 'Q') => return true,
        Key::Esc => {
            if state.view != ActiveView::Dashboard {
                switch_view(paths, store, vault, session, state, ActiveView::Dashboard);
            } else if !state.filter.is_empty() {
                state.filter.clear();
                state.clamp_selection();
            } else {
                return true;
            }
        }
        Key::Down | Key::Char('j') => {
            if state.view == ActiveView::Dashboard {
                state.move_selection(1);
            } else {
                state.detail_scroll = state.detail_scroll.saturating_add(1);
                state.subview_cursor = state.subview_cursor.saturating_add(1);
            }
        }
        Key::Up | Key::Char('k') => {
            if state.view == ActiveView::Dashboard {
                state.move_selection(-1);
            } else {
                state.detail_scroll = state.detail_scroll.saturating_sub(1);
                state.subview_cursor = state.subview_cursor.saturating_sub(1);
            }
        }
        Key::PageDown => {
            if state.view == ActiveView::Dashboard {
                state.move_selection(5);
            } else {
                state.detail_scroll = state.detail_scroll.saturating_add(5);
                state.subview_cursor = state.subview_cursor.saturating_add(5);
            }
        }
        Key::PageUp => {
            if state.view == ActiveView::Dashboard {
                state.move_selection(-5);
            } else {
                state.detail_scroll = state.detail_scroll.saturating_sub(5);
                state.subview_cursor = state.subview_cursor.saturating_sub(5);
            }
        }
        Key::Home => {
            if state.view == ActiveView::Dashboard {
                state.select_boundary(false);
            } else {
                state.detail_scroll = 0;
                state.subview_cursor = 0;
            }
        }
        Key::End => {
            if state.view == ActiveView::Dashboard {
                state.select_boundary(true);
            }
        }
        Key::Char(ch @ '1'..='9') => {
            if state.view == ActiveView::Dashboard {
                state.select_slot((ch as u8 - b'0') as usize);
            }
        }
        Key::Enter => {
            if state.view == ActiveView::Dashboard {
                if let Some(email) = state.selected_email() {
                    state.modal_button_idx = 0;
                    state.modal = Modal::ConfirmSwitch { email };
                }
            }
        }
        Key::Char('n' | 'N') => do_rotate_next(store, state, now_ms),
        Key::Char('r' | 'R') => {
            state.refreshing = true;
            let _ = term.draw(theme.env.ascii, |f| deck::render_deck(f, state, theme));
            do_refresh_all(paths, store, vault, state, quota_svc, true, now_ms);
        }
        Key::Char('u' | 'U') => {
            state.refreshing = true;
            let _ = term.draw(theme.env.ascii, |f| deck::render_deck(f, state, theme));
            do_refresh_selected(paths, store, vault, state, quota_svc, now_ms);
        }
        Key::Char('/') => {
            state.filter_backup = state.filter.clone();
            state.selected_before_filter = state.selected;
            state.modal = Modal::FilterInput;
        }
        Key::Char(':') => {
            state.modal = Modal::CommandPalette {
                query: String::new(),
                selected: 0,
            };
        }
        Key::Char('g' | 'G') => {
            switch_view(paths, store, vault, session, state, ActiveView::Dashboard);
        }
        Key::Char('p' | 'P') => {
            toggle_view(paths, store, vault, session, state, ActiveView::Profiles);
        }
        Key::Char('h' | 'H') => {
            toggle_view(paths, store, vault, session, state, ActiveView::History);
        }
        Key::Char('s' | 'S' | ',') => {
            toggle_view(paths, store, vault, session, state, ActiveView::Settings);
        }
        Key::Char('o') => {
            if state.view == ActiveView::Dashboard {
                if let Some(email) = state.selected_email() {
                    do_launch_isolated_agy(term, paths, store, vault, state, &email, now_ms);
                } else {
                    toggle_view(paths, store, vault, session, state, ActiveView::Doctor);
                }
            } else {
                toggle_view(paths, store, vault, session, state, ActiveView::Doctor);
            }
        }
        Key::Char('O') => {
            toggle_view(paths, store, vault, session, state, ActiveView::Doctor);
        }
        Key::Char('b' | 'B') => {
            toggle_view(paths, store, vault, session, state, ActiveView::Backup);
        }
        Key::Char('v' | 'V') => {
            toggle_view(paths, store, vault, session, state, ActiveView::QuotaPools);
        }
        Key::Char('f' | 'F') => {
            toggle_view(
                paths,
                store,
                vault,
                session,
                state,
                ActiveView::FailoverPolicy,
            );
        }
        Key::Char('a' | 'A') => {
            state.modal_button_idx = 0;
            state.modal = Modal::AddAccountHint;
        }
        Key::Char('i' | 'I') => {
            do_import_current(
                term, theme, paths, store, vault, session, state, quota_svc, now_ms,
            );
        }
        Key::Char('d' | 'D') => {
            if let Some(email) = state.selected_email() {
                state.modal_button_idx = 0;
                state.modal = Modal::ConfirmDelete { email };
            }
        }
        Key::Char('w' | 'W') => do_verify_or_toggle_mode(store, state, now_ms),
        Key::Char('m' | 'M') => do_migrate_vault(paths, store, vault, state, now_ms),
        Key::Char('y' | 'Y') => do_ack_restart(paths, state, now_ms),
        Key::Char('[') => {
            state.adjust_split(-4, stacked);
            let _ = state.persist_settings(store);
        }
        Key::Char(']') => {
            state.adjust_split(4, stacked);
            let _ = state.persist_settings(store);
        }
        Key::Char('=') => {
            state.reset_split(stacked);
            let _ = state.persist_settings(store);
        }
        Key::Char('?') => state.modal = Modal::ShortcutGuide,
        _ => {}
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn handle_mouse_event(
    mouse: MouseEvent,
    term: &mut Terminal,
    theme: &Theme,
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
    state: &mut DeckState,
    quota_svc: &mut Option<QuotaService>,
    now_ms: u64,
) -> (bool, bool) {
    let (w, h) = term.size();
    let bp = Breakpoint::from_width(w);
    let areas = deck::compute_areas(Rect::new(0, 0, w, h), state);
    let hit = term.hits().hit_test(mouse.x, mouse.y);

    match mouse.kind {
        MouseKind::Move => {
            let next_hover = hit.map(|(id, _)| id);
            let changed = state.hover_hit != next_hover;
            state.hover_hit = next_hover;
            let shape = match state.dragging {
                Some(DividerDrag::Vertical) => PointerShape::ColResize,
                Some(DividerDrag::Horizontal) => PointerShape::RowResize,
                None => hit
                    .and_then(|(id, s)| {
                        HitTarget::decode(id)
                            .map(HitTarget::pointer_shape)
                            .or(Some(s))
                    })
                    .unwrap_or(PointerShape::Default),
            };
            let _ = term.set_pointer(shape);
            (false, changed)
        }
        MouseKind::Drag(0) => {
            if let Some(drag) = state.dragging {
                match drag {
                    DividerDrag::Vertical => {
                        let base = if bp == Breakpoint::Wide {
                            ((w as i32) * 38 / 100).clamp(36, 68)
                        } else {
                            ((w as i32) * 44 / 100).clamp(32, 54)
                        };
                        state.split_offset = ((mouse.x as i32) - base).clamp(-36, 36) as i16;
                        let _ = term.set_pointer(PointerShape::ColResize);
                    }
                    DividerDrag::Horizontal => {
                        state.set_stack_from_row(mouse.y, areas.body.y, areas.body.h);
                        let _ = term.set_pointer(PointerShape::RowResize);
                    }
                }
                return (false, true);
            }
            (false, false)
        }
        MouseKind::Up(_) => {
            if state.dragging.take().is_some() {
                let _ = state.persist_settings(store);
                let next_shape = hit.map(|(_, s)| s).unwrap_or(PointerShape::Default);
                let _ = term.set_pointer(next_shape);
                return (false, true);
            }
            (false, false)
        }
        MouseKind::ScrollUp | MouseKind::ScrollDown => {
            let up = mouse.kind == MouseKind::ScrollUp;
            if let Modal::CommandPalette {
                ref query,
                selected,
            } = state.modal
            {
                let q = query.clone();
                let items = state.filtered_palette(&q);
                if !items.is_empty() {
                    let cur = selected.min(items.len() - 1);
                    let next = if up {
                        if cur == 0 {
                            items.len() - 1
                        } else {
                            cur - 1
                        }
                    } else {
                        (cur + 1) % items.len()
                    };
                    state.modal = Modal::CommandPalette {
                        query: q,
                        selected: next,
                    };
                }
                return (false, true);
            }
            if state.modal.is_overlay() {
                return (false, false);
            }
            let decoded = hit.and_then(|(id, _)| HitTarget::decode(id));
            if state.view == ActiveView::FailoverPolicy {
                if up {
                    state.policy_draft.cursor = state.policy_draft.cursor.saturating_sub(1);
                } else {
                    let max = state.policy_draft.known_pools.len().saturating_sub(1);
                    state.policy_draft.cursor = (state.policy_draft.cursor + 1).min(max);
                }
            } else if state.view == ActiveView::Dashboard
                && !matches!(decoded, Some(HitTarget::DetailScrollArea))
            {
                state.move_selection(if up { -1 } else { 1 });
            } else if up {
                state.detail_scroll = state.detail_scroll.saturating_sub(2);
                state.subview_cursor = state.subview_cursor.saturating_sub(1);
            } else {
                state.detail_scroll = state.detail_scroll.saturating_add(2);
                state.subview_cursor = state.subview_cursor.saturating_add(1);
            }
            (false, true)
        }
        MouseKind::Down(0) => {
            let decoded = hit.and_then(|(id, _)| HitTarget::decode(id));
            if state.modal.is_overlay() {
                match decoded {
                    Some(HitTarget::ModalConfirm) => {
                        confirm_active_modal(
                            term, paths, store, vault, session, state, quota_svc, now_ms,
                        );
                    }
                    Some(HitTarget::ModalSecondary) => {
                        let current = core::mem::replace(&mut state.modal, Modal::None);
                        if let Modal::ConfirmSwitch { email } = current {
                            do_switch_account(paths, store, vault, session, state, &email, now_ms);
                        }
                    }
                    Some(HitTarget::ModalCancel) => {
                        state.modal = Modal::None;
                    }
                    Some(HitTarget::PaletteRow(idx)) => {
                        let cmd_opt = if let Modal::CommandPalette { ref query, .. } = state.modal {
                            let q = query.clone();
                            state.filtered_palette(&q).get(idx).map(|e| e.cmd)
                        } else {
                            None
                        };
                        state.modal = Modal::None;
                        if let Some(cmd) = cmd_opt {
                            let quit = run_palette_command(
                                cmd,
                                term,
                                theme,
                                paths,
                                store,
                                vault,
                                session,
                                state,
                                quota_svc,
                                areas.stacked,
                                now_ms,
                            );
                            return (quit, true);
                        }
                    }
                    Some(HitTarget::ModalBox) => {}
                    _ => {
                        state.modal = Modal::None;
                    }
                }
                return (false, true);
            }

            if state.modal == Modal::FilterInput {
                state.modal = Modal::None;
            }

            let Some((hit_id, _)) = hit else {
                state.armed_row_click = None;
                return (false, true);
            };
            let is_double = state
                .last_click
                .map(|prev| {
                    prev.hit == hit_id
                        && prev.x.abs_diff(mouse.x) <= 2
                        && prev.y == mouse.y
                        && now_ms.saturating_sub(prev.at_ms) <= 400
                })
                .unwrap_or(false);
            state.last_click = Some(LastClick {
                hit: hit_id,
                at_ms: now_ms,
                x: mouse.x,
                y: mouse.y,
            });

            match decoded {
                Some(HitTarget::SplitDivider) => {
                    if is_double {
                        state.reset_split(false);
                        let _ = state.persist_settings(store);
                        state.dragging = None;
                        state.last_click = None;
                    } else {
                        state.dragging = Some(DividerDrag::Vertical);
                    }
                }
                Some(HitTarget::StackDivider) => {
                    if is_double {
                        state.reset_split(true);
                        let _ = state.persist_settings(store);
                        state.dragging = None;
                        state.last_click = None;
                    } else {
                        state.dragging = Some(DividerDrag::Horizontal);
                    }
                }
                Some(HitTarget::AccountRow(idx)) => {
                    let vis = state.visible_emails();
                    if idx < vis.len() {
                        if state.selected == idx && state.armed_row_click == Some(idx) {
                            state.armed_row_click = None;
                            state.modal_button_idx = 0;
                            state.modal = Modal::ConfirmSwitch {
                                email: vis[idx].clone(),
                            };
                        } else {
                            state.selected = idx;
                            state.armed_row_click = Some(idx);
                        }
                    }
                }
                Some(HitTarget::SubviewTab(view)) => {
                    state.armed_row_click = None;
                    switch_view(paths, store, vault, session, state, view);
                }
                Some(HitTarget::PolicyPoolRow(idx)) => {
                    state.policy_draft.cursor = idx;
                    state.policy_toggle_at(idx);
                }
                Some(HitTarget::FooterKeycap(act)) => {
                    state.armed_row_click = None;
                    let quit = run_keycap_action(
                        act,
                        term,
                        theme,
                        paths,
                        store,
                        vault,
                        session,
                        state,
                        quota_svc,
                        areas.stacked,
                        now_ms,
                    );
                    return (quit, true);
                }
                _ => {
                    state.armed_row_click = None;
                }
            }
            (false, true)
        }
        _ => (false, false),
    }
}

pub fn run_interactive(paths: Paths) -> i32 {
    let theme = Theme::detect(false);
    let store = Store::new(paths.clone());
    let vault = open_vault(&paths);
    let session = SessionManager::new(paths.clone());
    let _ = init_log_cursors_at_eof(&paths);
    let mut state = DeckState::load(&paths);
    let mut quota_svc: Option<QuotaService> = None;

    let mut term = match Terminal::enter(theme.env.mouse, theme.env.pointer_shapes) {
        Ok(t) => t,
        Err(err) => {
            let msg = format!("agy-swap-rs: failed to initialize terminal UI - {err}\n");
            eko::print::write_fd(2, msg.as_bytes());
            return 1;
        }
    };

    let boot = eko::time::Instant::now();
    if term
        .draw(theme.env.ascii, |frame| {
            deck::render_deck(frame, &state, &theme)
        })
        .is_err()
    {
        return 0;
    }
    let mut dirty = false;
    if harvest_all_overlays(&paths, &store, &vault, &state.accounts) {
        state.reload_from_disk(&paths);
        dirty = true;
    }
    if !is_offline() && needs_initial_quota_refresh(&state) {
        let init_ms = boot.elapsed().as_millis() as u64;
        do_refresh_all(
            &paths,
            &store,
            &vault,
            &mut state,
            &mut quota_svc,
            true,
            init_ms,
        );
        dirty = true;
    }
    let mut last_log_poll_ms: u64 = 0;
    let mut last_due_check_ms: u64 = boot.elapsed().as_millis() as u64;
    let mut last_wall_sec = state.now_unix;

    loop {
        let now_ms = boot.elapsed().as_millis() as u64;
        let wall = agy_core::wall_unix_secs();
        if wall != last_wall_sec {
            state.now_unix = wall;
            if !theme.env.reduced_motion {
                dirty = true;
            }
            last_wall_sec = wall;
        }
        if state.expire_toast(now_ms) {
            dirty = true;
        }

        if now_ms.saturating_sub(last_log_poll_ms) >= 1_000 {
            last_log_poll_ms = now_ms;
            if let Ok(Some(failover)) = poll_logs_once(
                &paths,
                &store,
                &vault,
                &session,
                state.switch_mode,
                false,
                state.now_unix,
            ) {
                state.reload_from_disk(&paths);
                match failover.outcome.as_str() {
                    "switched" => {
                        let dst = failover.switched_to.as_deref().unwrap_or("standby");
                        state.show_toast(
                            format!("LogWatch rotated active session to {dst}"),
                            ToastLevel::Warn,
                            now_ms,
                        );
                    }
                    "switch_required" => {
                        let dst = failover.switched_to.as_deref().unwrap_or("standby");
                        state.show_toast(
                            format!("Quota reached - press n to switch to {dst}"),
                            ToastLevel::Warn,
                            now_ms,
                        );
                    }
                    "no_account" => {
                        state.show_toast(
                            "Quota reached - no healthy standby account available",
                            ToastLevel::Error,
                            now_ms,
                        );
                    }
                    _ => {}
                }
                dirty = true;
            } else {
                let rt = load_runtime_file(&paths);
                if rt != state.runtime {
                    state.runtime = rt;
                    dirty = true;
                }
                let iso = warm_isolated_map(&paths, &state.accounts);
                if iso != state.isolated_running {
                    state.isolated_running = iso;
                    dirty = true;
                }
            }
        }

        if apply_refresh_outcomes(&paths, &store, &vault, &mut state, now_ms) {
            dirty = true;
        }

        if now_ms.saturating_sub(last_due_check_ms) >= 4_000 {
            last_due_check_ms = now_ms;
            if do_refresh_one_due(&paths, &store, &vault, &mut state, &mut quota_svc) {
                dirty = true;
            }
        }

        if dirty {
            if term
                .draw(theme.env.ascii, |frame| {
                    deck::render_deck(frame, &state, &theme)
                })
                .is_err()
            {
                break;
            }
            dirty = false;
        }

        let ev = match term.poll_event(250) {
            Ok(e) => e,
            Err(_) => break,
        };
        let event_ms = boot.elapsed().as_millis() as u64;
        match ev {
            Event::Signal(_) => break,
            Event::Resize(_, _) => {
                state.hover_hit = None;
                dirty = true;
            }
            Event::Key(key, mods) => {
                let (tw, th) = term.size();
                let areas = deck::compute_areas(Rect::new(0, 0, tw, th), &state);
                let should_quit = handle_key_event(
                    key,
                    mods,
                    &mut term,
                    &theme,
                    &paths,
                    &store,
                    &vault,
                    &session,
                    &mut state,
                    &mut quota_svc,
                    areas.stacked,
                    event_ms,
                );
                if should_quit {
                    break;
                }
                dirty = true;
            }
            Event::Mouse(mouse) => {
                let (should_quit, mouse_dirty) = handle_mouse_event(
                    mouse,
                    &mut term,
                    &theme,
                    &paths,
                    &store,
                    &vault,
                    &session,
                    &mut state,
                    &mut quota_svc,
                    event_ms,
                );
                if should_quit {
                    break;
                }
                if mouse_dirty {
                    dirty = true;
                }
            }
            Event::Tick => {}
        }
    }

    0
}
