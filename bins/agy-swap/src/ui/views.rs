use super::alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use super::deck::{collect_display_pools, draw_pool_card, format_age, format_countdown};
use super::state::{ActiveView, DeckState, HitTarget, Modal, Toast, ToastLevel};
use super::theme::Theme;
use agy_core::{
    paths::format_rfc3339_utc,
    policy::{
        evaluate_pool_failover, recommend, DirectoryBinding, PoolMatchMode, PoolState, Profile,
        RankingPolicy, SwitchMode,
    },
};
use agy_tui::{centered_rect, display_width, Frame, PointerShape, Rect, Style};

pub fn render_subview(frame: &mut Frame<'_>, area: Rect, state: &DeckState, theme: &Theme) {
    if area.is_empty() {
        return;
    }
    frame.hit(HitTarget::DetailScrollArea.encode(), area, PointerShape::Default);
    let pad_x: u16 = if area.w >= 48 { 2 } else { 1 };
    let x = area.x.saturating_add(pad_x);
    let w = area.w.saturating_sub(pad_x * 2);
    if w == 0 {
        return;
    }
    let mut y = area.y;
    frame.surface.put_str(x, y, w, state.view.title(), theme.text_bold);
    let back_hint = "[Esc / g] Dashboard";
    let bw = display_width(back_hint) as u16;
    if w > bw + 20 {
        frame.surface.put_str(x + w - bw, y, bw, back_hint, theme.muted);
    }
    y = y.saturating_add(1);
    if y < area.bottom() {
        let hch = if frame.ascii { '-' } else { '\u{2500}' };
        frame.surface.fill(Rect::new(x, y, w, 1), hch, theme.divider);
        y = y.saturating_add(1);
    }
    if y >= area.bottom() {
        return;
    }
    let content = Rect::new(x, y, w, area.bottom().saturating_sub(y));
    match state.view {
        ActiveView::Dashboard => {}
        ActiveView::Profiles => render_profiles_view(frame, content, state, theme),
        ActiveView::History => render_history_view(frame, content, state, theme),
        ActiveView::Settings => render_settings_view(frame, content, state, theme),
        ActiveView::Doctor => render_doctor_view(frame, content, state, theme),
        ActiveView::Backup => render_backup_view(frame, content, state, theme),
        ActiveView::QuotaPools => render_quota_pools_view(frame, content, state, theme),
        ActiveView::FailoverPolicy => render_failover_policy_view(frame, content, state, theme),
    }
}

fn put_scrolled_lines(
    frame: &mut Frame<'_>,
    area: Rect,
    lines: &[(String, Style)],
    scroll: usize,
) {
    if area.is_empty() || lines.is_empty() {
        return;
    }
    let max_vis = area.h as usize;
    let start = scroll.min(lines.len().saturating_sub(max_vis));
    let mut y = area.y;
    for (txt, st) in lines.iter().skip(start).take(max_vis) {
        frame.surface.put_str(area.x, y, area.w, txt, *st);
        y = y.saturating_add(1);
    }
}

fn render_profiles_view(frame: &mut Frame<'_>, area: Rect, state: &DeckState, theme: &Theme) {
    let profiles: BTreeMap<String, Profile> = state
        .settings_json
        .get("profiles")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let mut lines: Vec<(String, Style)> = Vec::new();
    if profiles.is_empty() {
        lines.push((
            "No routing profiles configured yet.".to_string(),
            theme.muted,
        ));
        lines.push((
            "Press [c] to create a profile for the selected account, or run 'agy-swap-rs profile set'."
                .to_string(),
            theme.text,
        ));
    } else {
        let names: Vec<String> = profiles.keys().cloned().collect();
        let cur = state.subview_cursor.min(names.len().saturating_sub(1));
        for (idx, name) in names.iter().enumerate() {
            if let Some(prof) = profiles.get(name) {
                let mark = if idx == cur { ">" } else { " " };
                let fam = prof
                    .family
                    .map(|f| f.as_str())
                    .unwrap_or("any-family");
                let reserves = if prof.reserves.is_empty() {
                    "none".to_string()
                } else {
                    prof.reserves.join(", ")
                };
                let row = format!(
                    "{mark} {name:<16} primary={}  family={fam}  policy={}  min={}%  reserves=[{reserves}]",
                    prof.primary, prof.policy, prof.threshold_pct
                );
                let st = if idx == cur { theme.row_selected } else { theme.text };
                lines.push((row, st));
            }
        }
        if let Some(sel_name) = names.get(cur) {
            if let Some(prof) = profiles.get(sel_name) {
                let rec = recommend(
                    &state.accounts,
                    state.active_email.as_deref(),
                    prof.family,
                    prof.policy,
                    prof.threshold_pct,
                    Some(prof),
                    state.now_unix,
                );
                lines.push((String::new(), theme.body));
                lines.push((
                    format!(
                        "Live recommendation for '{}': {} ({})",
                        sel_name,
                        rec.selected_email.as_deref().unwrap_or("none"),
                        rec.reason
                    ),
                    theme.active_name,
                ));
            }
        }
        lines.push((String::new(), theme.body));
        lines.push((
            "Keys: [j/k] select  [c] quick-create for selected account  [d] delete profile"
                .to_string(),
            theme.muted,
        ));
    }
    put_scrolled_lines(frame, area, &lines, state.detail_scroll);
}

fn render_history_view(frame: &mut Frame<'_>, area: Rect, state: &DeckState, theme: &Theme) {
    let mut lines: Vec<(String, Style)> = Vec::new();
    if state.history_json.is_empty() {
        lines.push(("No local audit history recorded yet.".to_string(), theme.muted));
        lines.push((
            "Switches, automatic failovers, and quota refreshes are logged locally.".to_string(),
            theme.text,
        ));
    } else {
        lines.push((
            format!(
                "Recent events: {}  ([j/k] scroll  [c] clear history)",
                state.history_json.len()
            ),
            theme.muted,
        ));
        for (idx, item) in state.history_json.iter().enumerate() {
            let ts_str = item
                .get("timestamp_unix")
                .and_then(|v| v.as_i64())
                .map(format_rfc3339_utc)
                .or_else(|| item.get("at").and_then(|v| v.as_str()).map(ToString::to_string))
                .unwrap_or_else(|| "-".to_string());
            let kind = item
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("event");
            let email = item
                .get("email")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("system");
            let detail = item
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let row = if detail.is_empty() {
                format!("  {ts_str}  {kind:<14}  {email}")
            } else {
                format!("  {ts_str}  {kind:<14}  {email} - {detail}")
            };
            let st = if idx == state.subview_cursor {
                theme.row_selected
            } else {
                theme.text
            };
            lines.push((row, st));
        }
    }
    put_scrolled_lines(frame, area, &lines, state.detail_scroll);
}

fn render_settings_view(frame: &mut Frame<'_>, area: Rect, state: &DeckState, theme: &Theme) {
    let s = &state.settings_json;
    let def_pol = s
        .get("default_policy")
        .and_then(|v| v.as_str())
        .unwrap_or(RankingPolicy::Sticky.as_str());
    let route_strat = s
        .get("route_strategy")
        .and_then(|v| v.as_str())
        .unwrap_or("same-family-first");
    let min_pct = s
        .get("min_remaining_pct")
        .and_then(|v| v.as_u64())
        .unwrap_or(10);
    let hist_days = s
        .get("history_retention_days")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let aliases: BTreeMap<String, String> = s
        .get("aliases")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let bindings: Vec<DirectoryBinding> = s
        .get("bindings")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let mode_str = match state.switch_mode {
        SwitchMode::Auto => "auto (logwatch rotates active session automatically)",
        SwitchMode::Manual => "manual (logwatch records cooldown without switching)",
    };
    let pol = &state.policy_draft.policy;
    let mut lines: Vec<(String, Style)> = vec![
        ("Routing & Failover".to_string(), theme.text_bold),
        (format!("  Switch mode:        {mode_str}  [press w to toggle]"), theme.text),
        (format!("  Ranking policy:     {def_pol}"), theme.text),
        (format!("  Route strategy:     {route_strat}"), theme.text),
        (format!("  Min remaining:      {min_pct}%"), theme.text),
        (
            format!(
                "  Pool failover:      {} ({} of {} checked <= {}%, max_age={}s)  [press f]",
                if pol.enabled { "ON" } else { "OFF" },
                match pol.match_mode {
                    PoolMatchMode::Any => "ANY",
                    PoolMatchMode::All => "ALL",
                },
                pol.checked_pools.len(),
                pol.threshold_pct,
                pol.max_age_secs
            ),
            theme.text,
        ),
        (String::new(), theme.body),
        ("Layout & Audit".to_string(), theme.text_bold),
        (
            format!(
                "  Pane offsets:       split={:+}  stack={:+}  ([ / ] resize, = reset)",
                state.split_offset, state.stack_offset
            ),
            theme.text,
        ),
        (format!("  History retention:  {hist_days} days"), theme.text),
        (String::new(), theme.body),
        (format!("Aliases ({})", aliases.len()), theme.text_bold),
    ];
    if aliases.is_empty() {
        lines.push(("  (none - set via 'agy-swap-rs alias set <name> <email>')".to_string(), theme.muted));
    } else {
        for (k, v) in &aliases {
            lines.push((format!("  {k:<16} -> {v}"), theme.text));
        }
    }
    lines.push((String::new(), theme.body));
    lines.push((format!("Directory Bindings ({})", bindings.len()), theme.text_bold));
    if bindings.is_empty() {
        lines.push(("  (none - set via 'agy-swap-rs bind set <dir> <profile>')".to_string(), theme.muted));
    } else {
        for b in &bindings {
            lines.push((format!("  {} -> {} ({})", b.path, b.profile, b.mode), theme.text));
        }
    }
    put_scrolled_lines(frame, area, &lines, state.detail_scroll);
}

fn render_doctor_view(frame: &mut Frame<'_>, area: Rect, state: &DeckState, theme: &Theme) {
    let mut lines: Vec<(String, Style)> = Vec::new();
    if state.doctor_checks.is_empty() {
        lines.push(("Press [r] or [Enter] to run installation diagnostics.".to_string(), theme.muted));
    } else {
        let mut all_ok = true;
        for chk in &state.doctor_checks {
            if !chk.ok {
                all_ok = false;
            }
            let icon = if chk.ok {
                if frame.ascii { "[OK]  " } else { "\u{2713} " }
            } else if frame.ascii {
                "[FAIL]"
            } else {
                "\u{2715} "
            };
            let st = if chk.ok { theme.badge_ready } else { theme.badge_critical };
            lines.push((format!("{icon} {:<22} {}", chk.name, chk.detail), st));
        }
        lines.push((String::new(), theme.body));
        if all_ok {
            lines.push((
                "Overall status: HEALTHY  ([r] re-run checks)".to_string(),
                theme.badge_ready,
            ));
        } else {
            lines.push((
                "Overall status: ATTENTION NEEDED  ([r] re-run checks)".to_string(),
                theme.badge_critical,
            ));
        }
    }
    put_scrolled_lines(frame, area, &lines, state.detail_scroll);
}

fn render_backup_view(frame: &mut Frame<'_>, area: Rect, state: &DeckState, theme: &Theme) {
    let lines: Vec<(String, Style)> = vec![
        ("Portable Backup & Crash-Safe Restore".to_string(), theme.text_bold),
        (
            format!("  Default target path: {}", state.backup_path),
            theme.text,
        ),
        (String::new(), theme.body),
        (
            "  [x] Export metadata-only backup now (redacts all OAuth tokens & vault refs)"
                .to_string(),
            theme.active_name,
        ),
        (
            "  [m] Migrate any legacy inline tokens from accounts.json into Vault".to_string(),
            theme.text,
        ),
        (String::new(), theme.body),
        ("Encrypted Vault Bundle Commands (AES-256-GCM + PBKDF2-HMAC-SHA256, 600k iters):".to_string(), theme.text_bold),
        (
            "  agy-swap-rs backup export backup.json --include-secrets --passphrase <8+ chars>"
                .to_string(),
            theme.muted,
        ),
        (
            "  agy-swap-rs backup import backup.json --merge --passphrase <8+ chars>".to_string(),
            theme.muted,
        ),
        (
            "  agy-swap-rs backup verify backup.json --passphrase <8+ chars>".to_string(),
            theme.muted,
        ),
    ];
    put_scrolled_lines(frame, area, &lines, state.detail_scroll);
}

fn render_quota_pools_view(frame: &mut Frame<'_>, area: Rect, state: &DeckState, theme: &Theme) {
    let Some(acc) = state.selected_account() else {
        frame.surface.put_str(
            area.x,
            area.y,
            area.w,
            "No account selected - add an account with [a] first.",
            theme.muted,
        );
        return;
    };
    let mut y = area.y;
    let Some(ref snap) = acc.quota else {
        let msg = format!(
            "Account {} has no cached quota pools yet - press [r] or [u] to fetch.",
            acc.email
        );
        frame.surface.put_str(area.x, y, area.w, &msg, theme.muted);
        return;
    };
    let pools = collect_display_pools(snap);
    let meta = format!(
        "Account: {}  |  Tier: {}  |  Project: {}  |  Pools: {}  |  Cached: {}",
        acc.email,
        snap.plan_tier.as_deref().unwrap_or("-"),
        snap.project_id.as_deref().unwrap_or("-"),
        pools.len(),
        format_age(snap.fetched_at_unix, state.now_unix),
    );
    frame.surface.put_str(area.x, y, area.w, &meta, theme.muted);
    y = y.saturating_add(1);
    if y >= area.bottom() {
        return;
    }

    let rem_h = area.bottom().saturating_sub(y);
    if area.w >= 96 && rem_h >= 6 {
        let half_w = area.w.saturating_sub(1) / 2;
        let mut idx = state.detail_scroll.min(pools.len().saturating_sub(1)) & !1usize;
        while idx < pools.len() && y + 5 <= area.bottom() {
            let card_h = 6.min(area.bottom().saturating_sub(y));
            draw_pool_card(
                frame,
                Rect::new(area.x, y, half_w, card_h),
                pools[idx],
                state.now_unix,
                theme,
            );
            if idx + 1 < pools.len() {
                let rx = area.x + half_w + 1;
                let rw = area.right().saturating_sub(rx);
                draw_pool_card(
                    frame,
                    Rect::new(rx, y, rw, card_h),
                    pools[idx + 1],
                    state.now_unix,
                    theme,
                );
            }
            y = y.saturating_add(card_h);
            idx += 2;
        }
    } else {
        let start = state.detail_scroll.min(pools.len().saturating_sub(1));
        for p in pools.iter().skip(start) {
            if y >= area.bottom() {
                break;
            }
            let rem = area.bottom().saturating_sub(y);
            if rem >= 5 && area.w >= 26 {
                let h = 5.min(rem);
                draw_pool_card(frame, Rect::new(area.x, y, area.w, h), *p, state.now_unix, theme);
                y = y.saturating_add(h);
            } else {
                let eff = p.quota.effective_pct().map(|v| format!("{v:.1}%")).unwrap_or_else(|| "n/a".to_string());
                let cd = format_countdown(p.quota.next_reset_unix(), state.now_unix);
                let line = format!("{:<18}  remaining: {:>6}  resets: {cd}", p.label, eff);
                frame.surface.put_str(area.x, y, area.w, &line, theme.text);
                y = y.saturating_add(1);
            }
        }
    }
}

fn render_failover_policy_view(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &DeckState,
    theme: &Theme,
) {
    if area.is_empty() {
        return;
    }
    let pol = &state.policy_draft.policy;
    let match_str = match pol.match_mode {
        PoolMatchMode::Any => "ANY checked pool exhausted",
        PoolMatchMode::All => "ALL checked pools exhausted",
    };
    let dirty_tag = if state.policy_draft.dirty {
        "  * UNSAVED (press S to save)"
    } else {
        "  (saved)"
    };
    let mut y = area.y;
    let l1 = format!(
        "[E] Enabled: {:<3}  |  [M] Trigger: {match_str}{dirty_tag}",
        if pol.enabled { "ON" } else { "OFF" }
    );
    frame.surface.put_str(
        area.x,
        y,
        area.w,
        &l1,
        if state.policy_draft.dirty { theme.badge_low } else { theme.text_bold },
    );
    y = y.saturating_add(1);
    if y >= area.bottom() {
        return;
    }
    let l2 = format!(
        "[+/-] Remaining threshold: <= {}%  |  [[ / ]] Cache max age: {}s  |  [A] All  [C] Clear",
        pol.threshold_pct, pol.max_age_secs
    );
    frame.surface.put_str(area.x, y, area.w, &l2, theme.muted);
    y = y.saturating_add(1);
    if y >= area.bottom() {
        return;
    }

    let eval_opt = state
        .selected_account()
        .map(|acc| evaluate_pool_failover(acc, pol, state.now_unix));
    if let Some(ref ev) = eval_opt {
        let sel_em = state.selected_email().unwrap_or_default();
        let trig = if ev.failover_triggered { "TRIGGERED" } else { "OK" };
        let repl = if ev.replacement_usable { "usable" } else { "not proven usable" };
        let l3 = format!(
            "Preview on {sel_em}: failover={trig}, standby={repl}, cache_fresh={}",
            ev.snapshot_fresh
        );
        let st = if ev.failover_triggered {
            theme.badge_critical
        } else {
            theme.active_name
        };
        frame.surface.put_str(area.x, y, area.w, &l3, st);
        y = y.saturating_add(1);
    }
    if y < area.bottom() {
        y = y.saturating_add(1);
    }
    let list_bottom = area.bottom().saturating_sub(1);
    let cap = list_bottom.saturating_sub(y) as usize;
    let pools = &state.policy_draft.known_pools;
    if cap > 0 && !pools.is_empty() {
        let cur = state.policy_draft.cursor.min(pools.len().saturating_sub(1));
        let start = if cur >= cap { cur + 1 - cap } else { 0 };
        for (idx, name) in pools.iter().enumerate().skip(start).take(cap) {
            let checked = state.is_pool_checked(name);
            let is_sel = idx == cur;
            let hit_id = HitTarget::PolicyPoolRow(idx).encode();
            let is_hov = !is_sel && state.hover_hit == Some(hit_id);
            let row_rect = Rect::new(area.x, y, area.w, 1);
            let base_st = if is_sel {
                theme.row_selected
            } else if is_hov {
                theme.row_hover
            } else {
                theme.text
            };
            frame.surface.fill(row_rect, ' ', base_st);
            frame.hit(hit_id, row_rect, PointerShape::Pointer);
            let state_note = eval_opt
                .as_ref()
                .and_then(|ev| {
                    ev.pools
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, s)| match s {
                            PoolState::Available => " - available",
                            PoolState::Exhausted => " - EXHAUSTED",
                            PoolState::Unknown => " - unknown/stale",
                        })
                })
                .unwrap_or("");
            let row_txt = format!(
                "{} [{}] {}{}",
                if is_sel { ">" } else { " " },
                if checked { "x" } else { " " },
                name,
                state_note
            );
            frame.surface.put_str(area.x, y, area.w, &row_txt, base_st);
            y = y.saturating_add(1);
        }
    }
    if list_bottom < area.bottom() {
        frame.surface.put_str(
            area.x,
            list_bottom,
            area.w,
            "Space toggle | A select all | C clear | M ANY/ALL | +/- threshold | S save | Esc cancel",
            theme.muted,
        );
    }
}

pub fn render_overlays(frame: &mut Frame<'_>, state: &DeckState, theme: &Theme) {
    if state.modal.is_overlay() {
        dim_backdrop(frame, theme);
        match state.modal {
            Modal::None | Modal::FilterInput => {}
            Modal::CommandPalette { ref query, selected } => {
                render_command_palette(frame, query, selected, state, theme);
            }
            Modal::ConfirmSwitch { ref email } => {
                render_account_action_dialog(frame, state, theme, email);
            }
            Modal::ConfirmDelete { ref email } => {
                let body = [
                    format!("Remove {email} from agy-swap-rs?"),
                    "Its saved vault secret and local quota cache will be deleted.".to_string(),
                ];
                render_confirm_dialog(
                    frame,
                    state,
                    theme,
                    "Remove Saved Account",
                    &body,
                    "Delete",
                    true,
                );
            }
            Modal::AddAccountHint => {
                let body = [
                    "Open Google Account Chooser login to add an account?".to_string(),
                    "Active ~/.gemini session stays untouched; quota syncs automatically.".to_string(),
                ];
                render_confirm_dialog(
                    frame,
                    state,
                    theme,
                    "Add Google Account",
                    &body,
                    "Launch Login",
                    false,
                );
            }
            Modal::ShortcutGuide => {
                render_shortcut_guide(frame, state, theme);
            }
        }
    }
    if let Some(ref toast) = state.toast {
        render_toast(frame, toast, theme);
    }
}

fn dim_backdrop(frame: &mut Frame<'_>, theme: &Theme) {
    let w = frame.surface.width();
    let h = frame.surface.height();
    let mut y = 0u16;
    while y < h {
        let mut x = 0u16;
        while x < w {
            if let Some(&cell) = frame.surface.get(x, y) {
                if !cell.continuation {
                    frame.surface.set_char(x, y, cell.ch, theme.backdrop);
                }
            }
            x += 1;
        }
        y += 1;
    }
}

fn render_command_palette(
    frame: &mut Frame<'_>,
    query: &str,
    selected: usize,
    state: &DeckState,
    theme: &Theme,
) {
    let area = frame.size();
    let box_w = area.w.saturating_sub(4).clamp(24, 74);
    let box_h = area.h.saturating_sub(2).clamp(8, 22);
    let rect = centered_rect(area, box_w, box_h);
    if rect.w < 12 || rect.h < 5 {
        return;
    }
    frame.surface.draw_box(rect, theme.borders(), theme.modal_border, Some(theme.modal_bg));
    frame.hit(HitTarget::ModalBox.encode(), rect, PointerShape::Default);
    let inner = rect.inner(2, 1);
    if inner.is_empty() {
        return;
    }
    let mut y = inner.y;
    frame.surface.put_str(inner.x, y, inner.w, "COMMAND PALETTE", theme.modal_title);
    y = y.saturating_add(1);
    if y < inner.bottom() {
        let prompt = format!(": {query}_");
        frame.surface.put_str(inner.x, y, inner.w, &prompt, theme.banner_info);
        y = y.saturating_add(1);
    }
    if y < inner.bottom() {
        let hch = if frame.ascii { '-' } else { '\u{2500}' };
        frame.surface.fill(Rect::new(inner.x, y, inner.w, 1), hch, theme.divider);
        y = y.saturating_add(1);
    }
    let items = state.filtered_palette(query);
    let list_bottom = inner.bottom().saturating_sub(1);
    let cap = list_bottom.saturating_sub(y) as usize;
    if items.is_empty() && y < list_bottom {
        frame.surface.put_str(inner.x, y, inner.w, "No matching commands", theme.muted);
    } else if cap > 0 && !items.is_empty() {
        let sel = selected.min(items.len() - 1);
        let start = if sel >= cap { sel + 1 - cap } else { 0 };
        for (idx, entry) in items.iter().enumerate().skip(start).take(cap) {
            let hit_id = HitTarget::PaletteRow(idx).encode();
            let is_sel = idx == sel;
            let is_hov = !is_sel && state.hover_hit == Some(hit_id);
            let row_rect = Rect::new(inner.x, y, inner.w, 1);
            let st = if is_sel {
                theme.row_selected
            } else if is_hov {
                theme.row_hover
            } else {
                theme.modal_bg
            };
            frame.surface.fill(row_rect, ' ', st);
            frame.hit(hit_id, row_rect, PointerShape::Pointer);
            let key_badge = format!("[{}]", entry.shortcut);
            let kw = display_width(&key_badge) as u16;
            let prefix = if is_sel { "> " } else { "  " };
            let line = if inner.w >= 52 {
                format!("{prefix}{:<26} {}", entry.label, entry.description)
            } else {
                format!("{prefix}{}", entry.label)
            };
            let max_l = inner.w.saturating_sub(kw + 1);
            frame.surface.put_str(inner.x, y, max_l, &line, st);
            if kw < inner.w {
                frame.surface.put_str(inner.right() - kw, y, kw, &key_badge, st);
            }
            y = y.saturating_add(1);
        }
    }
    if list_bottom < inner.bottom() {
        frame.surface.put_str(
            inner.x,
            list_bottom,
            inner.w,
            "Up/Down select - Enter run - Esc close",
            theme.btn_idle,
        );
    }
}

fn render_confirm_dialog(
    frame: &mut Frame<'_>,
    state: &DeckState,
    theme: &Theme,
    title: &str,
    body: &[String],
    confirm_label: &str,
    danger: bool,
) {
    let area = frame.size();
    let box_w = area.w.saturating_sub(4).clamp(24, 62);
    let box_h = ((body.len() as u16) + 6).min(area.h.saturating_sub(2)).max(6);
    let rect = centered_rect(area, box_w, box_h);
    if rect.w < 12 || rect.h < 5 {
        return;
    }
    frame.surface.draw_box(rect, theme.borders(), theme.modal_border, Some(theme.modal_bg));
    frame.hit(HitTarget::ModalBox.encode(), rect, PointerShape::Default);
    let inner = rect.inner(2, 1);
    if inner.is_empty() {
        return;
    }
    let mut y = inner.y;
    frame.surface.put_str(inner.x, y, inner.w, title, theme.modal_title);
    y = y.saturating_add(2);
    for (idx, line) in body.iter().enumerate() {
        if y >= inner.bottom().saturating_sub(1) {
            break;
        }
        let st = if idx == 0 { theme.modal_bg } else { theme.btn_idle };
        frame.surface.put_str(inner.x, y, inner.w, line, st);
        y = y.saturating_add(1);
    }
    let btn_y = inner.bottom().saturating_sub(1);
    let c_hit = HitTarget::ModalConfirm.encode();
    let x_hit = HitTarget::ModalCancel.encode();
    let c_sel = state.modal_button_idx == 0 || state.hover_hit == Some(c_hit);
    let x_sel = state.modal_button_idx == 1 || state.hover_hit == Some(x_hit);
    let c_txt = if state.modal_button_idx == 0 {
        format!("[ {confirm_label} (y) ]")
    } else {
        format!("  {confirm_label} (y)  ")
    };
    let x_txt = if state.modal_button_idx == 1 {
        "[ Cancel (n) ]".to_string()
    } else {
        "  Cancel (n)  ".to_string()
    };
    let c_st = if c_sel {
        if danger { theme.btn_danger } else { theme.btn_confirm }
    } else {
        theme.btn_idle
    };
    let x_st = if x_sel { theme.btn_confirm } else { theme.btn_idle };
    let cw = display_width(&c_txt) as u16;
    let xw = display_width(&x_txt) as u16;
    let mut bx = inner.x;
    if bx + cw <= inner.right() {
        frame.surface.put_str(bx, btn_y, cw, &c_txt, c_st);
        frame.hit(c_hit, Rect::new(bx, btn_y, cw, 1), PointerShape::Pointer);
        bx = bx.saturating_add(cw + 2);
    }
    if bx + xw <= inner.right() {
        frame.surface.put_str(bx, btn_y, xw, &x_txt, x_st);
        frame.hit(x_hit, Rect::new(bx, btn_y, xw, 1), PointerShape::Pointer);
    }
}

fn render_account_action_dialog(
    frame: &mut Frame<'_>,
    state: &DeckState,
    theme: &Theme,
    email: &str,
) {
    let area = frame.size();
    let box_w = area.w.saturating_sub(4).clamp(26, 68);
    let box_h = 8.min(area.h.saturating_sub(2)).max(6);
    let rect = centered_rect(area, box_w, box_h);
    if rect.w < 14 || rect.h < 5 {
        return;
    }
    frame.surface.draw_box(rect, theme.borders(), theme.modal_border, Some(theme.modal_bg));
    frame.hit(HitTarget::ModalBox.encode(), rect, PointerShape::Default);
    let inner = rect.inner(2, 1);
    if inner.is_empty() {
        return;
    }
    let mut y = inner.y;
    frame.surface.put_str(inner.x, y, inner.w, "Account Session Action", theme.modal_title);
    y = y.saturating_add(1);
    if y < inner.bottom().saturating_sub(1) {
        let l1 = format!("Selected account: {email}");
        frame.surface.put_str(inner.x, y, inner.w, &l1, theme.modal_bg);
        y = y.saturating_add(1);
    }
    if y < inner.bottom().saturating_sub(1) {
        let l2 = "Launch isolated agy (--use-account) or swap ~/.gemini IDE (restart IDE):";
        frame.surface.put_str(inner.x, y, inner.w, l2, theme.btn_idle);
    }
    let btn_y = inner.bottom().saturating_sub(1);
    let compact_btns = inner.w < 42;
    let specs = [
        (
            0usize,
            HitTarget::ModalConfirm.encode(),
            if compact_btns { "[Launch]" } else { "[ Launch agy ]" },
        ),
        (
            1usize,
            HitTarget::ModalSecondary.encode(),
            if compact_btns { "[IDE]" } else { "[ Switch IDE ]" },
        ),
        (
            2usize,
            HitTarget::ModalCancel.encode(),
            if compact_btns { "[Esc]" } else { "[ Cancel ]" },
        ),
    ];
    let mut bx = inner.x;
    let gap: u16 = if compact_btns { 1 } else { 2 };
    for (idx, hit_id, lbl) in specs {
        let active = state.modal_button_idx == idx || state.hover_hit == Some(hit_id);
        let st = if active { theme.btn_confirm } else { theme.btn_idle };
        let lw = display_width(lbl) as u16;
        if bx.saturating_add(lw) <= inner.right() {
            frame.surface.put_str(bx, btn_y, lw, lbl, st);
            frame.hit(hit_id, Rect::new(bx, btn_y, lw, 1), PointerShape::Pointer);
            bx = bx.saturating_add(lw + gap);
        }
    }
}

fn render_shortcut_guide(frame: &mut Frame<'_>, state: &DeckState, theme: &Theme) {
    const GUIDE: &[(&str, &str)] = &[
        ("j / k / Up / Down", "Select account or scroll subview"),
        ("1 - 9", "Jump directly to visible account slot"),
        ("Enter / o", "Account action dialog / Launch isolated agy"),
        ("n", "Select next healthy standby account"),
        ("r / u", "Refresh all due accounts / selected account"),
        ("/", "Live filter accounts by email, name, alias, or tag"),
        ("Ctrl+K / :", "Open searchable command palette (incl. Switch IDE)"),
        ("v / f", "Quota Pools inspector / Pool Failover Policy"),
        ("p / h / s / O / b", "Profiles, History, Settings, Doctor, Backup"),
        ("a / i / d / m", "Add login, Import ~/.gemini, Delete, Migrate vault"),
        ("w / y", "Verification link or switch mode / Ack restart"),
        ("[ / ] / =", "Resize split divider or reset to default"),
        ("Mouse", "Click select, 2nd click action dialog, drag divider, wheel"),
        ("? / Esc / q", "Toggle guide / Return to deck / Quit"),
    ];
    let area = frame.size();
    let box_w = area.w.saturating_sub(4).clamp(26, 72);
    let box_h = ((GUIDE.len() as u16) + 5).min(area.h.saturating_sub(2)).max(7);
    let rect = centered_rect(area, box_w, box_h);
    if rect.w < 14 || rect.h < 5 {
        return;
    }
    frame.surface.draw_box(rect, theme.borders(), theme.modal_border, Some(theme.modal_bg));
    frame.hit(HitTarget::ModalBox.encode(), rect, PointerShape::Default);
    let inner = rect.inner(2, 1);
    if inner.is_empty() {
        return;
    }
    let mut y = inner.y;
    frame.surface.put_str(inner.x, y, inner.w, "OPERATOR SHORTCUT GUIDE", theme.modal_title);
    y = y.saturating_add(1);
    let close_y = inner.bottom().saturating_sub(1);
    for &(keys, desc) in GUIDE {
        if y >= close_y {
            break;
        }
        let line = format!("{keys:<19} {desc}");
        frame.surface.put_str(inner.x, y, inner.w, &line, theme.modal_bg);
        y = y.saturating_add(1);
    }
    let hit_id = HitTarget::ModalCancel.encode();
    let close_lbl = "[ Close (Esc) ]";
    let cw = display_width(close_lbl) as u16;
    let st = if state.hover_hit == Some(hit_id) {
        theme.keycap_active
    } else {
        theme.btn_confirm
    };
    if cw <= inner.w {
        frame.surface.put_str(inner.x, close_y, cw, close_lbl, st);
        frame.hit(hit_id, Rect::new(inner.x, close_y, cw, 1), PointerShape::Pointer);
    }
}

fn render_toast(frame: &mut Frame<'_>, toast: &Toast, theme: &Theme) {
    let area = frame.size();
    if area.w < 20 || area.h < 6 {
        return;
    }
    let border = match toast.level {
        ToastLevel::Success => Style {
            fg: theme.badge_ready.fg,
            bg: theme.modal_bg.bg,
            attrs: theme.modal_border.attrs,
        },
        ToastLevel::Warn => Style {
            fg: theme.badge_low.fg,
            bg: theme.modal_bg.bg,
            attrs: theme.modal_border.attrs,
        },
        ToastLevel::Error => Style {
            fg: theme.badge_critical.fg,
            bg: theme.modal_bg.bg,
            attrs: theme.modal_border.attrs,
        },
        ToastLevel::Info => theme.modal_border,
    };
    let box_w = ((display_width(&toast.message) as u16) + 4)
        .clamp(18, area.w.saturating_sub(4));
    let x = area.right().saturating_sub(box_w + 1);
    let y = area.bottom().saturating_sub(5);
    let rect = Rect::new(x, y, box_w, 3);
    frame.surface.draw_box(rect, theme.borders(), border, Some(theme.modal_bg));
    frame.surface.put_str(rect.x + 2, rect.y + 1, rect.w.saturating_sub(4), &toast.message, border);
}
