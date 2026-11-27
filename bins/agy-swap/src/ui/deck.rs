use super::alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use super::state::{
    ActiveView, DeckState, DividerDrag, HitTarget, KeycapAction, Modal, ToastLevel,
};
use super::theme::{PoolTone, Theme};
use super::views;
use agy_core::{
    policy::{PoolMatchMode, SwitchMode},
    Account, Badge, PoolQuota, PoolWindow, QuotaSnapshot,
};
use agy_tui::{display_width, Breakpoint, Frame, PointerShape, Rect, Style};

#[derive(Clone, Copy)]
pub(crate) struct DisplayPool<'a> {
    pub label: &'a str,
    pub short: &'static str,
    pub tone: PoolTone,
    pub quota: &'a PoolQuota,
}

#[derive(Clone, Copy)]
pub(crate) struct DeckAreas {
    pub body: Rect,
    pub list: Rect,
    pub detail: Rect,
    pub stacked: bool,
}

pub(crate) fn collect_display_pools(snap: &QuotaSnapshot) -> Vec<DisplayPool<'_>> {
    let gem_label = if snap.gemini.name.trim().is_empty() {
        "Gemini"
    } else {
        snap.gemini.name.as_str()
    };
    let cg_label = if snap.claude_gpt.name.trim().is_empty() {
        "Claude/GPT"
    } else {
        snap.claude_gpt.name.as_str()
    };
    let mut out = vec![
        DisplayPool {
            label: gem_label,
            short: "Gem",
            tone: PoolTone::Gemini,
            quota: &snap.gemini,
        },
        DisplayPool {
            label: cg_label,
            short: "C/G",
            tone: PoolTone::ClaudeGpt,
            quota: &snap.claude_gpt,
        },
    ];
    if let Some(ref argon) = snap.argon {
        let arg_label = if argon.name.trim().is_empty() {
            "Gemini 4 Argon"
        } else {
            argon.name.as_str()
        };
        out.push(DisplayPool {
            label: arg_label,
            short: "Argon",
            tone: PoolTone::Argon,
            quota: argon,
        });
    }
    for extra in &snap.extra_pools {
        let lbl = if extra.name.trim().is_empty() {
            "Extra Pool"
        } else {
            extra.name.as_str()
        };
        out.push(DisplayPool {
            label: lbl,
            short: "Pool",
            tone: PoolTone::Extra,
            quota: extra,
        });
    }
    out
}

pub(crate) fn format_countdown(reset_at_unix: Option<i64>, now_unix: i64) -> String {
    let Some(at) = reset_at_unix else {
        return "-".to_string();
    };
    let diff = at - now_unix;
    if diff <= 0 {
        return "due".to_string();
    }
    let mins = diff / 60;
    let days = mins / (24 * 60);
    let hours = (mins % (24 * 60)) / 60;
    let rem_m = mins % 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {rem_m}m")
    } else {
        format!("{rem_m}m")
    }
}

pub(crate) fn format_age(fetched_at_unix: i64, now_unix: i64) -> String {
    if fetched_at_unix <= 0 {
        return "never".to_string();
    }
    let age = (now_unix - fetched_at_unix).max(0);
    if age < 60 {
        format!("{age}s ago")
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else {
        format!("{}h {}m ago", age / 3600, (age % 3600) / 60)
    }
}

pub(crate) fn compute_areas(area: Rect, state: &DeckState) -> DeckAreas {
    let bp = Breakpoint::from_width(area.w);
    let tall_header = !matches!(bp, Breakpoint::Compact) && area.h >= 16;
    let mut y = area.y;
    let header_h: u16 = if tall_header { 2 } else { 1 };
    y = y.saturating_add(header_h);
    if state.runtime.restart_agy_needed && area.h >= 10 {
        y = y.saturating_add(1);
    }
    let bottom_chrome: u16 = if area.h >= 6 { 2 } else { 1 };
    let body_bottom = area.bottom().saturating_sub(bottom_chrome);
    let body_h = body_bottom.saturating_sub(y);
    let body = Rect::new(area.x, y, area.w, body_h);
    if state.view != ActiveView::Dashboard || state.accounts.is_empty() {
        return DeckAreas {
            body,
            list: Rect::new(0, 0, 0, 0),
            detail: body,
            stacked: false,
        };
    }
    match bp {
        Breakpoint::Wide => {
            let base = ((body.w as i32) * 38 / 100).clamp(36, 68);
            let max_left = ((body.w as i32) - 46).max(30);
            let left_w = (base + state.split_offset as i32).clamp(30, max_left) as u16;
            let right_x = body.x.saturating_add(left_w).saturating_add(1);
            let right_w = body.right().saturating_sub(right_x);
            DeckAreas {
                body,
                list: Rect::new(body.x, body.y, left_w, body.h),
                detail: Rect::new(right_x, body.y, right_w, body.h),
                stacked: false,
            }
        }
        Breakpoint::Medium => {
            let base = ((body.w as i32) * 44 / 100).clamp(32, 54);
            let max_left = ((body.w as i32) - 34).max(28);
            let left_w = (base + state.split_offset as i32).clamp(28, max_left) as u16;
            let right_x = body.x.saturating_add(left_w).saturating_add(1);
            let right_w = body.right().saturating_sub(right_x);
            DeckAreas {
                body,
                list: Rect::new(body.x, body.y, left_w, body.h),
                detail: Rect::new(right_x, body.y, right_w, body.h),
                stacked: false,
            }
        }
        Breakpoint::Stacked | Breakpoint::Compact => {
            if body.h < 5 {
                return DeckAreas {
                    body,
                    list: body,
                    detail: Rect::new(0, 0, 0, 0),
                    stacked: true,
                };
            }
            let base_h = ((body.h as i32) * 45 / 100).max(2);
            let max_list = ((body.h as i32) - 4).max(2);
            let list_h = (base_h + state.stack_offset as i32).clamp(2, max_list) as u16;
            let detail_y = body.y.saturating_add(list_h).saturating_add(1);
            let detail_h = body.bottom().saturating_sub(detail_y);
            DeckAreas {
                body,
                list: Rect::new(body.x, body.y, body.w, list_h),
                detail: Rect::new(body.x, detail_y, body.w, detail_h),
                stacked: true,
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailMode {
    SideBySide,
    StackedCards,
    Compact,
}

pub fn render_deck(frame: &mut Frame<'_>, state: &DeckState, theme: &Theme) {
    let area = frame.size();
    frame.surface.clear(theme.body);
    frame.hits.clear();
    if area.is_empty() {
        return;
    }
    let bp = Breakpoint::from_width(area.w);
    let tall_header = !matches!(bp, Breakpoint::Compact) && area.h >= 16;
    let mut cur_y = area.y;
    render_header_top(frame, Rect::new(area.x, cur_y, area.w, 1), state, theme);
    cur_y = cur_y.saturating_add(1);
    if tall_header {
        render_header_active(frame, Rect::new(area.x, cur_y, area.w, 1), state, theme);
        cur_y = cur_y.saturating_add(1);
    }
    if state.runtime.restart_agy_needed && area.h >= 10 {
        render_restart_banner(frame, Rect::new(area.x, cur_y, area.w, 1), state, theme);
    }

    let areas = compute_areas(area, state);
    if !areas.body.is_empty() {
        if state.view != ActiveView::Dashboard {
            views::render_subview(frame, areas.body, state, theme);
        } else if state.accounts.is_empty() {
            render_empty_deck(frame, areas.body, theme);
        } else {
            render_dashboard_body(frame, areas, bp, state, theme);
        }
    }

    if area.h >= 6 {
        let status_y = area.bottom().saturating_sub(2);
        render_status_bar(frame, Rect::new(area.x, status_y, area.w, 1), state, theme);
    }
    if area.h >= 3 {
        let footer_y = area.bottom().saturating_sub(1);
        render_footer_bar(
            frame,
            Rect::new(area.x, footer_y, area.w, 1),
            bp,
            state,
            theme,
        );
    }

    views::render_overlays(frame, state, theme);
}

fn render_header_top(frame: &mut Frame<'_>, row: Rect, state: &DeckState, theme: &Theme) {
    frame.surface.fill(row, ' ', theme.header_bar);
    let mut x = row.x.saturating_add(1);
    let brand = if row.w < 46 {
        "AGY-SWAP-RS".to_string()
    } else {
        format!("AGY-SWAP-RS v{}", agy_core::VERSION)
    };
    x = x.saturating_add(frame.surface.put_str(
        x,
        row.y,
        row.right().saturating_sub(x),
        &brand,
        theme.title,
    ));

    let mode_tag = if state.refreshing {
        " [SYNC] "
    } else {
        match state.switch_mode {
            SwitchMode::Auto => " [AUTO] ",
            SwitchMode::Manual => " [MANUAL] ",
        }
    };
    let right_w = display_width(mode_tag) as u16;
    let right_limit = if row.w > right_w.saturating_add(14) {
        let rx = row.right().saturating_sub(right_w).saturating_sub(1);
        let m_style = if state.refreshing {
            theme.banner_info
        } else if state.switch_mode == SwitchMode::Auto {
            theme.banner_success
        } else {
            theme.subtitle
        };
        frame.surface.put_str(rx, row.y, right_w, mode_tag, m_style);
        rx
    } else {
        row.right()
    };

    x = x.saturating_add(2);
    for view in ActiveView::ALL {
        let lbl = view.tab_label();
        let chip = format!(" {lbl} ");
        let w = display_width(&chip) as u16;
        if x.saturating_add(w) >= right_limit {
            break;
        }
        let hit_id = HitTarget::SubviewTab(view).encode();
        let is_active = state.view == view;
        let is_hov = state.hover_hit == Some(hit_id);
        let st = if is_active {
            theme.tab_active
        } else if is_hov {
            theme.keycap_active
        } else {
            theme.tab_inactive
        };
        frame.surface.put_str(x, row.y, w, &chip, st);
        frame.hit(hit_id, Rect::new(x, row.y, w, 1), PointerShape::Pointer);
        x = x.saturating_add(w).saturating_add(1);
    }
}

fn render_header_active(frame: &mut Frame<'_>, row: Rect, state: &DeckState, theme: &Theme) {
    frame.surface.fill(row, ' ', theme.header_bar);
    let dot = if frame.ascii { "*" } else { "\u{25cf}" };
    let mut x = row.x.saturating_add(1);
    let active_txt = match state.active_email.as_deref() {
        Some(email) => format!("{dot} Active: {email}"),
        None => "o Active: none (press Enter on an account)".to_string(),
    };
    let act_style = if state.active_email.is_some() {
        Style {
            fg: theme.active_name.fg,
            bg: theme.header_bar.bg,
            attrs: theme.active_name.attrs,
        }
    } else {
        theme.subtitle
    };
    x = x.saturating_add(frame.surface.put_str(
        x,
        row.y,
        row.right().saturating_sub(x),
        &active_txt,
        act_style,
    ));
    let pol = &state.policy_draft.policy;
    let match_lbl = match pol.match_mode {
        PoolMatchMode::Any => "ANY",
        PoolMatchMode::All => "ALL",
    };
    let pol_summary = if pol.enabled {
        format!(
            "  |  Failover: ON ({match_lbl} of {} <= {}%)",
            pol.checked_pools.len(),
            pol.threshold_pct
        )
    } else {
        "  |  Failover: OFF (press f)".to_string()
    };
    if x.saturating_add(8) < row.right() {
        frame.surface.put_str(
            x,
            row.y,
            row.right().saturating_sub(x).saturating_sub(1),
            &pol_summary,
            theme.subtitle,
        );
    }
}

fn render_restart_banner(frame: &mut Frame<'_>, row: Rect, state: &DeckState, theme: &Theme) {
    frame.surface.fill(row, ' ', theme.banner_warn);
    let msg = " ! LogWatch: restart agy to apply rotated credentials ";
    let used = frame
        .surface
        .put_str(row.x, row.y, row.w, msg, theme.banner_warn);
    let btn = "[Y] Ack restart";
    let bw = display_width(btn) as u16;
    let bx = row.x.saturating_add(used).saturating_add(1);
    if bx.saturating_add(bw) <= row.right() {
        let hit_id = HitTarget::FooterKeycap(KeycapAction::AckRestart).encode();
        let st = if state.hover_hit == Some(hit_id) {
            theme.keycap_active
        } else {
            theme.keycap
        };
        frame.surface.put_str(bx, row.y, bw, btn, st);
        frame.hit(hit_id, Rect::new(bx, row.y, bw, 1), PointerShape::Pointer);
    }
}

fn render_empty_deck(frame: &mut Frame<'_>, area: Rect, theme: &Theme) {
    let box_w = area.w.saturating_sub(2).clamp(1, 68);
    let box_h = area.h.clamp(1, 7);
    let rect = agy_tui::centered_rect(area, box_w, box_h);
    if rect.w >= 6 && rect.h >= 3 {
        frame.surface.draw_box(
            rect,
            theme.borders(),
            theme.panel_border,
            Some(theme.panel_bg),
        );
        let inner = rect.inner(2, 1);
        if !inner.is_empty() {
            frame.surface.put_str(
                inner.x,
                inner.y,
                inner.w,
                "No Google accounts saved yet",
                theme.text_bold,
            );
            if inner.h >= 2 {
                frame.surface.put_str(
                    inner.x,
                    inner.y + 1,
                    inner.w,
                    "Press [i] to import ~/.gemini, [a] to login, or run 'agy-swap-rs add'.",
                    theme.muted,
                );
            }
        }
    } else {
        frame.surface.put_str(
            area.x,
            area.y,
            area.w,
            "No accounts - press [i] or [a]",
            theme.muted,
        );
    }
}

fn render_dashboard_body(
    frame: &mut Frame<'_>,
    areas: DeckAreas,
    bp: Breakpoint,
    state: &DeckState,
    theme: &Theme,
) {
    match bp {
        Breakpoint::Wide | Breakpoint::Medium => {
            let row_lines: u16 = if areas.list.h >= 9 { 2 } else { 1 };
            render_account_list(frame, areas.list, state, theme, row_lines);

            let div_x = areas.list.right();
            if div_x < areas.body.right() {
                let hit_id = HitTarget::SplitDivider.encode();
                let div_style = if state.dragging == Some(DividerDrag::Vertical) {
                    theme.divider_drag
                } else if state.hover_hit == Some(hit_id) {
                    theme.divider_hover
                } else {
                    theme.divider
                };
                let vch = if frame.ascii { '|' } else { '\u{2502}' };
                frame.surface.fill(
                    Rect::new(div_x, areas.body.y, 1, areas.body.h),
                    vch,
                    div_style,
                );
                let hit_x = div_x.saturating_sub(1);
                let hit_w = 3.min(areas.body.right().saturating_sub(hit_x));
                frame.hit(
                    hit_id,
                    Rect::new(hit_x, areas.body.y, hit_w, areas.body.h),
                    PointerShape::ColResize,
                );
            }

            let mode = if bp == Breakpoint::Wide {
                DetailMode::SideBySide
            } else {
                DetailMode::StackedCards
            };
            render_detail_pane(frame, areas.detail, state, theme, mode);
        }
        Breakpoint::Stacked | Breakpoint::Compact => {
            render_account_list(frame, areas.list, state, theme, 1);
            if !areas.detail.is_empty() {
                let rule_y = areas.list.bottom();
                if rule_y < areas.body.bottom() {
                    let hit_id = HitTarget::StackDivider.encode();
                    let div_style = if state.dragging == Some(DividerDrag::Horizontal) {
                        theme.divider_drag
                    } else if state.hover_hit == Some(hit_id) {
                        theme.divider_hover
                    } else {
                        theme.divider
                    };
                    let hch = if frame.ascii { '-' } else { '\u{2500}' };
                    frame.surface.fill(
                        Rect::new(areas.body.x, rule_y, areas.body.w, 1),
                        hch,
                        div_style,
                    );
                    frame.hit(
                        hit_id,
                        Rect::new(areas.body.x, rule_y, areas.body.w, 1),
                        PointerShape::RowResize,
                    );
                }
                render_detail_pane(frame, areas.detail, state, theme, DetailMode::Compact);
            }
        }
    }
}

fn render_account_list(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &DeckState,
    theme: &Theme,
    lines_per_row: u16,
) {
    if area.is_empty() {
        return;
    }
    frame.hit(
        HitTarget::ListScrollArea.encode(),
        area,
        PointerShape::Default,
    );
    let emails = state.visible_emails();
    let mut y = area.y;
    if area.h >= 4 {
        let hdr = if state.filter.is_empty() {
            format!(" ACCOUNTS ({})", emails.len())
        } else {
            format!(
                " ACCOUNTS ({}/{}) filter: {}",
                emails.len(),
                state.accounts.len(),
                state.filter
            )
        };
        frame.surface.put_str(area.x, y, area.w, &hdr, theme.muted);
        y = y.saturating_add(1);
    }
    let avail_rows = area.bottom().saturating_sub(y);
    if avail_rows == 0 {
        return;
    }
    if emails.is_empty() {
        frame.surface.put_str(
            area.x.saturating_add(1),
            y,
            area.w.saturating_sub(1),
            "No matching accounts (press / to clear)",
            theme.muted,
        );
        return;
    }

    let step = lines_per_row.max(1) as usize;
    let capacity = (avail_rows as usize / step).max(1);
    let mut start = state.list_scroll.min(emails.len().saturating_sub(1));
    if state.selected < start {
        start = state.selected;
    } else if state.selected >= start + capacity {
        start = state.selected + 1 - capacity;
    }
    let max_start = emails.len().saturating_sub(capacity);
    if start > max_start {
        start = max_start;
    }

    let end = (start + capacity).min(emails.len());
    for (vis_idx, email) in emails.iter().enumerate().take(end).skip(start) {
        let row_h = lines_per_row.min(area.bottom().saturating_sub(y));
        if row_h == 0 {
            break;
        }
        let row_rect = Rect::new(area.x, y, area.w, row_h);
        if let Some(acc) = state.accounts.get(email) {
            render_account_entry(frame, row_rect, vis_idx, acc, state, theme);
        }
        y = y.saturating_add(row_h);
    }
}

fn render_account_entry(
    frame: &mut Frame<'_>,
    rect: Rect,
    vis_idx: usize,
    acc: &Account,
    state: &DeckState,
    theme: &Theme,
) {
    let hit_id = HitTarget::AccountRow(vis_idx).encode();
    let selected = vis_idx == state.selected;
    let hovered = !selected && state.hover_hit == Some(hit_id);
    let is_active = state
        .active_email
        .as_deref()
        .map(|a| a.eq_ignore_ascii_case(&acc.email))
        .unwrap_or(false);

    let row_bg = if selected {
        theme.row_selected
    } else if hovered {
        theme.row_hover
    } else {
        theme.body
    };
    frame.surface.fill(rect, ' ', row_bg);
    frame.hit(hit_id, rect, PointerShape::Pointer);

    let badge = state.account_badge(acc);
    let badge_str = if rect.w < 44 {
        Theme::badge_compact_label(badge)
    } else {
        Theme::badge_label(badge)
    };
    let b_style = theme.on_row(theme.badge_style(badge), selected, hovered);
    let bw = display_width(badge_str) as u16;
    let badge_x = rect.right().saturating_sub(bw).saturating_sub(1);
    let run_count = state.isolated_count(&acc.email);
    let run_tag = if run_count == 1 {
        "[RUN]".to_string()
    } else if run_count > 1 {
        format!("[RUNx{run_count}]")
    } else {
        String::new()
    };
    let rw = display_width(&run_tag) as u16;
    let right_anchor = if rw > 0 && badge_x > rect.x.saturating_add(rw + 10) {
        badge_x.saturating_sub(rw).saturating_sub(1)
    } else {
        badge_x
    };

    let sel_mark = if selected { ">" } else { " " };
    let act_mark = if is_active {
        if frame.ascii {
            "*"
        } else {
            "\u{25cf}"
        }
    } else {
        " "
    };
    let slot_prefix = if vis_idx < 9 && rect.w >= 34 {
        format!("{} ", vis_idx + 1)
    } else {
        String::new()
    };
    let identity = if rect.w >= 54 && !acc.name.is_empty() && acc.name != "Google User" {
        format!("{} <{}>", acc.name, acc.email)
    } else {
        acc.email.clone()
    };

    let mut x = rect.x;
    x = x.saturating_add(frame.surface.put_str(
        x,
        rect.y,
        2,
        sel_mark,
        theme.on_row(theme.title, selected, hovered),
    ));
    x = x.saturating_add(frame.surface.put_str(
        x,
        rect.y,
        2,
        act_mark,
        theme.on_row(theme.active_dot, selected, hovered),
    ));
    x = x.saturating_add(1);
    if !slot_prefix.is_empty() {
        x = x.saturating_add(frame.surface.put_str(
            x,
            rect.y,
            4,
            &slot_prefix,
            theme.on_row(theme.muted, selected, hovered),
        ));
    }
    let max_id_w = right_anchor.saturating_sub(x).saturating_sub(1);
    let id_style = if is_active {
        theme.on_row(theme.active_name, selected, hovered)
    } else {
        theme.on_row(theme.text_bold, selected, hovered)
    };
    if max_id_w > 0 {
        frame
            .surface
            .put_str(x, rect.y, max_id_w, &identity, id_style);
    }
    if right_anchor < badge_x {
        let run_st = Style {
            fg: theme.pool_extra.fg,
            bg: row_bg.bg,
            attrs: theme.pool_extra.attrs,
        };
        frame.surface.put_str(
            right_anchor,
            rect.y,
            rw,
            &run_tag,
            theme.on_row(run_st, selected, hovered),
        );
    }
    if badge_x > rect.x && bw <= rect.w {
        frame
            .surface
            .put_str(badge_x, rect.y, bw, badge_str, b_style);
    }

    if rect.h >= 2 {
        let y2 = rect.y + 1;
        let mut x2 = rect.x.saturating_add(4);
        let right2 = rect.right().saturating_sub(1);
        if badge == Badge::Verify {
            let note = "Google verification required - press [w]";
            frame.surface.put_str(
                x2,
                y2,
                right2.saturating_sub(x2),
                note,
                theme.on_row(theme.badge_verify, selected, hovered),
            );
        } else if badge == Badge::NoToken {
            let note = "No OAuth token in vault - press [a] to login";
            frame.surface.put_str(
                x2,
                y2,
                right2.saturating_sub(x2),
                note,
                theme.on_row(theme.muted, selected, hovered),
            );
        } else if let Some(ref snap) = acc.quota {
            let bar_w =
                ((right2.saturating_sub(x2) as usize).saturating_sub(24) / 2).clamp(4, 12) as u16;
            for (short, tone, pool) in [
                ("Gem", PoolTone::Gemini, &snap.gemini),
                ("C/G", PoolTone::ClaudeGpt, &snap.claude_gpt),
            ] {
                if x2.saturating_add(bar_w + 10) > right2 {
                    break;
                }
                x2 = x2.saturating_add(frame.surface.put_str(
                    x2,
                    y2,
                    4,
                    short,
                    theme.on_row(theme.muted, selected, hovered),
                ));
                x2 = x2.saturating_add(1);
                let pct = pool.effective_pct().unwrap_or(0.0);
                let fill_st = theme.on_row(theme.pool_gauge_style(tone, pct), selected, hovered);
                let emp_st = theme.on_row(theme.gauge_track, selected, hovered);
                frame.surface.draw_gauge(
                    Rect::new(x2, y2, bar_w, 1),
                    pct as f32,
                    fill_st,
                    emp_st,
                    frame.ascii,
                );
                x2 = x2.saturating_add(bar_w).saturating_add(1);
                let pct_lbl = match pool.effective_pct() {
                    Some(v) => format!("{v:>3.0}%  "),
                    None => " n/a  ".to_string(),
                };
                x2 = x2.saturating_add(frame.surface.put_str(x2, y2, 6, &pct_lbl, fill_st));
            }
        } else {
            frame.surface.put_str(
                x2,
                y2,
                right2.saturating_sub(x2),
                "Quota pending - press [r] to refresh",
                theme.on_row(theme.muted, selected, hovered),
            );
        }
    }
}

fn format_matrix_pct(pct: Option<f64>, width: usize) -> String {
    match pct {
        Some(v) if width >= 6 => format!("{v:>5.0}%"),
        Some(v) if width == 5 => format!("{v:>4.0}%"),
        Some(v) => format!("{v:>3.0}%"),
        None if width >= 6 => "    - ".to_string(),
        None if width == 5 => "   - ".to_string(),
        None => "  - ".to_string(),
    }
}

fn render_usage_matrix(
    frame: &mut Frame<'_>,
    x: u16,
    y: u16,
    w: u16,
    max_h: u16,
    state: &DeckState,
    theme: &Theme,
) -> u16 {
    if w < 46 || max_h < 8 || state.accounts.len() < 2 {
        return 0;
    }
    let avail = max_h.saturating_sub(4);
    if avail < 3 {
        return 0;
    }
    let total = state.accounts.order.len();
    let boxed = avail >= 5 && w >= 48;
    let max_rows = if boxed {
        avail.saturating_sub(3) as usize
    } else {
        avail.saturating_sub(1) as usize
    };
    let show_rows = total.min(max_rows).max(1);
    let card_h = if boxed {
        (show_rows as u16).saturating_add(3)
    } else {
        (show_rows as u16).saturating_add(1)
    };
    let inner = if boxed {
        let rect = Rect::new(x, y, w, card_h);
        frame.surface.draw_box(
            rect,
            theme.borders(),
            theme.panel_border,
            Some(theme.panel_bg),
        );
        if rect.w > 30 {
            let title_st = Style {
                fg: theme.title.fg,
                bg: theme.panel_bg.bg,
                attrs: theme.title.attrs,
            };
            frame.surface.put_str(
                rect.x + 2,
                rect.y,
                rect.w - 4,
                " ALL-ACCOUNTS USAGE MATRIX ",
                title_st,
            );
        }
        rect.inner(1, 1)
    } else {
        Rect::new(x, y, w, card_h)
    };
    if inner.is_empty() {
        return 0;
    }

    let wide = inner.w >= 66;
    let acct_w: u16 = if wide {
        inner.w.saturating_sub(53).max(12)
    } else {
        inner.w.saturating_sub(40).max(8)
    };
    let status_w: u16 = if wide { 8 } else { 6 };
    let pct_w: u16 = if wide { 6 } else { 4 };
    let arg_w: u16 = if wide { 5 } else { 4 };
    let rst_w: u16 = if wide { 6 } else { 4 };
    let base_bg = if boxed { theme.panel_bg } else { theme.body };
    let hdr_st = Style {
        fg: theme.muted.fg,
        bg: base_bg.bg,
        attrs: theme.muted.attrs,
    };

    let mut hx = inner.x;
    frame.surface.put_str(hx, inner.y, 2, " #", hdr_st);
    hx = hx.saturating_add(3);
    frame
        .surface
        .put_str(hx, inner.y, acct_w, "Account", hdr_st);
    hx = hx.saturating_add(acct_w + 1);
    frame
        .surface
        .put_str(hx, inner.y, status_w, "Status", hdr_st);
    hx = hx.saturating_add(status_w + 1);
    for lbl in if wide {
        ["Gem 5h", "Gem Wk", "C/G 5h", "C/G Wk"]
    } else {
        ["G5h", "GWk", "C5h", "CWk"]
    } {
        frame.surface.put_str(hx, inner.y, pct_w, lbl, hdr_st);
        hx = hx.saturating_add(pct_w + 1);
    }
    frame.surface.put_str(
        hx,
        inner.y,
        arg_w,
        if wide { "Argon" } else { "Arg" },
        hdr_st,
    );
    hx = hx.saturating_add(arg_w + 1);
    if hx < inner.right() {
        frame.surface.put_str(
            hx,
            inner.y,
            rst_w.min(inner.right() - hx),
            if wide { "Reset" } else { "Rst" },
            hdr_st,
        );
    }

    let vis_emails = state.visible_emails();
    let sel_email = state.selected_email();
    let sel_order_idx = sel_email
        .as_deref()
        .and_then(|s| {
            state
                .accounts
                .order
                .iter()
                .position(|e| e.eq_ignore_ascii_case(s))
        })
        .unwrap_or(0);
    let start = if sel_order_idx >= show_rows {
        (sel_order_idx + 1 - show_rows).min(total.saturating_sub(show_rows))
    } else {
        0
    };

    let mut ry = inner.y.saturating_add(1);
    for (ord_idx, email) in state
        .accounts
        .order
        .iter()
        .enumerate()
        .skip(start)
        .take(show_rows)
    {
        if ry >= inner.bottom() {
            break;
        }
        let Some(acc) = state.accounts.get(email) else {
            continue;
        };
        let vis_pos = vis_emails
            .iter()
            .position(|v| v.eq_ignore_ascii_case(email));
        let is_sel = sel_email
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case(email))
            .unwrap_or(false);
        let hit_opt = vis_pos.map(|vp| HitTarget::AccountRow(vp).encode());
        let is_hov = !is_sel && hit_opt.is_some() && state.hover_hit == hit_opt;
        let row_rect = Rect::new(inner.x, ry, inner.w, 1);
        let row_st = if is_sel {
            theme.row_selected
        } else if is_hov {
            theme.row_hover
        } else {
            base_bg
        };
        frame.surface.fill(row_rect, ' ', row_st);
        if let Some(hid) = hit_opt {
            frame.hit(hid, row_rect, PointerShape::Pointer);
        }

        let is_active = state
            .active_email
            .as_deref()
            .map(|a| a.eq_ignore_ascii_case(&acc.email))
            .unwrap_or(false);
        let mark = if is_active {
            if frame.ascii {
                "*"
            } else {
                "\u{25cf}"
            }
        } else {
            " "
        };
        let slot_str = format!("{mark}{}", ord_idx + 1);
        let mut cx = inner.x;
        let slot_st = if is_active {
            Style {
                fg: theme.active_dot.fg,
                bg: row_st.bg,
                attrs: theme.active_dot.attrs,
            }
        } else {
            row_st
        };
        frame
            .surface
            .put_str(cx, ry, 2, &slot_str, theme.on_row(slot_st, is_sel, is_hov));
        cx = cx.saturating_add(3);

        let acct_st = if is_active {
            Style {
                fg: theme.active_name.fg,
                bg: row_st.bg,
                attrs: theme.active_name.attrs,
            }
        } else {
            Style {
                fg: theme.text_bold.fg,
                bg: row_st.bg,
                attrs: theme.text_bold.attrs,
            }
        };
        frame.surface.put_str(
            cx,
            ry,
            acct_w,
            &acc.email,
            theme.on_row(acct_st, is_sel, is_hov),
        );
        cx = cx.saturating_add(acct_w + 1);

        let badge = state.account_badge(acc);
        let run_n = state.isolated_count(&acc.email);
        let (st_lbl, st_fg) = if run_n > 1 {
            (format!("RUNx{run_n}"), theme.pool_extra)
        } else if run_n == 1 {
            ("[RUN]".to_string(), theme.pool_extra)
        } else {
            (
                Theme::badge_compact_label(badge).to_string(),
                theme.badge_style(badge),
            )
        };
        let st_cell = Style {
            fg: st_fg.fg,
            bg: row_st.bg,
            attrs: st_fg.attrs,
        };
        frame.surface.put_str(
            cx,
            ry,
            status_w,
            &st_lbl,
            theme.on_row(st_cell, is_sel, is_hov),
        );
        cx = cx.saturating_add(status_w + 1);

        let snap = acc.quota.as_ref();
        let cells = [
            (
                snap.and_then(|q| q.gemini.five_hour.remaining_pct),
                PoolTone::Gemini,
            ),
            (
                snap.and_then(|q| q.gemini.weekly.remaining_pct),
                PoolTone::Gemini,
            ),
            (
                snap.and_then(|q| q.claude_gpt.five_hour.remaining_pct),
                PoolTone::ClaudeGpt,
            ),
            (
                snap.and_then(|q| q.claude_gpt.weekly.remaining_pct),
                PoolTone::ClaudeGpt,
            ),
        ];
        for (val, tone) in cells {
            let txt = format_matrix_pct(val, pct_w as usize);
            let cst = match val {
                Some(p) => {
                    let g = theme.pool_gauge_style(tone, p);
                    Style {
                        fg: g.fg,
                        bg: row_st.bg,
                        attrs: g.attrs,
                    }
                }
                None => Style {
                    fg: theme.muted.fg,
                    bg: row_st.bg,
                    attrs: theme.muted.attrs,
                },
            };
            frame
                .surface
                .put_str(cx, ry, pct_w, &txt, theme.on_row(cst, is_sel, is_hov));
            cx = cx.saturating_add(pct_w + 1);
        }

        let arg_val = snap
            .and_then(|q| q.argon.as_ref())
            .and_then(PoolQuota::effective_pct);
        let arg_txt = format_matrix_pct(arg_val, arg_w as usize);
        let arg_st = match arg_val {
            Some(p) => {
                let g = theme.pool_gauge_style(PoolTone::Argon, p);
                Style {
                    fg: g.fg,
                    bg: row_st.bg,
                    attrs: g.attrs,
                }
            }
            None => Style {
                fg: theme.muted.fg,
                bg: row_st.bg,
                attrs: theme.muted.attrs,
            },
        };
        frame.surface.put_str(
            cx,
            ry,
            arg_w,
            &arg_txt,
            theme.on_row(arg_st, is_sel, is_hov),
        );
        cx = cx.saturating_add(arg_w + 1);

        if cx < inner.right() {
            let earliest = snap.and_then(|q| {
                [
                    q.gemini.next_reset_unix(),
                    q.claude_gpt.next_reset_unix(),
                    q.argon.as_ref().and_then(PoolQuota::next_reset_unix),
                ]
                .into_iter()
                .flatten()
                .min()
            });
            let r_txt = format_countdown(earliest, state.now_unix);
            let r_st = Style {
                fg: theme.muted.fg,
                bg: row_st.bg,
                attrs: theme.muted.attrs,
            };
            frame.surface.put_str(
                cx,
                ry,
                rst_w.min(inner.right() - cx),
                &r_txt,
                theme.on_row(r_st, is_sel, is_hov),
            );
        }
        ry = ry.saturating_add(1);
    }
    card_h
}

fn render_detail_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &DeckState,
    theme: &Theme,
    mode: DetailMode,
) {
    if area.is_empty() {
        return;
    }
    frame.hit(
        HitTarget::DetailScrollArea.encode(),
        area,
        PointerShape::Default,
    );
    let Some(acc) = state.selected_account() else {
        frame.surface.put_str(
            area.x.saturating_add(1),
            area.y,
            area.w.saturating_sub(1),
            "Select an account to inspect quota pools.",
            theme.muted,
        );
        return;
    };

    let pad_x: u16 = if area.w >= 48 { 1 } else { 0 };
    let inner_x = area.x.saturating_add(pad_x);
    let inner_w = area.w.saturating_sub(pad_x * 2);
    let mut y = area.y;
    if state.accounts.len() >= 2 {
        let used = render_usage_matrix(
            frame,
            inner_x,
            y,
            inner_w,
            area.bottom().saturating_sub(y),
            state,
            theme,
        );
        y = y.saturating_add(used);
        if y >= area.bottom() {
            return;
        }
    }

    let badge = state.account_badge(acc);
    let b_lbl = if inner_w < 40 {
        Theme::badge_compact_label(badge)
    } else {
        Theme::badge_label(badge)
    };
    let bw = display_width(b_lbl) as u16;
    let bx = inner_x.saturating_add(inner_w.saturating_sub(bw));
    let tier_suffix = acc
        .quota
        .as_ref()
        .and_then(|q| q.plan_tier.as_deref())
        .filter(|t| !t.is_empty())
        .map(|t| format!(" - {t}"))
        .unwrap_or_default();
    let hdr = if inner_w >= 52 && !acc.name.is_empty() && acc.name != "Google User" {
        format!("{} <{}>{}", acc.name, acc.email, tier_suffix)
    } else {
        format!("{}{}", acc.email, tier_suffix)
    };
    let hdr_max = bx.saturating_sub(inner_x).saturating_sub(1);
    if hdr_max > 0 {
        frame
            .surface
            .put_str(inner_x, y, hdr_max, &hdr, theme.text_bold);
    }
    if bw <= inner_w {
        frame
            .surface
            .put_str(bx, y, bw, b_lbl, theme.badge_style(badge));
    }
    y = y.saturating_add(1);

    if y >= area.bottom() {
        return;
    }

    if badge == Badge::Verify {
        frame.surface.put_str(
            inner_x,
            y,
            inner_w,
            "Verification required before Antigravity can use this account.",
            theme.badge_verify,
        );
        if y + 1 < area.bottom() {
            let url_hint = acc
                .verify_url
                .as_deref()
                .unwrap_or("Press [w] or run 'agy-swap-rs verify --open'");
            frame
                .surface
                .put_str(inner_x, y + 1, inner_w, url_hint, theme.muted);
        }
        return;
    }

    let Some(ref snap) = acc.quota else {
        let msg = if !state.has_token(acc) {
            "No token in vault - press [a] to authenticate."
        } else {
            "Waiting for quota refresh - press [r] or [u]."
        };
        frame.surface.put_str(inner_x, y, inner_w, msg, theme.muted);
        return;
    };

    if mode != DetailMode::Compact && y + 6 < area.bottom() {
        let fresh = format!(
            "Snapshot: {}",
            format_age(snap.fetched_at_unix, state.now_unix)
        );
        frame
            .surface
            .put_str(inner_x, y, inner_w, &fresh, theme.muted);
        y = y.saturating_add(1);
    }

    let pools = collect_display_pools(snap);
    let rem_h = area.bottom().saturating_sub(y);
    if rem_h == 0 {
        return;
    }

    match mode {
        DetailMode::SideBySide if inner_w >= 52 && rem_h >= 5 => {
            let rows_needed = pools.len().div_ceil(2).max(1) as u16;
            let card_h = (rem_h / rows_needed).clamp(5, 8);
            let half_w = inner_w.saturating_sub(1) / 2;
            let mut idx = 0usize;
            while idx < pools.len() && y < area.bottom() {
                let h = card_h.min(area.bottom().saturating_sub(y));
                if h < 4 {
                    draw_compact_pool_line(
                        frame,
                        Rect::new(inner_x, y, inner_w, 1),
                        pools[idx],
                        state.now_unix,
                        theme,
                    );
                    y = y.saturating_add(1);
                    idx += 1;
                    continue;
                }
                let left_rect = Rect::new(inner_x, y, half_w, h);
                draw_pool_card(frame, left_rect, pools[idx], state.now_unix, theme);
                if idx + 1 < pools.len() {
                    let rx = inner_x.saturating_add(half_w).saturating_add(1);
                    let rw = inner_x.saturating_add(inner_w).saturating_sub(rx);
                    let right_rect = Rect::new(rx, y, rw, h);
                    draw_pool_card(frame, right_rect, pools[idx + 1], state.now_unix, theme);
                }
                y = y.saturating_add(h);
                idx += 2;
            }
        }
        DetailMode::StackedCards if inner_w >= 28 && rem_h >= 5 => {
            let count = pools.len().max(1) as u16;
            let card_h = (rem_h / count).clamp(4, 7);
            for p in pools {
                if y >= area.bottom() {
                    break;
                }
                let h = card_h.min(area.bottom().saturating_sub(y));
                if h >= 5 {
                    draw_pool_card(
                        frame,
                        Rect::new(inner_x, y, inner_w, h),
                        p,
                        state.now_unix,
                        theme,
                    );
                    y = y.saturating_add(h);
                } else {
                    draw_compact_pool_line(
                        frame,
                        Rect::new(inner_x, y, inner_w, 1),
                        p,
                        state.now_unix,
                        theme,
                    );
                    y = y.saturating_add(1);
                }
            }
        }
        _ => {
            for p in pools {
                if y >= area.bottom() {
                    break;
                }
                draw_compact_pool_line(
                    frame,
                    Rect::new(inner_x, y, inner_w, 1),
                    p,
                    state.now_unix,
                    theme,
                );
                y = y.saturating_add(1);
            }
        }
    }
}

pub(crate) fn draw_pool_card(
    frame: &mut Frame<'_>,
    rect: Rect,
    pool: DisplayPool<'_>,
    now_unix: i64,
    theme: &Theme,
) {
    if rect.w < 10 || rect.h < 4 {
        return;
    }
    let eff = pool.quota.effective_pct().unwrap_or(0.0);
    let border_st = if pool.quota.effective_pct().is_some() && eff <= 10.0 {
        Style {
            fg: theme.badge_critical.fg,
            bg: theme.panel_bg.bg,
            attrs: theme.panel_border.attrs,
        }
    } else if pool.quota.effective_pct().is_some() && eff <= 30.0 {
        Style {
            fg: theme.badge_low.fg,
            bg: theme.panel_bg.bg,
            attrs: theme.panel_border.attrs,
        }
    } else {
        theme.panel_border
    };
    frame
        .surface
        .draw_box(rect, theme.borders(), border_st, Some(theme.panel_bg));
    let inner = rect.inner(1, 1);
    if inner.is_empty() {
        return;
    }
    let accent = theme.pool_gauge_style(pool.tone, eff.max(31.0));
    let eff_txt = match pool.quota.effective_pct() {
        Some(v) => format!("{v:.1}%"),
        None => "n/a".to_string(),
    };
    let ew = display_width(&eff_txt) as u16;
    let ex = inner.right().saturating_sub(ew);
    let title_max = ex.saturating_sub(inner.x).saturating_sub(1);
    if title_max > 0 {
        frame
            .surface
            .put_str(inner.x, inner.y, title_max, pool.label, accent);
    }
    if ew <= inner.w {
        let val_st = theme.pool_gauge_style(pool.tone, eff);
        frame.surface.put_str(ex, inner.y, ew, &eff_txt, val_st);
    }

    let mut wy = inner.y.saturating_add(1);
    let spacious = inner.h >= 5;
    for (w_label, win) in [
        ("5-Hour", &pool.quota.five_hour),
        ("Weekly", &pool.quota.weekly),
    ] {
        if wy >= inner.bottom() {
            break;
        }
        draw_window_row(
            frame,
            Rect::new(inner.x, wy, inner.w, if spacious { 2 } else { 1 }),
            w_label,
            win,
            pool.tone,
            now_unix,
            theme,
        );
        wy = wy.saturating_add(if spacious { 2 } else { 1 });
    }
}

fn draw_window_row(
    frame: &mut Frame<'_>,
    area: Rect,
    label: &str,
    win: &PoolWindow,
    tone: PoolTone,
    now_unix: i64,
    theme: &Theme,
) {
    let pct = win.remaining_pct.unwrap_or(0.0);
    let fill = theme.pool_gauge_style(
        tone,
        if win.remaining_pct.is_some() {
            pct
        } else {
            50.0
        },
    );
    let cd = format_countdown(win.reset_at_unix, now_unix);
    let pct_str = match win.remaining_pct {
        Some(v) => format!("{v:>5.1}%"),
        None => "  n/a ".to_string(),
    };
    if area.h >= 2 {
        let info = if cd == "-" {
            format!("{label}  {pct_str}")
        } else {
            format!("{label}  {pct_str}  resets {cd}")
        };
        frame
            .surface
            .put_str(area.x, area.y, area.w, &info, theme.panel_bg);
        frame.surface.draw_gauge(
            Rect::new(area.x, area.y + 1, area.w, 1),
            pct as f32,
            fill,
            theme.gauge_track,
            frame.ascii,
        );
    } else {
        let mut x = area.x;
        let lbl_w = 6.min(area.w);
        frame
            .surface
            .put_str(x, area.y, lbl_w, label, theme.panel_bg);
        x = x.saturating_add(lbl_w).saturating_add(1);
        let suffix = if cd == "-" {
            pct_str
        } else {
            format!("{pct_str} {cd}")
        };
        let sw = display_width(&suffix) as u16;
        let bar_w = area.right().saturating_sub(x).saturating_sub(sw + 1);
        if bar_w >= 3 {
            frame.surface.draw_gauge(
                Rect::new(x, area.y, bar_w, 1),
                pct as f32,
                fill,
                theme.gauge_track,
                frame.ascii,
            );
            x = x.saturating_add(bar_w).saturating_add(1);
        }
        if x < area.right() {
            frame
                .surface
                .put_str(x, area.y, area.right().saturating_sub(x), &suffix, fill);
        }
    }
}

fn draw_compact_pool_line(
    frame: &mut Frame<'_>,
    row: Rect,
    pool: DisplayPool<'_>,
    now_unix: i64,
    theme: &Theme,
) {
    if row.is_empty() {
        return;
    }
    let eff = pool.quota.effective_pct().unwrap_or(0.0);
    let fill = theme.pool_gauge_style(
        pool.tone,
        if pool.quota.effective_pct().is_some() {
            eff
        } else {
            50.0
        },
    );
    let mut x = row.x;
    let lbl = if row.w >= 56 { pool.label } else { pool.short };
    let lbl_col: u16 = if row.w >= 56 { 14 } else { 5 };
    frame
        .surface
        .put_str(x, row.y, lbl_col.min(row.w), lbl, theme.text_bold);
    x = x.saturating_add(lbl_col).saturating_add(1);
    let cd = format_countdown(pool.quota.next_reset_unix(), now_unix);
    let pct_txt = match pool.quota.effective_pct() {
        Some(v) => format!("{v:>3.0}%"),
        None => " n/a".to_string(),
    };
    let tail = if row.w >= 44 && cd != "-" {
        let wk = pool
            .quota
            .weekly
            .remaining_pct
            .map(|v| format!(" wk:{v:.0}%"))
            .unwrap_or_default();
        format!("{pct_txt} {cd}{wk}")
    } else if cd != "-" && row.w >= 32 {
        format!("{pct_txt} {cd}")
    } else {
        pct_txt
    };
    let tw = display_width(&tail) as u16;
    let bar_w = row.right().saturating_sub(x).saturating_sub(tw + 1);
    if bar_w >= 3 {
        frame.surface.draw_gauge(
            Rect::new(x, row.y, bar_w, 1),
            eff as f32,
            fill,
            theme.divider,
            frame.ascii,
        );
        x = x.saturating_add(bar_w).saturating_add(1);
    }
    if x < row.right() {
        frame
            .surface
            .put_str(x, row.y, row.right().saturating_sub(x), &tail, fill);
    }
}

fn render_status_bar(frame: &mut Frame<'_>, row: Rect, state: &DeckState, theme: &Theme) {
    frame.surface.fill(row, ' ', theme.footer_bar);
    let x = row.x.saturating_add(1);
    let w = row.w.saturating_sub(2);
    if w == 0 {
        return;
    }
    if state.modal == Modal::FilterInput {
        let prompt = format!("/{}_  (Enter apply - Esc cancel)", state.filter);
        frame
            .surface
            .put_str(x, row.y, w, &prompt, theme.banner_info);
        return;
    }
    if let Some((ref msg, lvl)) = state.status_line {
        let st = match lvl {
            ToastLevel::Success => theme.banner_success,
            ToastLevel::Warn => theme.banner_warn,
            ToastLevel::Error => theme.banner_error,
            ToastLevel::Info => theme.banner_info,
        };
        frame.surface.put_str(x, row.y, w, msg, st);
        return;
    }
    let hint = state.view.subtitle();
    frame.surface.put_str(x, row.y, w, hint, theme.footer_bar);
}

fn render_footer_bar(
    frame: &mut Frame<'_>,
    row: Rect,
    bp: Breakpoint,
    state: &DeckState,
    theme: &Theme,
) {
    frame.surface.fill(row, ' ', theme.footer_bar);
    let chips: &[(&str, &str, KeycapAction)] = match state.view {
        ActiveView::Dashboard => {
            if matches!(bp, Breakpoint::Wide | Breakpoint::Medium) {
                &[
                    ("j/k", "Move", KeycapAction::MoveDown),
                    ("Enter", "Launch", KeycapAction::Confirm),
                    ("a", "Add", KeycapAction::Add),
                    ("i", "Import", KeycapAction::ImportCurrent),
                    ("r", "Refresh", KeycapAction::Refresh),
                    ("n", "Next", KeycapAction::Next),
                    ("/", "Filter", KeycapAction::Filter),
                    ("[", "Narrow", KeycapAction::SplitNarrow),
                    ("]", "Widen", KeycapAction::SplitWiden),
                    ("^K", "Actions", KeycapAction::Palette),
                    ("?", "Help", KeycapAction::Help),
                    ("q", "Quit", KeycapAction::Quit),
                ]
            } else {
                &[
                    ("j/k", "Move", KeycapAction::MoveDown),
                    ("Enter", "Launch", KeycapAction::Confirm),
                    ("r", "Sync", KeycapAction::Refresh),
                    ("^K", "Menu", KeycapAction::Palette),
                    ("?", "Help", KeycapAction::Help),
                    ("q", "Quit", KeycapAction::Quit),
                ]
            }
        }
        ActiveView::FailoverPolicy => &[
            ("Space", "Toggle", KeycapAction::PolicyToggle),
            ("M", "ANY/ALL", KeycapAction::PolicyMode),
            ("S", "Save", KeycapAction::PolicySave),
            ("Esc", "Back", KeycapAction::BackDashboard),
            ("^K", "Actions", KeycapAction::Palette),
        ],
        ActiveView::Backup => &[
            ("x", "Export", KeycapAction::BackupExport),
            ("Esc", "Back", KeycapAction::BackDashboard),
            ("^K", "Actions", KeycapAction::Palette),
            ("?", "Help", KeycapAction::Help),
        ],
        _ => &[
            ("j/k", "Scroll", KeycapAction::MoveDown),
            ("r", "Refresh", KeycapAction::Refresh),
            ("Esc", "Back", KeycapAction::BackDashboard),
            ("^K", "Actions", KeycapAction::Palette),
            ("?", "Help", KeycapAction::Help),
            ("q", "Quit", KeycapAction::Quit),
        ],
    };

    let mut x = row.x.saturating_add(1);
    let limit = row.right().saturating_sub(1);
    for &(key_lbl, desc, act) in chips {
        let key_txt = format!(" {key_lbl} ");
        let kw = display_width(&key_txt) as u16;
        let desc_txt = format!(" {desc}  ");
        let dw = display_width(&desc_txt) as u16;
        if x.saturating_add(kw) > limit {
            break;
        }
        let hit_id = HitTarget::FooterKeycap(act).encode();
        let k_style = if state.hover_hit == Some(hit_id) {
            theme.keycap_active
        } else {
            theme.keycap
        };
        frame.surface.put_str(x, row.y, kw, &key_txt, k_style);
        let show_desc = x.saturating_add(kw + dw) <= limit;
        let total_w = if show_desc { kw + dw } else { kw };
        if show_desc {
            frame
                .surface
                .put_str(x + kw, row.y, dw, &desc_txt, theme.keycap_desc);
        }
        frame.hit(
            hit_id,
            Rect::new(x, row.y, total_w, 1),
            PointerShape::Pointer,
        );
        x = x
            .saturating_add(total_w)
            .saturating_add(if show_desc { 0 } else { 1 });
    }
}
