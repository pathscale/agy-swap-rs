//! Differential ANSI frame encoder with synchronized output and SGR state tracking.

use alloc::vec::Vec;

use crate::style::{Attrs, Color, Style};
use crate::surface::{Cell, Surface};

fn push_u16(out: &mut Vec<u8>, mut val: u16) {
    if val == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 5];
    let mut i = 5usize;
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + ((val % 10) as u8);
        val /= 10;
    }
    out.extend_from_slice(&buf[i..]);
}

fn push_param(out: &mut Vec<u8>, first: &mut bool, val: u16) {
    if !*first {
        out.push(b';');
    }
    *first = false;
    push_u16(out, val);
}

fn emit_color_params(out: &mut Vec<u8>, first: &mut bool, color: Color, is_bg: bool) {
    match color {
        Color::Reset => push_param(out, first, if is_bg { 49 } else { 39 }),
        Color::Ansi(idx) => {
            if idx < 8 {
                let base = if is_bg { 40 } else { 30 };
                push_param(out, first, base + (idx as u16));
            } else if idx < 16 {
                let base = if is_bg { 100 } else { 90 };
                push_param(out, first, base + ((idx - 8) as u16));
            } else {
                push_param(out, first, if is_bg { 48 } else { 38 });
                push_param(out, first, 5);
                push_param(out, first, idx as u16);
            }
        }
        Color::Rgb(r, g, b) => {
            push_param(out, first, if is_bg { 48 } else { 38 });
            push_param(out, first, 2);
            push_param(out, first, r as u16);
            push_param(out, first, g as u16);
            push_param(out, first, b as u16);
        }
    }
}

fn emit_attrs_params(out: &mut Vec<u8>, first: &mut bool, attrs: Attrs) {
    if attrs.contains(Attrs::BOLD) {
        push_param(out, first, 1);
    }
    if attrs.contains(Attrs::DIM) {
        push_param(out, first, 2);
    }
    if attrs.contains(Attrs::ITALIC) {
        push_param(out, first, 3);
    }
    if attrs.contains(Attrs::UNDERLINE) {
        push_param(out, first, 4);
    }
    if attrs.contains(Attrs::REVERSE) {
        push_param(out, first, 7);
    }
}

fn emit_sgr_transition(out: &mut Vec<u8>, cur: Option<Style>, target: Style) {
    if cur == Some(target) {
        return;
    }
    out.extend_from_slice(b"\x1b[");
    let mut first = true;
    let need_reset = match cur {
        None => true,
        Some(prev) => (prev.attrs.0 & !target.attrs.0) != 0,
    };
    if need_reset {
        push_param(out, &mut first, 0);
        emit_attrs_params(out, &mut first, target.attrs);
        if target.fg != Color::Reset {
            emit_color_params(out, &mut first, target.fg, false);
        }
        if target.bg != Color::Reset {
            emit_color_params(out, &mut first, target.bg, true);
        }
    } else if let Some(prev) = cur {
        let added = Attrs(target.attrs.0 & !prev.attrs.0);
        emit_attrs_params(out, &mut first, added);
        if target.fg != prev.fg {
            emit_color_params(out, &mut first, target.fg, false);
        }
        if target.bg != prev.bg {
            emit_color_params(out, &mut first, target.bg, true);
        }
    }
    out.push(b'm');
}

fn emit_cup(out: &mut Vec<u8>, x: u16, y: u16) {
    if x == 0 && y == 0 {
        out.extend_from_slice(b"\x1b[H");
    } else {
        out.extend_from_slice(b"\x1b[");
        push_u16(out, y.saturating_add(1));
        out.push(b';');
        push_u16(out, x.saturating_add(1));
        out.push(b'H');
    }
}

/// Encode minimal ANSI escape sequences transforming `prev` into `next`.
pub fn diff_ansi(prev: Option<&Surface>, next: &Surface, sync_output: bool, out: &mut Vec<u8>) {
    let w = next.width();
    let h = next.height();
    if sync_output {
        out.extend_from_slice(b"\x1b[?2026h");
    }
    let same_dims = prev.map_or(false, |p| p.width() == w && p.height() == h);
    let prev_surf = if same_dims { prev } else { None };
    let mut cur_style: Option<Style> = None;
    let mut cur_pos: Option<(u16, u16)> = None;
    if prev_surf.is_none() && w > 0 && h > 0 {
        out.extend_from_slice(b"\x1b[0m\x1b[2J");
        cur_style = Some(Style::new());
    }
    let mut utf8_buf = [0u8; 4];
    let mut y = 0u16;
    while y < h {
        let mut x = 0u16;
        while x < w {
            let cell = next.get(x, y).copied().unwrap_or_else(Cell::default);
            if cell.continuation {
                x += 1;
                continue;
            }
            let is_wide_pair = x + 1 < w && next.get(x + 1, y).map_or(false, |c| c.continuation);
            let step: u16 = if is_wide_pair { 2 } else { 1 };
            let unchanged = match prev_surf {
                Some(p) => {
                    let c0_same = p.get(x, y) == Some(&cell);
                    if is_wide_pair {
                        c0_same && p.get(x + 1, y) == next.get(x + 1, y)
                    } else {
                        c0_same
                    }
                }
                None => false,
            };
            if unchanged {
                x += step;
                continue;
            }
            if cur_pos != Some((x, y)) {
                emit_cup(out, x, y);
            }
            emit_sgr_transition(out, cur_style, cell.style);
            cur_style = Some(cell.style);
            let encoded = cell.ch.encode_utf8(&mut utf8_buf);
            out.extend_from_slice(encoded.as_bytes());
            let next_x = x.saturating_add(step);
            if next_x >= w {
                cur_pos = None;
            } else {
                cur_pos = Some((next_x, y));
            }
            x = next_x;
        }
        y += 1;
    }
    if cur_style.is_some() && cur_style != Some(Style::new()) {
        out.extend_from_slice(b"\x1b[0m");
    }
    if sync_output {
        out.extend_from_slice(b"\x1b[?2026l");
    }
}
