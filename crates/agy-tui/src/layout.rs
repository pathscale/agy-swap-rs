//! Rectangular geometry, responsive breakpoints, and 1D splitters.

use alloc::vec;
use alloc::vec::Vec;

/// Axis-aligned rectangle in terminal cell coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    #[must_use]
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    #[must_use]
    pub const fn right(self) -> u16 {
        self.x.saturating_add(self.w)
    }

    #[must_use]
    pub const fn bottom(self) -> u16 {
        self.y.saturating_add(self.h)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    #[must_use]
    pub const fn contains(self, x: u16, y: u16) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }

    #[must_use]
    pub const fn inner(self, pad_x: u16, pad_y: u16) -> Self {
        let dx = pad_x.saturating_mul(2);
        let dy = pad_y.saturating_mul(2);
        let nx = self.x.saturating_add(if pad_x < self.w { pad_x } else { self.w });
        let ny = self.y.saturating_add(if pad_y < self.h { pad_y } else { self.h });
        let nw = self.w.saturating_sub(dx);
        let nh = self.h.saturating_sub(dy);
        Self { x: nx, y: ny, w: nw, h: nh }
    }

    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        let x1 = if self.x > other.x { self.x } else { other.x };
        let y1 = if self.y > other.y { self.y } else { other.y };
        let r1 = self.right();
        let r2 = other.right();
        let x2 = if r1 < r2 { r1 } else { r2 };
        let b1 = self.bottom();
        let b2 = other.bottom();
        let y2 = if b1 < b2 { b1 } else { b2 };
        if x2 <= x1 || y2 <= y1 {
            Self { x: x1, y: y1, w: 0, h: 0 }
        } else {
            Self { x: x1, y: y1, w: x2 - x1, h: y2 - y1 }
        }
    }
}

/// Sizing rule for a single slot in [`split_h`] or [`split_v`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Constraint {
    Fixed(u16),
    Min(u16),
    Percent(u16),
    Fill(u16),
}

/// Responsive width tier for the operator deck.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Breakpoint {
    Wide,
    Medium,
    Stacked,
    Compact,
}

impl Breakpoint {
    #[must_use]
    pub const fn from_width(w: u16) -> Self {
        if w >= 120 {
            Self::Wide
        } else if w >= 92 {
            Self::Medium
        } else if w >= 64 {
            Self::Stacked
        } else {
            Self::Compact
        }
    }
}

fn solve_1d(origin: u16, total: u16, constraints: &[Constraint], gap: u16) -> Vec<(u16, u16)> {
    let n = constraints.len();
    if n == 0 {
        return Vec::new();
    }
    let total_gap = (gap as u32).saturating_mul((n - 1) as u32);
    let avail = (total as u32).saturating_sub(total_gap);
    let mut sizes = vec![0u32; n];
    let mut rem = avail;
    let mut fill_weight_sum = 0u32;
    let mut fill_zero_count = 0u32;
    let mut min_count = 0u32;
    let mut pct_sum = 0u32;
    let mut last_pct_idx: Option<usize> = None;

    for (i, c) in constraints.iter().copied().enumerate() {
        match c {
            Constraint::Fixed(v) => {
                let take = (v as u32).min(rem);
                sizes[i] = take;
                rem -= take;
            }
            Constraint::Min(v) => {
                let take = (v as u32).min(rem);
                sizes[i] = take;
                rem -= take;
                min_count += 1;
            }
            Constraint::Percent(p) => {
                let pct = p.min(100) as u32;
                pct_sum += pct;
                if pct > 0 {
                    last_pct_idx = Some(i);
                }
                let want = (avail * pct) / 100;
                let take = want.min(rem);
                sizes[i] = take;
                rem -= take;
            }
            Constraint::Fill(w) => {
                if w == 0 {
                    fill_zero_count += 1;
                } else {
                    fill_weight_sum += w as u32;
                }
            }
        }
    }

    if rem > 0 {
        if fill_weight_sum > 0 {
            let pool = rem;
            let mut distributed = 0u32;
            for (i, c) in constraints.iter().copied().enumerate() {
                if let Constraint::Fill(w) = c {
                    if w > 0 {
                        let share = (pool * (w as u32)) / fill_weight_sum;
                        sizes[i] += share;
                        distributed += share;
                    }
                }
            }
            let mut leftover = pool - distributed;
            for (i, c) in constraints.iter().copied().enumerate() {
                if leftover == 0 {
                    break;
                }
                if let Constraint::Fill(w) = c {
                    if w > 0 {
                        sizes[i] += 1;
                        leftover -= 1;
                    }
                }
            }
        } else if fill_zero_count > 0 {
            let each = rem / fill_zero_count;
            let mut leftover = rem % fill_zero_count;
            for (i, c) in constraints.iter().copied().enumerate() {
                if matches!(c, Constraint::Fill(0)) {
                    sizes[i] += each;
                    if leftover > 0 {
                        sizes[i] += 1;
                        leftover -= 1;
                    }
                }
            }
        } else if min_count > 0 {
            let each = rem / min_count;
            let mut leftover = rem % min_count;
            for (i, c) in constraints.iter().copied().enumerate() {
                if matches!(c, Constraint::Min(_)) {
                    sizes[i] += each;
                    if leftover > 0 {
                        sizes[i] += 1;
                        leftover -= 1;
                    }
                }
            }
        } else if pct_sum >= 100 {
            if let Some(idx) = last_pct_idx {
                sizes[idx] += rem;
            }
        }
    }

    let limit = origin.saturating_add(total);
    let mut cursor = origin;
    let mut out = Vec::with_capacity(n);
    for (i, sz) in sizes.into_iter().enumerate() {
        let pos = cursor.min(limit);
        let max_len = limit.saturating_sub(pos);
        let len = (sz.min(u16::MAX as u32) as u16).min(max_len);
        out.push((pos, len));
        cursor = pos.saturating_add(len);
        if i + 1 < n {
            cursor = cursor.saturating_add(gap).min(limit);
        }
    }
    out
}

/// Split `area` horizontally into left-to-right sub-rectangles.
#[must_use]
pub fn split_h(area: Rect, constraints: &[Constraint], gap: u16) -> Vec<Rect> {
    solve_1d(area.x, area.w, constraints, gap)
        .into_iter()
        .map(|(x, w)| Rect::new(x, area.y, w, area.h))
        .collect()
}

/// Split `area` vertically into top-to-bottom sub-rectangles.
#[must_use]
pub fn split_v(area: Rect, constraints: &[Constraint], gap: u16) -> Vec<Rect> {
    solve_1d(area.y, area.h, constraints, gap)
        .into_iter()
        .map(|(y, h)| Rect::new(area.x, y, area.w, h))
        .collect()
}

/// Center a rectangle of at most `(max_w, max_h)` inside `area`.
#[must_use]
pub const fn centered_rect(area: Rect, max_w: u16, max_h: u16) -> Rect {
    let w = if max_w < area.w { max_w } else { area.w };
    let h = if max_h < area.h { max_h } else { area.h };
    let x = area.x.saturating_add((area.w - w) / 2);
    let y = area.y.saturating_add((area.h - h) / 2);
    Rect::new(x, y, w, h)
}
