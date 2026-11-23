//! 2D cell buffer, Unicode display width, box borders, and gauge primitives.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::layout::Rect;
use crate::style::{Color, Style};

/// Box-drawing glyph set for frames and panels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BorderSet {
    pub tl: char,
    pub tr: char,
    pub bl: char,
    pub br: char,
    pub h: char,
    pub v: char,
}

impl BorderSet {
    pub const ROUNDED: Self = Self {
        tl: '\u{256d}',
        tr: '\u{256e}',
        bl: '\u{2570}',
        br: '\u{256f}',
        h: '\u{2500}',
        v: '\u{2502}',
    };

    pub const PLAIN: Self = Self {
        tl: '\u{250c}',
        tr: '\u{2510}',
        bl: '\u{2514}',
        br: '\u{2518}',
        h: '\u{2500}',
        v: '\u{2502}',
    };

    pub const ASCII: Self = Self {
        tl: '+',
        tr: '+',
        bl: '+',
        br: '+',
        h: '-',
        v: '|',
    };
}

/// Single grid cell on a [`Surface`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cell {
    pub ch: char,
    pub style: Style,
    pub continuation: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            style: Style::new(),
            continuation: false,
        }
    }
}

const fn is_combining_or_zero(u: u32) -> bool {
    matches!(
        u,
        0x0000..=0x001F
            | 0x007F..=0x009F
            | 0x00AD
            | 0x0300..=0x036F
            | 0x0483..=0x0489
            | 0x0591..=0x05BD
            | 0x05BF
            | 0x05C1..=0x05C2
            | 0x05C4..=0x05C5
            | 0x05C7
            | 0x0610..=0x061A
            | 0x064B..=0x065F
            | 0x0670
            | 0x06D6..=0x06DC
            | 0x06DF..=0x06E4
            | 0x06E7..=0x06E8
            | 0x06EA..=0x06ED
            | 0x0711
            | 0x0730..=0x074A
            | 0x07A6..=0x07B0
            | 0x07EB..=0x07F3
            | 0x0E31
            | 0x0E34..=0x0E3A
            | 0x0E47..=0x0E4E
            | 0x0EB1
            | 0x0EB4..=0x0EBC
            | 0x0EC8..=0x0ECD
            | 0x0F18..=0x0F19
            | 0x0F35
            | 0x0F37
            | 0x0F39
            | 0x0F71..=0x0F7E
            | 0x0F80..=0x0F84
            | 0x0F86..=0x0F87
            | 0x0F8D..=0x0F97
            | 0x0F99..=0x0FBC
            | 0x0FC6
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0x20D0..=0x20FF
            | 0x3099..=0x309A
            | 0xFE00..=0xFE0F
            | 0xFE20..=0xFE2F
            | 0xFEFF
            | 0xE0000..=0xE007F
            | 0xE0100..=0xE01EF
    )
}

const fn is_wide(u: u32) -> bool {
    matches!(
        u,
        0x1100..=0x115F
            | 0x231A..=0x231B
            | 0x2329..=0x232A
            | 0x23E9..=0x23F3
            | 0x23F8..=0x23FA
            | 0x25FD..=0x25FE
            | 0x2614..=0x2615
            | 0x2648..=0x2653
            | 0x267F
            | 0x2693
            | 0x26A1
            | 0x26AA..=0x26AB
            | 0x26BD..=0x26BE
            | 0x26C4..=0x26C5
            | 0x26CE
            | 0x26D4
            | 0x26EA
            | 0x26F2..=0x26F3
            | 0x26F5
            | 0x26FA
            | 0x26FD
            | 0x2705
            | 0x270A..=0x270B
            | 0x2728
            | 0x274C
            | 0x274E
            | 0x2753..=0x2755
            | 0x2757
            | 0x2795..=0x2797
            | 0x27B0
            | 0x27BF
            | 0x2B1B..=0x2B1C
            | 0x2B50
            | 0x2B55
            | 0x2E80..=0x303E
            | 0x3041..=0x33FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0xA4CF
            | 0xA960..=0xA97C
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF01..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F004
            | 0x1F0CF
            | 0x1F18E
            | 0x1F1E6..=0x1F251
            | 0x1F300..=0x1F64F
            | 0x1F680..=0x1F6FF
            | 0x1F900..=0x1FAFF
            | 0x20000..=0x2FFFD
            | 0x30000..=0x3FFFD
    )
}

/// Terminal column width of a single Unicode scalar value (`0`, `1`, or `2`).
#[must_use]
pub const fn char_width(ch: char) -> usize {
    let u = ch as u32;
    if u >= 0x20 && u < 0x7F {
        1
    } else if is_combining_or_zero(u) {
        0
    } else if is_wide(u) {
        2
    } else {
        1
    }
}

/// Total terminal column width of a UTF-8 string.
#[must_use]
pub fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// Offscreen 2D cell buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface {
    w: u16,
    h: u16,
    cells: Vec<Cell>,
}

impl Surface {
    #[must_use]
    pub fn new(w: u16, h: u16) -> Self {
        let len = (w as usize) * (h as usize);
        Self {
            w,
            h,
            cells: vec![Cell::default(); len],
        }
    }

    #[must_use]
    pub const fn width(&self) -> u16 {
        self.w
    }

    #[must_use]
    pub const fn height(&self) -> u16 {
        self.h
    }

    pub fn resize(&mut self, w: u16, h: u16) {
        self.w = w;
        self.h = h;
        let len = (w as usize) * (h as usize);
        self.cells.clear();
        self.cells.resize(len, Cell::default());
    }

    pub fn clear(&mut self, style: Style) {
        let blank = Cell {
            ch: ' ',
            style,
            continuation: false,
        };
        self.cells.fill(blank);
    }

    #[must_use]
    pub fn get(&self, x: u16, y: u16) -> Option<&Cell> {
        if x < self.w && y < self.h {
            Some(&self.cells[(y as usize) * (self.w as usize) + (x as usize)])
        } else {
            None
        }
    }

    fn idx(&self, x: u16, y: u16) -> usize {
        (y as usize) * (self.w as usize) + (x as usize)
    }

    fn scrub_wide_overlap(&mut self, x: u16, y: u16) {
        let i = self.idx(x, y);
        if self.cells[i].continuation && x > 0 {
            let prev = self.idx(x - 1, y);
            self.cells[prev].ch = ' ';
            self.cells[prev].continuation = false;
        }
        if x + 1 < self.w {
            let next = self.idx(x + 1, y);
            if self.cells[next].continuation {
                self.cells[next].ch = ' ';
                self.cells[next].continuation = false;
            }
        }
    }

    pub fn set_char(&mut self, x: u16, y: u16, ch: char, style: Style) {
        if x >= self.w || y >= self.h {
            return;
        }
        let cw = char_width(ch);
        if cw == 0 {
            return;
        }
        self.scrub_wide_overlap(x, y);
        let i = self.idx(x, y);
        if cw == 2 {
            if x + 1 >= self.w {
                self.cells[i] = Cell {
                    ch: ' ',
                    style,
                    continuation: false,
                };
                return;
            }
            self.scrub_wide_overlap(x + 1, y);
            self.cells[i] = Cell {
                ch,
                style,
                continuation: false,
            };
            self.cells[i + 1] = Cell {
                ch: ' ',
                style,
                continuation: true,
            };
        } else {
            self.cells[i] = Cell {
                ch,
                style,
                continuation: false,
            };
        }
    }

    pub fn fill(&mut self, rect: Rect, ch: char, style: Style) {
        let bounds = Rect::new(0, 0, self.w, self.h);
        let area = rect.intersect(bounds);
        if area.is_empty() {
            return;
        }
        let glyph = if char_width(ch) == 0 { ' ' } else { ch };
        let step = char_width(glyph).max(1) as u16;
        let mut y = area.y;
        while y < area.bottom() {
            let mut x = area.x;
            while x < area.right() {
                if step == 2 && x + 1 >= area.right() {
                    self.set_char(x, y, ' ', style);
                    break;
                }
                self.set_char(x, y, glyph, style);
                x = x.saturating_add(step);
            }
            y += 1;
        }
    }

    pub fn put_str(&mut self, x: u16, y: u16, max_w: u16, text: &str, style: Style) -> u16 {
        if y >= self.h || x >= self.w || max_w == 0 {
            return 0;
        }
        let limit = x.saturating_add(max_w).min(self.w);
        let mut cur_x = x;
        for ch in text.chars() {
            if ch == '\n' || ch == '\r' {
                break;
            }
            let cw = char_width(ch) as u16;
            if cw == 0 {
                continue;
            }
            if cur_x.saturating_add(cw) > limit {
                break;
            }
            self.set_char(cur_x, y, ch, style);
            cur_x += cw;
        }
        cur_x - x
    }

    pub fn put_str_clipped(&mut self, rect: Rect, text: &str, style: Style) -> u16 {
        if rect.is_empty() {
            return 0;
        }
        self.put_str(rect.x, rect.y, rect.w, text, style)
    }

    pub fn draw_box(
        &mut self,
        rect: Rect,
        borders: BorderSet,
        border_style: Style,
        fill_style: Option<Style>,
    ) {
        if rect.is_empty() {
            return;
        }
        if let Some(fs) = fill_style {
            let interior = rect.inner(1, 1);
            if !interior.is_empty() {
                self.fill(interior, ' ', fs);
            }
        }
        if rect.w == 1 && rect.h == 1 {
            self.set_char(rect.x, rect.y, borders.tl, border_style);
            return;
        }
        if rect.h == 1 {
            let mut x = rect.x;
            while x < rect.right() {
                self.set_char(x, rect.y, borders.h, border_style);
                x += 1;
            }
            return;
        }
        if rect.w == 1 {
            let mut y = rect.y;
            while y < rect.bottom() {
                self.set_char(rect.x, y, borders.v, border_style);
                y += 1;
            }
            return;
        }
        let right = rect.right() - 1;
        let bottom = rect.bottom() - 1;
        self.set_char(rect.x, rect.y, borders.tl, border_style);
        self.set_char(right, rect.y, borders.tr, border_style);
        self.set_char(rect.x, bottom, borders.bl, border_style);
        self.set_char(right, bottom, borders.br, border_style);
        let mut x = rect.x + 1;
        while x < right {
            self.set_char(x, rect.y, borders.h, border_style);
            self.set_char(x, bottom, borders.h, border_style);
            x += 1;
        }
        let mut y = rect.y + 1;
        while y < bottom {
            self.set_char(rect.x, y, borders.v, border_style);
            self.set_char(right, y, borders.v, border_style);
            y += 1;
        }
    }

    pub fn draw_gauge(
        &mut self,
        rect: Rect,
        ratio_pct: f32,
        filled: Style,
        empty: Style,
        ascii: bool,
    ) {
        let bounds = Rect::new(0, 0, self.w, self.h);
        let area = rect.intersect(bounds);
        if area.is_empty() {
            return;
        }
        let pct = if ratio_pct.is_nan() || ratio_pct < 0.0 {
            0.0
        } else if ratio_pct > 100.0 {
            100.0
        } else {
            ratio_pct
        };
        if ascii {
            let total = area.w as u32;
            let full = (((pct * (total as f32)) / 100.0) + 0.5) as u32;
            let full_cols = full.min(total) as u16;
            let mut y = area.y;
            while y < area.bottom() {
                let mut col = 0u16;
                while col < area.w {
                    if col < full_cols {
                        self.set_char(area.x + col, y, '#', filled);
                    } else {
                        self.set_char(area.x + col, y, '-', empty);
                    }
                    col += 1;
                }
                y += 1;
            }
            return;
        }
        const EIGHTHS: [char; 8] = [
            ' ', '\u{258f}', '\u{258e}', '\u{258d}', '\u{258c}', '\u{258b}', '\u{258a}', '\u{2589}',
        ];
        let total_eighths = (area.w as u32) * 8;
        let units = (((pct * (total_eighths as f32)) / 100.0) + 0.5) as u32;
        let clamped = units.min(total_eighths);
        let full_cols = (clamped / 8) as u16;
        let rem = (clamped % 8) as usize;
        let partial_style = if filled.bg == Color::Reset {
            filled.bg(empty.bg)
        } else {
            filled
        };
        let mut y = area.y;
        while y < area.bottom() {
            let mut col = 0u16;
            while col < area.w {
                if col < full_cols {
                    self.set_char(area.x + col, y, '\u{2588}', filled);
                } else if col == full_cols && rem > 0 {
                    self.set_char(area.x + col, y, EIGHTHS[rem], partial_style);
                } else {
                    self.set_char(area.x + col, y, '\u{2591}', empty);
                }
                col += 1;
            }
            y += 1;
        }
    }

    #[must_use]
    pub fn row_text(&self, y: u16) -> String {
        if y >= self.h {
            return String::new();
        }
        let mut line = String::with_capacity(self.w as usize);
        let base = (y as usize) * (self.w as usize);
        let row = &self.cells[base..base + (self.w as usize)];
        for cell in row {
            if !cell.continuation {
                line.push(cell.ch);
            }
        }
        let trimmed = line.trim_end_matches(' ').len();
        line.truncate(trimmed);
        line
    }

    #[must_use]
    pub fn dump_plain(&self) -> String {
        let mut out = String::with_capacity(((self.w as usize) + 1) * (self.h as usize));
        let mut y = 0u16;
        while y < self.h {
            if y > 0 {
                out.push('\n');
            }
            let row = self.row_text(y);
            out.push_str(&row);
            y += 1;
        }
        out
    }
}
