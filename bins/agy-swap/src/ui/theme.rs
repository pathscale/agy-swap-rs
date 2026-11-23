use agy_core::Badge;
use agy_tui::{Attrs, BorderSet, Color, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Mono,
    Ansi16,
    Ansi256,
    TrueColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolTone {
    Gemini,
    ClaudeGpt,
    Argon,
    Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiEnv {
    pub color_mode: ColorMode,
    pub ascii: bool,
    pub reduced_motion: bool,
    pub mouse: bool,
    pub pointer_shapes: bool,
}

fn eq_ignore_ascii(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b)
}

fn contains_ignore_ascii(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    if n.len() > h.len() {
        return false;
    }
    let mut i = 0usize;
    while i + n.len() <= h.len() {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return true;
        }
        i += 1;
    }
    false
}

fn env_is_truthy(name: &str) -> bool {
    match eko::env::var(name) {
        Some(v) => {
            let t = v.trim();
            eq_ignore_ascii(t, "1")
                || eq_ignore_ascii(t, "true")
                || eq_ignore_ascii(t, "yes")
                || eq_ignore_ascii(t, "on")
        }
        None => false,
    }
}

fn env_is_falsy(name: &str) -> bool {
    match eko::env::var(name) {
        Some(v) => {
            let t = v.trim();
            eq_ignore_ascii(t, "0")
                || eq_ignore_ascii(t, "false")
                || eq_ignore_ascii(t, "no")
                || eq_ignore_ascii(t, "off")
        }
        None => false,
    }
}

impl UiEnv {
    pub fn detect(force_ascii: bool) -> Self {
        let no_color = eko::env::var("NO_COLOR").map(|v| !v.is_empty()).unwrap_or(false);
        let term = eko::env::var("TERM").unwrap_or_default();
        let colorterm = eko::env::var("COLORTERM").unwrap_or_default();
        let color_mode = if no_color || eq_ignore_ascii(&term, "dumb") {
            ColorMode::Mono
        } else if eq_ignore_ascii(&colorterm, "truecolor")
            || eq_ignore_ascii(&colorterm, "24bit")
            || contains_ignore_ascii(&term, "ghostty")
            || contains_ignore_ascii(&term, "alacritty")
            || contains_ignore_ascii(&term, "kitty")
            || contains_ignore_ascii(&term, "iterm")
            || contains_ignore_ascii(&term, "wezterm")
            || contains_ignore_ascii(&term, "truecolor")
        {
            ColorMode::TrueColor
        } else if contains_ignore_ascii(&term, "256color") {
            ColorMode::Ansi256
        } else {
            ColorMode::Ansi16
        };
        let ascii = force_ascii || env_is_truthy("AGY_SWAP_ASCII");
        let reduced_motion = env_is_truthy("AGY_SWAP_REDUCED_MOTION");
        let mouse = !env_is_falsy("AGY_SWAP_MOUSE");
        let pointer_shapes =
            mouse && color_mode != ColorMode::Mono && !env_is_falsy("AGY_SWAP_POINTER_SHAPES");
        Self { color_mode, ascii, reduced_motion, mouse, pointer_shapes }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub env: UiEnv,
    pub body: Style,
    pub header_bar: Style,
    pub footer_bar: Style,
    pub title: Style,
    pub subtitle: Style,
    pub muted: Style,
    pub text: Style,
    pub text_bold: Style,
    pub tab_active: Style,
    pub tab_inactive: Style,
    pub panel_border: Style,
    pub panel_bg: Style,
    pub divider: Style,
    pub divider_hover: Style,
    pub divider_drag: Style,
    pub row_selected: Style,
    pub row_hover: Style,
    pub active_dot: Style,
    pub active_name: Style,
    pub keycap: Style,
    pub keycap_active: Style,
    pub keycap_desc: Style,
    pub backdrop: Style,
    pub modal_border: Style,
    pub modal_bg: Style,
    pub modal_title: Style,
    pub btn_confirm: Style,
    pub btn_danger: Style,
    pub btn_idle: Style,
    pub gauge_track: Style,
    pub pool_gem: Style,
    pub pool_cg: Style,
    pub pool_argon: Style,
    pub pool_extra: Style,
    pub badge_ready: Style,
    pub badge_low: Style,
    pub badge_critical: Style,
    pub badge_limited: Style,
    pub badge_gem_only: Style,
    pub badge_cg_only: Style,
    pub badge_no_token: Style,
    pub badge_verify: Style,
    pub banner_warn: Style,
    pub banner_error: Style,
    pub banner_success: Style,
    pub banner_info: Style,
}

const fn fg_color(mode: ColorMode, rgb: (u8, u8, u8), c256: u8, c16: u8) -> Color {
    match mode {
        ColorMode::Mono => Color::Reset,
        ColorMode::Ansi16 => Color::Ansi(c16),
        ColorMode::Ansi256 => Color::Ansi(c256),
        ColorMode::TrueColor => Color::Rgb(rgb.0, rgb.1, rgb.2),
    }
}

const fn bg_color(mode: ColorMode, rgb: (u8, u8, u8), c256: u8) -> Color {
    match mode {
        ColorMode::Mono | ColorMode::Ansi16 => Color::Reset,
        ColorMode::Ansi256 => Color::Ansi(c256),
        ColorMode::TrueColor => Color::Rgb(rgb.0, rgb.1, rgb.2),
    }
}

impl Theme {
    pub fn detect(force_ascii: bool) -> Self {
        Self::from_env(UiEnv::detect(force_ascii))
    }

    pub fn from_env(env: UiEnv) -> Self {
        let m = env.color_mode;
        let body_bg = bg_color(m, (10, 12, 16), 232);
        let bar_bg = bg_color(m, (28, 33, 40), 234);
        let panel_bg_c = bg_color(m, (22, 27, 34), 234);
        let sel_bg = bg_color(m, (45, 51, 59), 236);
        let hov_bg = bg_color(m, (30, 36, 44), 235);
        let key_bg = bg_color(m, (55, 62, 71), 238);
        let modal_bg_c = bg_color(m, (18, 22, 28), 233);

        let white = fg_color(m, (240, 246, 252), 255, 15);
        let gray = fg_color(m, (139, 148, 158), 244, 7);
        let dim_gray = fg_color(m, (84, 93, 104), 240, 8);
        let track = fg_color(m, (55, 62, 71), 238, 8);
        let green = fg_color(m, (52, 211, 153), 78, 10);
        let amber = fg_color(m, (251, 191, 36), 220, 11);
        let red = fg_color(m, (248, 113, 113), 203, 9);
        let blue = fg_color(m, (56, 189, 248), 75, 12);
        let orange = fg_color(m, (255, 137, 26), 208, 14);
        let cyan = fg_color(m, (34, 211, 238), 86, 14);
        let violet = fg_color(m, (192, 132, 252), 177, 13);
        let magenta = fg_color(m, (232, 121, 249), 213, 13);

        let row_selected = if m == ColorMode::Mono || m == ColorMode::Ansi16 {
            Style::new().fg(white).bold().reverse()
        } else {
            Style::new().fg(white).bg(sel_bg).bold()
        };
        let row_hover = if m == ColorMode::Mono || m == ColorMode::Ansi16 {
            Style::new().fg(white).underline()
        } else {
            Style::new().fg(white).bg(hov_bg)
        };
        let keycap = if m == ColorMode::Mono || m == ColorMode::Ansi16 {
            Style::new().fg(white).bold().reverse()
        } else {
            Style::new().fg(white).bg(key_bg).bold()
        };
        let keycap_active = if m == ColorMode::Mono {
            Style::new().bold().underline()
        } else {
            Style::new().fg(orange).bg(sel_bg).bold()
        };

        Self {
            env,
            body: Style::new().fg(white).bg(body_bg),
            header_bar: Style::new().fg(white).bg(bar_bg),
            footer_bar: Style::new().fg(gray).bg(bar_bg),
            title: Style::new().fg(orange).bg(bar_bg).bold(),
            subtitle: Style::new().fg(gray).bg(bar_bg),
            muted: Style::new().fg(gray).bg(body_bg),
            text: Style::new().fg(white).bg(body_bg),
            text_bold: Style::new().fg(white).bg(body_bg).bold(),
            tab_active: Style::new().fg(orange).bg(bar_bg).bold().underline(),
            tab_inactive: Style::new().fg(gray).bg(bar_bg),
            panel_border: Style::new().fg(dim_gray).bg(panel_bg_c),
            panel_bg: Style::new().fg(white).bg(panel_bg_c),
            divider: Style::new().fg(track).bg(body_bg),
            divider_hover: Style::new().fg(gray).bg(body_bg).bold(),
            divider_drag: Style::new().fg(orange).bg(body_bg).bold(),
            row_selected,
            row_hover,
            active_dot: Style::new().fg(green).bg(body_bg).bold(),
            active_name: Style::new().fg(green).bg(body_bg).bold(),
            keycap,
            keycap_active,
            keycap_desc: Style::new().fg(gray).bg(bar_bg),
            backdrop: Style::new().fg(dim_gray).bg(body_bg).dim(),
            modal_border: Style::new().fg(blue).bg(modal_bg_c).bold(),
            modal_bg: Style::new().fg(white).bg(modal_bg_c),
            modal_title: Style::new().fg(orange).bg(modal_bg_c).bold(),
            btn_confirm: if m == ColorMode::Mono {
                Style::new().bold().reverse()
            } else {
                Style::new().fg(orange).bg(sel_bg).bold()
            },
            btn_danger: if m == ColorMode::Mono {
                Style::new().bold().reverse()
            } else {
                Style::new().fg(red).bg(sel_bg).bold()
            },
            btn_idle: Style::new().fg(gray).bg(modal_bg_c),
            gauge_track: Style::new().fg(track).bg(panel_bg_c),
            pool_gem: Style::new().fg(blue).bg(panel_bg_c).bold(),
            pool_cg: Style::new().fg(orange).bg(panel_bg_c).bold(),
            pool_argon: Style::new().fg(violet).bg(panel_bg_c).bold(),
            pool_extra: Style::new().fg(cyan).bg(panel_bg_c).bold(),
            badge_ready: Style::new().fg(green).bg(body_bg).bold(),
            badge_low: Style::new().fg(amber).bg(body_bg).bold(),
            badge_critical: Style::new().fg(red).bg(body_bg).bold(),
            badge_limited: Style::new().fg(red).bg(body_bg).bold(),
            badge_gem_only: Style::new().fg(blue).bg(body_bg).bold(),
            badge_cg_only: Style::new().fg(orange).bg(body_bg).bold(),
            badge_no_token: Style::new().fg(dim_gray).bg(body_bg).dim(),
            badge_verify: Style::new().fg(magenta).bg(body_bg).bold(),
            banner_warn: Style::new().fg(amber).bg(bar_bg).bold(),
            banner_error: Style::new().fg(red).bg(bar_bg).bold(),
            banner_success: Style::new().fg(green).bg(bar_bg).bold(),
            banner_info: Style::new().fg(cyan).bg(bar_bg),
        }
    }

    pub const fn borders(&self) -> BorderSet {
        if self.env.ascii {
            BorderSet::ASCII
        } else {
            BorderSet::ROUNDED
        }
    }

    pub const fn badge_label(badge: Badge) -> &'static str {
        match badge {
            Badge::Ready => "READY",
            Badge::Low => "LOW",
            Badge::Critical => "CRITICAL",
            Badge::GeminiOnly => "GEMINI ONLY",
            Badge::ClaudeGptOnly => "CLAUDE/GPT ONLY",
            Badge::Limited => "LIMITED",
            Badge::NoToken => "NO TOKEN",
            Badge::Verify => "VERIFY",
        }
    }

    pub const fn badge_compact_label(badge: Badge) -> &'static str {
        match badge {
            Badge::Ready => "READY",
            Badge::Low => "LOW",
            Badge::Critical => "CRIT",
            Badge::GeminiOnly => "GEM ONLY",
            Badge::ClaudeGptOnly => "C/G ONLY",
            Badge::Limited => "LIMITED",
            Badge::NoToken => "NO TOKEN",
            Badge::Verify => "VERIFY",
        }
    }

    pub const fn badge_style(&self, badge: Badge) -> Style {
        match badge {
            Badge::Ready => self.badge_ready,
            Badge::Low => self.badge_low,
            Badge::Critical => self.badge_critical,
            Badge::GeminiOnly => self.badge_gem_only,
            Badge::ClaudeGptOnly => self.badge_cg_only,
            Badge::Limited => self.badge_limited,
            Badge::NoToken => self.badge_no_token,
            Badge::Verify => self.badge_verify,
        }
    }

    pub fn pool_gauge_style(&self, tone: PoolTone, pct: f64) -> Style {
        let base = match tone {
            PoolTone::Gemini => self.pool_gem,
            PoolTone::ClaudeGpt => self.pool_cg,
            PoolTone::Argon => self.pool_argon,
            PoolTone::Extra => self.pool_extra,
        };
        if pct <= 10.0 {
            Style { fg: self.badge_critical.fg, bg: base.bg, attrs: base.attrs }
        } else if pct <= 30.0 {
            Style { fg: self.badge_low.fg, bg: base.bg, attrs: base.attrs }
        } else {
            base
        }
    }

    pub const fn on_row(&self, style: Style, selected: bool, hovered: bool) -> Style {
        if selected {
            if matches!(self.env.color_mode, ColorMode::Mono | ColorMode::Ansi16) {
                Style { fg: style.fg, bg: style.bg, attrs: style.attrs.union(Attrs::REVERSE) }
            } else {
                Style { fg: style.fg, bg: self.row_selected.bg, attrs: style.attrs }
            }
        } else if hovered {
            if matches!(self.env.color_mode, ColorMode::Mono | ColorMode::Ansi16) {
                Style { fg: style.fg, bg: style.bg, attrs: style.attrs.union(Attrs::UNDERLINE) }
            } else {
                Style { fg: style.fg, bg: self.row_hover.bg, attrs: style.attrs }
            }
        } else {
            style
        }
    }
}
