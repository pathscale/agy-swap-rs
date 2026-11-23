//! Cell color, attribute bitflags, and composable text styles.

use core::ops::{BitOr, BitOrAssign};

/// Foreground or background terminal color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Color {
    #[default]
    Reset,
    Ansi(u8),
    Rgb(u8, u8, u8),
}

/// Compact bitset of SGR character attributes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Attrs(pub u8);

impl Attrs {
    pub const NONE: Self = Self(0);
    pub const BOLD: Self = Self(1 << 0);
    pub const DIM: Self = Self(1 << 1);
    pub const ITALIC: Self = Self(1 << 2);
    pub const UNDERLINE: Self = Self(1 << 3);
    pub const REVERSE: Self = Self(1 << 4);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for Attrs {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl BitOrAssign for Attrs {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Visual style applied to a surface cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Style {
    pub fg: Color,
    pub bg: Color,
    pub attrs: Attrs,
}

impl Style {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fg: Color::Reset,
            bg: Color::Reset,
            attrs: Attrs::NONE,
        }
    }

    #[must_use]
    pub const fn fg(mut self, color: Color) -> Self {
        self.fg = color;
        self
    }

    #[must_use]
    pub const fn bg(mut self, color: Color) -> Self {
        self.bg = color;
        self
    }

    #[must_use]
    pub const fn bold(mut self) -> Self {
        self.attrs = self.attrs.union(Attrs::BOLD);
        self
    }

    #[must_use]
    pub const fn dim(mut self) -> Self {
        self.attrs = self.attrs.union(Attrs::DIM);
        self
    }

    #[must_use]
    pub const fn italic(mut self) -> Self {
        self.attrs = self.attrs.union(Attrs::ITALIC);
        self
    }

    #[must_use]
    pub const fn underline(mut self) -> Self {
        self.attrs = self.attrs.union(Attrs::UNDERLINE);
        self
    }

    #[must_use]
    pub const fn reverse(mut self) -> Self {
        self.attrs = self.attrs.union(Attrs::REVERSE);
        self
    }
}
