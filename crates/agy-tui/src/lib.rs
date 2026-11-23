//! Terminal rendering, layout, hit-testing, and raw input engine.

#![no_std]

extern crate alloc;

pub mod ansi;
pub mod hit;
pub mod input;
pub mod layout;
pub mod style;
pub mod surface;
pub mod term;

pub use ansi::diff_ansi;
pub use hit::{Frame, HitId, HitMap, PointerShape};
pub use input::{Event, InputParser, Key, Modifiers, MouseEvent, MouseKind};
pub use layout::{centered_rect, split_h, split_v, Breakpoint, Constraint, Rect};
pub use style::{Attrs, Color, Style};
pub use surface::{char_width, display_width, BorderSet, Cell, Surface};
pub use term::{is_tty, Terminal};
