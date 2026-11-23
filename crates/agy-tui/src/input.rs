//! Terminal key, mouse, signal, and streaming escape-sequence parser.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Keyboard and mouse modifier state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Modifiers {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

impl Modifiers {
    pub const NONE: Self = Self {
        ctrl: false,
        alt: false,
        shift: false,
    };
    pub const CTRL: Self = Self {
        ctrl: true,
        alt: false,
        shift: false,
    };
    pub const ALT: Self = Self {
        ctrl: false,
        alt: true,
        shift: false,
    };
    pub const SHIFT: Self = Self {
        ctrl: false,
        alt: false,
        shift: true,
    };

    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.ctrl && !self.alt && !self.shift
    }
}

/// Decoded logical key code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    Char(char),
    Enter,
    Esc,
    Backspace,
    Tab,
    BackTab,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
    F(u8),
}

/// SGR mouse interaction kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MouseKind {
    Down(u8),
    Up(u8),
    Drag(u8),
    Move,
    ScrollUp,
    ScrollDown,
}

/// Decoded mouse event in 0-based cell coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MouseEvent {
    pub kind: MouseKind,
    pub x: u16,
    pub y: u16,
    pub mods: Modifiers,
}

/// Unified terminal loop event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Event {
    Key(Key, Modifiers),
    Mouse(MouseEvent),
    Resize(u16, u16),
    Signal(eko::signal::Signal),
    Tick,
}

/// Streaming byte decoder for UTF-8 keys, CSI/SS3 sequences, and SGR mouse events.
#[derive(Clone, Debug, Default)]
pub struct InputParser {
    buf: Vec<u8>,
    queue: VecDeque<Event>,
}

impl InputParser {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64),
            queue: VecDeque::with_capacity(16),
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.buf.extend_from_slice(bytes);
            self.drain_complete(false);
        }
    }

    pub fn flush_pending(&mut self) {
        self.drain_complete(true);
    }

    pub fn next_event(&mut self) -> Option<Event> {
        self.queue.pop_front()
    }

    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.buf.is_empty()
    }

    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<Event>) {
        self.push_bytes(bytes);
        while let Some(ev) = self.queue.pop_front() {
            out.push(ev);
        }
    }

    pub fn flush_escape(&mut self, out: &mut Vec<Event>) {
        self.flush_pending();
        while let Some(ev) = self.queue.pop_front() {
            out.push(ev);
        }
    }

    fn drain_complete(&mut self, flush: bool) {
        let mut cursor = 0usize;
        while cursor < self.buf.len() {
            match parse_one(&self.buf[cursor..], flush) {
                Some((maybe_ev, used)) => {
                    cursor += used.max(1);
                    if let Some(ev) = maybe_ev {
                        self.queue.push_back(ev);
                    }
                }
                None => break,
            }
        }
        if cursor > 0 {
            self.buf.drain(..cursor);
        }
    }
}

fn parse_one(buf: &[u8], flush: bool) -> Option<(Option<Event>, usize)> {
    let b0 = *buf.first()?;
    if b0 == 0x1B {
        if buf.len() == 1 {
            return if flush {
                Some((Some(Event::Key(Key::Esc, Modifiers::NONE)), 1))
            } else {
                None
            };
        }
        let b1 = buf[1];
        if b1 == 0x1B {
            return Some((Some(Event::Key(Key::Esc, Modifiers::NONE)), 1));
        }
        if b1 == b'[' {
            let limit = buf.len().min(64);
            let mut idx = 2usize;
            while idx < limit {
                let b = buf[idx];
                if (0x40..=0x7E).contains(&b) {
                    return Some((decode_csi(&buf[2..idx], b), idx + 1));
                }
                idx += 1;
            }
            if buf.len() >= 64 {
                return Some((None, limit));
            }
            return if flush {
                if buf.len() == 2 {
                    Some((Some(Event::Key(Key::Char('['), Modifiers::ALT)), 2))
                } else {
                    Some((Some(Event::Key(Key::Esc, Modifiers::NONE)), buf.len()))
                }
            } else {
                None
            };
        }
        if b1 == b'O' {
            if buf.len() < 3 {
                return if flush {
                    Some((Some(Event::Key(Key::Char('O'), Modifiers::ALT)), 2))
                } else {
                    None
                };
            }
            return Some((decode_ss3(buf[2]), 3));
        }
        return match decode_plain_or_ctrl(&buf[1..], flush) {
            Some((Some((key, mut mods)), used)) => {
                mods.alt = true;
                Some((Some(Event::Key(key, mods)), 1 + used))
            }
            Some((None, used)) => Some((None, 1 + used)),
            None => None,
        };
    }
    match decode_plain_or_ctrl(buf, flush) {
        Some((Some((key, mods)), used)) => Some((Some(Event::Key(key, mods)), used)),
        Some((None, used)) => Some((None, used)),
        None => None,
    }
}

fn decode_plain_or_ctrl(buf: &[u8], flush: bool) -> Option<(Option<(Key, Modifiers)>, usize)> {
    let b = *buf.first()?;
    match b {
        b'\r' | b'\n' => Some((Some((Key::Enter, Modifiers::NONE)), 1)),
        b'\t' => Some((Some((Key::Tab, Modifiers::NONE)), 1)),
        0x7F | 0x08 => Some((Some((Key::Backspace, Modifiers::NONE)), 1)),
        0x00 => Some((Some((Key::Char(' '), Modifiers::CTRL)), 1)),
        0x01..=0x1A => {
            let ch = (b - 1 + b'a') as char;
            Some((Some((Key::Char(ch), Modifiers::CTRL)), 1))
        }
        0x1C..=0x1F => {
            let ch = match b {
                0x1C => '\\',
                0x1D => ']',
                0x1E => '^',
                _ => '_',
            };
            Some((Some((Key::Char(ch), Modifiers::CTRL)), 1))
        }
        0x20..=0x7E => Some((Some((Key::Char(b as char), Modifiers::NONE)), 1)),
        0xC2..=0xF4 => {
            let need = if b < 0xE0 {
                2
            } else if b < 0xF0 {
                3
            } else {
                4
            };
            let avail = buf.len().min(need);
            for &cont in &buf[1..avail] {
                if (cont & 0xC0) != 0x80 {
                    return Some((None, 1));
                }
            }
            if buf.len() < need {
                return if flush {
                    Some((None, buf.len()))
                } else {
                    None
                };
            }
            match core::str::from_utf8(&buf[..need]) {
                Ok(s) => {
                    let ch = s.chars().next().unwrap_or('\u{FFFD}');
                    Some((Some((Key::Char(ch), Modifiers::NONE)), need))
                }
                Err(_) => Some((None, 1)),
            }
        }
        _ => Some((None, 1)),
    }
}

fn decode_ss3(final_byte: u8) -> Option<Event> {
    let key = match final_byte {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        b'P' => Key::F(1),
        b'Q' => Key::F(2),
        b'R' => Key::F(3),
        b'S' => Key::F(4),
        _ => return None,
    };
    Some(Event::Key(key, Modifiers::NONE))
}

fn parse_csi_nums(raw: &[u8], out: &mut [u16; 4]) -> usize {
    if raw.is_empty() {
        return 0;
    }
    let mut count = 0usize;
    for part in raw.split(|&b| b == b';') {
        if count >= out.len() {
            break;
        }
        let mut val = 0u16;
        for &d in part {
            if d.is_ascii_digit() {
                val = val.saturating_mul(10).saturating_add((d - b'0') as u16);
            } else {
                return 0;
            }
        }
        out[count] = val;
        count += 1;
    }
    count
}

fn decode_xterm_mods(param: u16) -> Modifiers {
    let bits = param.saturating_sub(1);
    Modifiers {
        shift: (bits & 1) != 0,
        alt: (bits & 2) != 0,
        ctrl: (bits & 4) != 0,
    }
}

fn decode_csi(params: &[u8], final_byte: u8) -> Option<Event> {
    if params.first() == Some(&b'<') && (final_byte == b'M' || final_byte == b'm') {
        let mut nums = [0u16; 4];
        if parse_csi_nums(&params[1..], &mut nums) != 3 {
            return None;
        }
        let cb = nums[0];
        let x = nums[1].saturating_sub(1);
        let y = nums[2].saturating_sub(1);
        let mods = Modifiers {
            shift: (cb & 4) != 0,
            alt: (cb & 8) != 0,
            ctrl: (cb & 16) != 0,
        };
        let btn = (cb & 3) as u8;
        let kind = if (cb & 64) != 0 {
            match btn {
                0 => MouseKind::ScrollUp,
                1 => MouseKind::ScrollDown,
                _ => return None,
            }
        } else if final_byte == b'm' {
            MouseKind::Up(btn)
        } else if (cb & 32) != 0 {
            if btn == 3 {
                MouseKind::Move
            } else {
                MouseKind::Drag(btn)
            }
        } else if btn == 3 {
            MouseKind::Up(0)
        } else {
            MouseKind::Down(btn)
        };
        return Some(Event::Mouse(MouseEvent { kind, x, y, mods }));
    }
    if params.first().map_or(false, |b| matches!(b, b'?' | b'>' | b'=')) {
        return None;
    }
    let mut nums = [0u16; 4];
    let count = parse_csi_nums(params, &mut nums);
    let mods = if count >= 2 {
        decode_xterm_mods(nums[1])
    } else {
        Modifiers::NONE
    };
    let key = match final_byte {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        b'Z' => Key::BackTab,
        b'P' => Key::F(1),
        b'Q' => Key::F(2),
        b'R' => Key::F(3),
        b'S' => Key::F(4),
        b'~' => match nums[0] {
            1 | 7 => Key::Home,
            3 => Key::Delete,
            4 | 8 => Key::End,
            5 => Key::PageUp,
            6 => Key::PageDown,
            11..=15 => Key::F((nums[0] - 10) as u8),
            17..=21 => Key::F((nums[0] - 11) as u8),
            23..=24 => Key::F((nums[0] - 12) as u8),
            _ => return None,
        },
        _ => return None,
    };
    Some(Event::Key(key, mods))
}
