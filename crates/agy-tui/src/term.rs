//! POSIX raw-mode terminal controller, event poller, and alt-screen lifecycle.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::ansi::diff_ansi;
use crate::hit::{Frame, HitMap, PointerShape};
use crate::input::{Event, InputParser};
use crate::style::Style;
use crate::surface::Surface;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[cfg(target_os = "macos")]
mod sys {
    #![allow(non_camel_case_types)]
    use core::ffi::{c_int, c_ulong};

    pub type tcflag_t = c_ulong;
    pub type cc_t = u8;
    pub type speed_t = c_ulong;

    pub const NCCS: usize = 20;
    pub const TCSAFLUSH: c_int = 2;
    pub const VMIN: usize = 16;
    pub const VTIME: usize = 17;

    pub const IGNBRK: tcflag_t = 0x0000_0001;
    pub const BRKINT: tcflag_t = 0x0000_0002;
    pub const PARMRK: tcflag_t = 0x0000_0008;
    pub const INPCK: tcflag_t = 0x0000_0010;
    pub const ISTRIP: tcflag_t = 0x0000_0020;
    pub const INLCR: tcflag_t = 0x0000_0040;
    pub const IGNCR: tcflag_t = 0x0000_0080;
    pub const ICRNL: tcflag_t = 0x0000_0100;
    pub const IXON: tcflag_t = 0x0000_0200;

    pub const OPOST: tcflag_t = 0x0000_0001;

    pub const CSIZE: tcflag_t = 0x0000_0300;
    pub const CS8: tcflag_t = 0x0000_0300;
    pub const PARENB: tcflag_t = 0x0000_1000;

    pub const ECHO: tcflag_t = 0x0000_0008;
    pub const ECHONL: tcflag_t = 0x0000_0010;
    pub const ISIG: tcflag_t = 0x0000_0080;
    pub const ICANON: tcflag_t = 0x0000_0100;
    pub const IEXTEN: tcflag_t = 0x0000_0400;

    pub const TIOCGWINSZ: u64 = 0x4008_7468;
    pub const SIGWINCH: c_int = 28;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        pub c_iflag: tcflag_t,
        pub c_oflag: tcflag_t,
        pub c_cflag: tcflag_t,
        pub c_lflag: tcflag_t,
        pub c_cc: [cc_t; NCCS],
        pub c_ispeed: speed_t,
        pub c_ospeed: speed_t,
    }

    unsafe extern "C" {
        pub fn tcgetattr(fd: c_int, termios_p: *mut Termios) -> c_int;
        pub fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const Termios) -> c_int;
    }
}

#[cfg(target_os = "linux")]
mod sys {
    #![allow(non_camel_case_types)]
    use core::ffi::{c_int, c_uint};

    pub type tcflag_t = c_uint;
    pub type cc_t = u8;
    pub type speed_t = c_uint;

    pub const NCCS: usize = 32;
    pub const TCSAFLUSH: c_int = 2;
    pub const VTIME: usize = 5;
    pub const VMIN: usize = 6;

    pub const IGNBRK: tcflag_t = 0x0001;
    pub const BRKINT: tcflag_t = 0x0002;
    pub const PARMRK: tcflag_t = 0x0008;
    pub const INPCK: tcflag_t = 0x0010;
    pub const ISTRIP: tcflag_t = 0x0020;
    pub const INLCR: tcflag_t = 0x0040;
    pub const IGNCR: tcflag_t = 0x0080;
    pub const ICRNL: tcflag_t = 0x0100;
    pub const IXON: tcflag_t = 0x0400;

    pub const OPOST: tcflag_t = 0x0001;

    pub const CSIZE: tcflag_t = 0x0030;
    pub const CS8: tcflag_t = 0x0030;
    pub const PARENB: tcflag_t = 0x0100;

    pub const ISIG: tcflag_t = 0x0001;
    pub const ICANON: tcflag_t = 0x0002;
    pub const ECHO: tcflag_t = 0x0008;
    pub const ECHONL: tcflag_t = 0x0040;
    pub const IEXTEN: tcflag_t = 0x8000;

    pub const TIOCGWINSZ: u64 = 0x5413;
    pub const SIGWINCH: c_int = 28;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        pub c_iflag: tcflag_t,
        pub c_oflag: tcflag_t,
        pub c_cflag: tcflag_t,
        pub c_lflag: tcflag_t,
        pub c_line: cc_t,
        pub c_cc: [cc_t; NCCS],
        pub c_ispeed: speed_t,
        pub c_ospeed: speed_t,
    }

    unsafe extern "C" {
        pub fn tcgetattr(fd: c_int, termios_p: *mut Termios) -> c_int;
        pub fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const Termios) -> c_int;
    }
}

const MOUSE_ON: &[u8] = b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h";
const MOUSE_OFF: &[u8] = b"\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[?1000l";

static WINCH_READ_FD: AtomicI32 = AtomicI32::new(-1);
static WINCH_WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static WINCH_DIRTY: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigwinch(_sig: eko::libc::c_int) {
    WINCH_DIRTY.store(true, Ordering::Relaxed);
    let fd = WINCH_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let b = [1u8];
        unsafe {
            let _ = eko::libc::write(fd, b.as_ptr().cast(), 1);
        }
    }
}

fn install_sigwinch() -> i32 {
    let existing = WINCH_READ_FD.load(Ordering::Acquire);
    if existing >= 0 {
        return existing;
    }
    let mut ends = [0 as eko::libc::c_int; 2];
    if unsafe { eko::libc::pipe(ends.as_mut_ptr()) } != 0 {
        return -1;
    }
    let [rfd, wfd] = ends;
    let _ = eko::file::set_cloexec(rfd, true);
    let _ = eko::file::set_cloexec(wfd, true);
    let _ = eko::file::set_nonblocking(rfd, true);
    let _ = eko::file::set_nonblocking(wfd, true);
    if WINCH_READ_FD
        .compare_exchange(-1, rfd, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        unsafe {
            let _ = eko::libc::close(rfd);
            let _ = eko::libc::close(wfd);
        }
        return WINCH_READ_FD.load(Ordering::Acquire);
    }
    WINCH_WRITE_FD.store(wfd, Ordering::Release);
    let mut act: eko::libc::sigaction = unsafe { core::mem::zeroed() };
    act.sa_sigaction = on_sigwinch as *const () as usize;
    act.sa_flags = eko::libc::SA_RESTART;
    unsafe {
        let _ = eko::libc::sigemptyset(&mut act.sa_mask);
        let _ = eko::libc::sigaction(sys::SIGWINCH, &act, core::ptr::null_mut());
    }
    rfd
}

fn drain_winch(fd: i32) -> bool {
    let mut fired = WINCH_DIRTY.swap(false, Ordering::AcqRel);
    if fd >= 0 {
        let mut buf = [0u8; 32];
        loop {
            let n = unsafe { eko::libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                fired = true;
            } else {
                break;
            }
        }
    }
    fired
}

/// Return `true` when `fd` refers to an interactive terminal device.
#[must_use]
pub fn is_tty(fd: i32) -> bool {
    unsafe { eko::libc::isatty(fd) == 1 }
}

fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<(), eko::Errno> {
    while !bytes.is_empty() {
        let n = unsafe { eko::libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let err = eko::Errno::current();
            if err.interrupted() {
                continue;
            }
            return Err(err);
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

fn make_raw(orig: &sys::Termios) -> sys::Termios {
    let mut raw = *orig;
    raw.c_iflag &= !(sys::IGNBRK
        | sys::BRKINT
        | sys::PARMRK
        | sys::INPCK
        | sys::ISTRIP
        | sys::INLCR
        | sys::IGNCR
        | sys::ICRNL
        | sys::IXON);
    raw.c_oflag &= !sys::OPOST;
    raw.c_lflag &= !(sys::ECHO | sys::ECHONL | sys::ICANON | sys::ISIG | sys::IEXTEN);
    raw.c_cflag &= !(sys::CSIZE | sys::PARENB);
    raw.c_cflag |= sys::CS8;
    raw.c_cc[sys::VMIN] = 0;
    raw.c_cc[sys::VTIME] = 0;
    raw
}

fn set_termios(fd: i32, t: &sys::Termios) -> Result<(), eko::Errno> {
    loop {
        let rc = unsafe { sys::tcsetattr(fd, sys::TCSAFLUSH, t) };
        if rc == 0 {
            return Ok(());
        }
        let err = eko::Errno::current();
        if !err.interrupted() {
            return Err(err);
        }
    }
}

fn query_winsize(out_fd: i32, in_fd: i32, fallback: (u16, u16)) -> (u16, u16) {
    let mut ws = Winsize::default();
    let ptr = (&mut ws as *mut Winsize) as usize;
    if eko::file::ioctl_ptr(out_fd, sys::TIOCGWINSZ, ptr).is_ok() && ws.ws_col > 0 && ws.ws_row > 0
    {
        return (ws.ws_col, ws.ws_row);
    }
    if eko::file::ioctl_ptr(in_fd, sys::TIOCGWINSZ, ptr).is_ok() && ws.ws_col > 0 && ws.ws_row > 0
    {
        return (ws.ws_col, ws.ws_row);
    }
    let cols = eko::env::var("COLUMNS")
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&c| c > 0)
        .unwrap_or(fallback.0);
    let rows = eko::env::var("LINES")
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&r| r > 0)
        .unwrap_or(fallback.1);
    (cols.max(1), rows.max(1))
}

/// Interactive terminal session owning raw mode, alternate screen, and frame diffing.
pub struct Terminal {
    in_fd: i32,
    out_fd: i32,
    orig_termios: sys::Termios,
    raw_active: bool,
    mouse: bool,
    pointer_shapes: bool,
    current_pointer: PointerShape,
    cols: u16,
    rows: u16,
    front: Option<Surface>,
    back: Surface,
    hits: HitMap,
    out_buf: Vec<u8>,
    parser: InputParser,
    signals: eko::signal::Signals,
    winch_fd: i32,
}

impl Terminal {
    pub fn enter(mouse: bool, pointer_shapes: bool) -> Result<Self, eko::Errno> {
        let in_fd = eko::libc::STDIN_FILENO;
        let out_fd = eko::libc::STDOUT_FILENO;
        let mut orig: sys::Termios = unsafe { core::mem::zeroed() };
        if unsafe { sys::tcgetattr(in_fd, &mut orig) } != 0 {
            return Err(eko::Errno::current());
        }
        let signals = eko::signal::Signals::install(&eko::signal::Signal::ALL)?;
        let _ = eko::file::set_cloexec(signals.fd(), true);
        let winch_fd = install_sigwinch();
        let _ = drain_winch(winch_fd);
        let raw = make_raw(&orig);
        set_termios(in_fd, &raw)?;
        let (cols, rows) = query_winsize(out_fd, in_fd, (80, 24));
        let mut init_seq = Vec::with_capacity(64);
        init_seq.extend_from_slice(b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
        if mouse {
            init_seq.extend_from_slice(MOUSE_ON);
        }
        if let Err(err) = write_all_fd(out_fd, &init_seq) {
            let _ = set_termios(in_fd, &orig);
            return Err(err);
        }
        Ok(Self {
            in_fd,
            out_fd,
            orig_termios: orig,
            raw_active: true,
            mouse,
            pointer_shapes,
            current_pointer: PointerShape::Default,
            cols,
            rows,
            front: None,
            back: Surface::new(cols, rows),
            hits: HitMap::new(),
            out_buf: Vec::with_capacity(16 * 1024),
            parser: InputParser::new(),
            signals,
            winch_fd,
        })
    }

    #[must_use]
    pub fn size(&self) -> (u16, u16) {
        query_winsize(self.out_fd, self.in_fd, (self.cols, self.rows))
    }

    pub fn draw<F: FnOnce(&mut Frame<'_>)>(&mut self, ascii: bool, f: F) -> Result<(), eko::Errno> {
        let (w, h) = self.size();
        if w != self.cols || h != self.rows {
            self.cols = w;
            self.rows = h;
            self.front = None;
        }
        if self.back.width() != w || self.back.height() != h {
            self.back.resize(w, h);
        }
        self.back.clear(Style::new());
        self.hits.clear();
        {
            let mut frame = Frame::new(&mut self.back, &mut self.hits, ascii);
            f(&mut frame);
        }
        self.out_buf.clear();
        diff_ansi(self.front.as_ref(), &self.back, true, &mut self.out_buf);
        write_all_fd(self.out_fd, &self.out_buf)?;
        match &mut self.front {
            Some(prev) => prev.clone_from(&self.back),
            None => self.front = Some(self.back.clone()),
        }
        Ok(())
    }

    #[must_use]
    pub fn hits(&self) -> &HitMap {
        &self.hits
    }

    fn read_stdin(&mut self) -> Result<usize, eko::Errno> {
        let mut buf = [0u8; 256];
        let mut total = 0usize;
        loop {
            let n = unsafe { eko::libc::read(self.in_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = eko::Errno::current();
                if err.interrupted() {
                    continue;
                }
                if err.0 == eko::libc::EAGAIN || err.0 == eko::libc::EWOULDBLOCK {
                    break;
                }
                return Err(err);
            }
            if n == 0 {
                break;
            }
            let count = n as usize;
            self.parser.push_bytes(&buf[..count]);
            total += count;
            if count < buf.len() {
                break;
            }
        }
        Ok(total)
    }

    fn check_resize(&mut self) -> Option<Event> {
        if drain_winch(self.winch_fd) {
            let (w, h) = self.size();
            self.cols = w;
            self.rows = h;
            self.front = None;
            return Some(Event::Resize(w, h));
        }
        None
    }

    pub fn poll_event(&mut self, timeout_ms: i32) -> Result<Event, eko::Errno> {
        if let Some(ev) = self.parser.next_event() {
            return Ok(ev);
        }
        if let Some(sig) = self.signals.recv()? {
            return Ok(Event::Signal(sig));
        }
        if let Some(ev) = self.check_resize() {
            return Ok(ev);
        }
        let wait_ms = if self.parser.has_pending() {
            if timeout_ms >= 0 && timeout_ms < 25 {
                timeout_ms
            } else {
                25
            }
        } else {
            timeout_ms
        };
        let mut fds = [
            eko::poll::PollFd {
                fd: self.in_fd,
                events: eko::poll::POLLIN,
                revents: 0,
            },
            eko::poll::PollFd {
                fd: self.signals.fd(),
                events: eko::poll::POLLIN,
                revents: 0,
            },
            eko::poll::PollFd {
                fd: self.winch_fd,
                events: eko::poll::POLLIN,
                revents: 0,
            },
        ];
        let nfds = if self.winch_fd >= 0 { 3 } else { 2 };
        let ready = match eko::poll::poll(&mut fds[..nfds], wait_ms) {
            Ok(n) => n,
            Err(err) if err.interrupted() => {
                if let Some(sig) = self.signals.recv()? {
                    return Ok(Event::Signal(sig));
                }
                if let Some(ev) = self.check_resize() {
                    return Ok(ev);
                }
                return Ok(Event::Tick);
            }
            Err(err) => return Err(err),
        };
        if let Some(sig) = self.signals.recv()? {
            return Ok(Event::Signal(sig));
        }
        if let Some(ev) = self.check_resize() {
            return Ok(ev);
        }
        if (fds[0].revents & eko::poll::POLLIN) != 0 {
            let n = self.read_stdin()?;
            if n == 0 && (fds[0].revents & eko::poll::POLLHUP) != 0 {
                return Err(eko::Errno(eko::libc::EIO));
            }
            if let Some(ev) = self.parser.next_event() {
                return Ok(ev);
            }
            if self.parser.has_pending() {
                let mut esc_fd = [eko::poll::PollFd {
                    fd: self.in_fd,
                    events: eko::poll::POLLIN,
                    revents: 0,
                }];
                if let Ok(k) = eko::poll::poll(&mut esc_fd, 25) {
                    if k > 0 && (esc_fd[0].revents & eko::poll::POLLIN) != 0 {
                        let _ = self.read_stdin()?;
                    }
                }
                if let Some(ev) = self.parser.next_event() {
                    return Ok(ev);
                }
                self.parser.flush_pending();
                if let Some(ev) = self.parser.next_event() {
                    return Ok(ev);
                }
            }
        } else if (fds[0].revents & eko::poll::POLLHUP) != 0 {
            return Err(eko::Errno(eko::libc::EIO));
        }
        if ready == 0 && self.parser.has_pending() {
            self.parser.flush_pending();
            if let Some(ev) = self.parser.next_event() {
                return Ok(ev);
            }
        }
        Ok(Event::Tick)
    }

    pub fn set_pointer(&mut self, shape: PointerShape) -> Result<(), eko::Errno> {
        if !self.pointer_shapes || self.current_pointer == shape {
            return Ok(());
        }
        let mut seq = Vec::with_capacity(24);
        seq.extend_from_slice(b"\x1b]22;");
        seq.extend_from_slice(shape.osc22_name().as_bytes());
        seq.extend_from_slice(b"\x1b\\");
        write_all_fd(self.out_fd, &seq)?;
        self.current_pointer = shape;
        Ok(())
    }

    fn write_leave_sequences(&mut self) -> Result<(), eko::Errno> {
        let mut seq = Vec::with_capacity(64);
        if self.pointer_shapes {
            seq.extend_from_slice(b"\x1b]22;default\x1b\\");
            self.current_pointer = PointerShape::Default;
        }
        if self.mouse {
            seq.extend_from_slice(MOUSE_OFF);
        }
        seq.extend_from_slice(b"\x1b[0m\x1b[?1049l\x1b[?25h");
        write_all_fd(self.out_fd, &seq)
    }

    pub fn suspend_for_child<T, F: FnOnce() -> T>(&mut self, f: F) -> Result<T, eko::Errno> {
        self.write_leave_sequences()?;
        if self.raw_active {
            set_termios(self.in_fd, &self.orig_termios)?;
            self.raw_active = false;
        }
        let out = f();
        let raw = make_raw(&self.orig_termios);
        set_termios(self.in_fd, &raw)?;
        self.raw_active = true;
        let mut seq = Vec::with_capacity(64);
        seq.extend_from_slice(b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
        if self.mouse {
            seq.extend_from_slice(MOUSE_ON);
        }
        write_all_fd(self.out_fd, &seq)?;
        let (w, h) = self.size();
        self.cols = w;
        self.rows = h;
        self.front = None;
        Ok(out)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.write_leave_sequences();
        if self.raw_active {
            let _ = set_termios(self.in_fd, &self.orig_termios);
            self.raw_active = false;
        }
    }
}
