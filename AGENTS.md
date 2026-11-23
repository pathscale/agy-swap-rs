# Working agreement: agy-swap-rs

The operating contract for any coding agent working in this repository. This file is the
single source of truth for repository rules: Codex, Cursor and Gemini CLI read AGENTS.md
natively, and Claude Code loads it through the @AGENTS.md import in CLAUDE.md. Never fork
these rules into a per-vendor file.

## Architecture

- crates/agy-tui: #![no_std] terminal UI engine over ekostd (eko) with zero third-party TUI crates.
- crates/agy-core: #![no_std] core library over ekostd, nagoya, nago-rustls, nago-http, and ps-rustcrypto.
- bins/agy-swap: agy-swap-rs CLI and interactive TUI binary using the clap v4 Builder API (no derive proc-macros).

## Invariants

- std is banned in library crates. Both crates/agy-tui and crates/agy-core carry #![no_std]
  and extern crate alloc; at lib.rs top, with zero std:: paths and zero extern crate std;.
  Import alloc items (Vec, vec, String, ToString, Box, BTreeMap, Cow, format) explicitly in
  every module. Operating system calls go exclusively through ekostd (use eko::...).
- No Python anywhere in scripts, checks, wrappers, or runtime helpers.
- No AI attribution anywhere in commits, PR bodies, comments, or source files.
- No em dashes. Use a spaced hyphen ( - ) in all comments, docs, and user-facing strings.
- Zero inline #[test] functions in src/. Behavioural and end-to-end validation lives under
  bins/agy-swap/tests/ against isolated temporary HOME and configuration directories.
- Never run git stash on a shared checkout; stage and commit only owned paths.
