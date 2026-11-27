# agy-swap-rs

Multi-account quota operator deck, isolated concurrent CLI wrapper (`--use-account`), and explicit session switcher for Antigravity (`agy`).

Built over [ekostd](https://github.com/pathscale/ekostd), [nagoya](https://github.com/pathscale/nagoya), [nago-rustls](https://github.com/pathscale/nago-rustls), [nago-http](https://github.com/pathscale/nago-http), and `ps-rustcrypto`. No `tokio`, no `openssl`, no C dependencies, and zero third-party TUI crates (`crates/agy-tui` and `crates/agy-core` are `#![no_std]`).

## Install

```sh
cargo install agy-swap-rs
```

## Quick Start

Import your active `~/.gemini` session into Slot 1 without touching `~/.gemini`:

```sh
agy-swap-rs import-current
```

Add additional Google accounts via local OAuth 2.0 + S256 PKCE account-chooser login:

```sh
agy-swap-rs add
```

Open the interactive multi-account operator deck (live quota matrix, 5-hour and weekly reset windows, isolated session indicators):

```sh
agy-swap-rs
```

Run concurrent isolated `agy` sessions without mutating `~/.gemini` or interfering with other running sessions:

```sh
agy-swap-rs --use-account=1 -p "summarize changes"
agy-swap-rs --use-account=2 -p "run review"
```

Check cached or live quota pools from the CLI:

```sh
agy-swap-rs limits
agy-swap-rs limits --refresh
```

## Image generation

Generate an image in an account's isolated overlay `HOME` without touching `~/.gemini` (polling the brain directory, converting/cropping to PNG via `ffmpeg` when available, and printing a single-line JSON report):

```sh
agy-swap-rs --use-account=1 image --prompt "isometric blueprint of a coastal lighthouse at dusk" --out ./lighthouse.png --width 1280 --height 720
```

## Session Isolation & `~/.gemini` Boundary

- All `agy-swap-rs` metadata, encrypted/vault secrets, audit history, and per-account overlay homes live strictly under `~/.config/agy-swap-rs` (`0700` directories, `0600` files).
- Every CLI invocation that executes `agy` or targets a single account requires `--use-account=<slot|alias|email>` explicitly (exiting with code `2` if omitted) so a default account is never hammered by mistake.
- Isolated `--use-account=` sessions materialize a private per-account `HOME` under `~/.config/agy-swap-rs/homes/<slug>/` with zero writable symlinks into `~/.gemini`, then harvest refreshed OAuth tokens back into the vault on exit.
- Your global `~/.gemini` session is never modified unless you explicitly run `agy-swap-rs switch --use-account=<target>` or confirm `[ Switch IDE ]` in the TUI (restart the IDE afterward to apply).

## Workspace Layout

- `crates/agy-tui`: `#![no_std]` double-buffered `Surface`, immediate-mode `Frame`, inline `HitMap` mouse regions, and `DECSET 2026` synchronized ANSI diff renderer over `ekostd`.
- `crates/agy-core`: `#![no_std]` account store, OS keychain + `0600` file vault, OAuth PKCE loopback, Cloud Code Assist quota client, AES-256-GCM + PBKDF2-HMAC-SHA256 backups, log-tail failover, and isolated overlay homes.
- `bins/agy-swap`: `agy-swap-rs` binary (`clap` Builder API, interactive TUI views, and end-to-end test suite).

## License

MIT or Apache-2.0, at your option.
