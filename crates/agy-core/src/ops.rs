//! Health doctor, statusline renderer/installer, Prometheus metrics, forecasts, and verified CLI updaters.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use eko::command::Command;
use eko::file::File;
use eko::path::Path;
use serde::{Deserialize, Serialize};

use crate::paths::{hex_encode, join_path, sha256_hex, SemVer};
use crate::policy::lookup_account_secret;
use crate::store::atomic_write_private;
use crate::{
    Accounts, Error, HistoryEntry, HttpClient, Paths, PoolQuota, Result, SessionManager, Store,
    Vault, VERSION,
};

const DEFAULT_AGY_INSTALL_BASE_URL: &str =
    "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app";
const DEFAULT_GITHUB_RELEASE_API: &str =
    "https://api.github.com/repos/pathscale/agy-swap-rs/releases/latest";

/// Single installation or security check produced by [`run_doctor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Pool reset and remaining-quota forecast entry produced by [`compute_forecasts`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForecastEntry {
    pub email: String,
    pub pool: String,
    pub remaining_pct: Option<f64>,
    pub reset_at_unix: Option<i64>,
    pub seconds_until_reset: Option<i64>,
    pub confidence: String,
}

/// Aggregated audit log summary produced by [`summarize_history`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryStats {
    pub total_events: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub by_email: BTreeMap<String, usize>,
    pub oldest_unix: Option<i64>,
    pub newest_unix: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AgyManifest {
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha512: String,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    #[serde(default)]
    name: String,
    #[serde(default)]
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    assets: Vec<GithubReleaseAsset>,
}

const SHA512_H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    let mut i = 0usize;
    while i < 16 {
        let off = i * 8;
        w[i] = u64::from_be_bytes([
            block[off],
            block[off + 1],
            block[off + 2],
            block[off + 3],
            block[off + 4],
            block[off + 5],
            block[off + 6],
            block[off + 7],
        ]);
        i += 1;
    }
    while i < 80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
        i += 1;
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    let mut r = 0usize;
    while r < 80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[r])
            .wrapping_add(w[r]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        r += 1;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Compute the 64-byte FIPS 180-4 SHA-512 digest of `data`.
pub fn sha512_bytes(data: &[u8]) -> [u8; 64] {
    let mut state = SHA512_H0;
    let full = data.len() / 128;
    let mut idx = 0usize;
    while idx < full {
        let mut blk = [0u8; 128];
        blk.copy_from_slice(&data[idx * 128..(idx + 1) * 128]);
        sha512_compress(&mut state, &blk);
        idx += 1;
    }
    let rem = &data[full * 128..];
    let mut tail = [0u8; 256];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let bit_len = (data.len() as u128).wrapping_mul(8);
    let pad_len = if rem.len() < 112 { 128 } else { 256 };
    tail[pad_len - 16..pad_len].copy_from_slice(&bit_len.to_be_bytes());

    let mut b0 = [0u8; 128];
    b0.copy_from_slice(&tail[..128]);
    sha512_compress(&mut state, &b0);
    if pad_len == 256 {
        let mut b1 = [0u8; 128];
        b1.copy_from_slice(&tail[128..256]);
        sha512_compress(&mut state, &b1);
    }

    let mut out = [0u8; 64];
    let mut w = 0usize;
    while w < 8 {
        out[w * 8..(w + 1) * 8].copy_from_slice(&state[w].to_be_bytes());
        w += 1;
    }
    out
}

/// Compute the lowercase 128-character hex SHA-512 digest of `data`.
pub fn sha512_hex(data: &[u8]) -> String {
    hex_encode(&sha512_bytes(data))
}

fn is_executable_file(path: &str) -> bool {
    if path.trim().is_empty() || !eko::file::exists(path) {
        return false;
    }
    match eko::file::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.mode() & 0o111) != 0,
        Err(_) => false,
    }
}

/// Locate the installed `agy` binary across environment overrides, `PATH`, and standard user paths.
pub fn locate_agy_binary(paths: &Paths) -> Option<String> {
    if let Some(custom) = eko::env::var("AGY_SWAP_AGY_BIN") {
        let trimmed = custom.trim();
        if is_executable_file(trimmed) {
            return Some(trimmed.to_string());
        }
    }
    if let Some(path_bytes) = eko::env::var_os("PATH") {
        for dir in eko::env::split_paths(&path_bytes) {
            let cand = Path::new(dir).join("agy");
            if let Some(s) = cand.to_str() {
                if is_executable_file(s) {
                    return Some(s.to_string());
                }
            }
        }
    }
    let fallbacks = [
        join_path(&paths.home, ".local/bin/agy"),
        join_path(&paths.home, ".gemini/bin/agy"),
        join_path(&paths.home, "bin/agy"),
        "/opt/homebrew/bin/agy".to_string(),
        "/usr/local/bin/agy".to_string(),
    ];
    fallbacks.into_iter().find(|c| is_executable_file(c))
}

/// Run read-only installation, storage permission, vault, and session health diagnostics.
pub fn run_doctor(
    paths: &Paths,
    store: &Store,
    vault: &Vault,
    session: &SessionManager,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::with_capacity(8);

    // 1. Config directory check.
    if eko::file::exists(&paths.config_dir) {
        match eko::file::metadata(&paths.config_dir) {
            Ok(meta) if meta.is_dir() => {
                let mode = meta.mode() & 0o777;
                let private = (mode & 0o077) == 0;
                checks.push(DoctorCheck {
                    name: "config_dir".to_string(),
                    ok: private,
                    detail: format!("{} (mode {:04o})", paths.config_dir, mode),
                });
            }
            Ok(_) => checks.push(DoctorCheck {
                name: "config_dir".to_string(),
                ok: false,
                detail: format!("{} exists but is not a directory", paths.config_dir),
            }),
            Err(err) => checks.push(DoctorCheck {
                name: "config_dir".to_string(),
                ok: false,
                detail: format!("cannot stat {}: {err}", paths.config_dir),
            }),
        }
    } else {
        checks.push(DoctorCheck {
            name: "config_dir".to_string(),
            ok: true,
            detail: format!("{} (will be created on first write)", paths.config_dir),
        });
    }

    // 2. Settings check.
    match store.load_settings() {
        Ok(s) => checks.push(DoctorCheck {
            name: "settings".to_string(),
            ok: true,
            detail: format!(
                "schema {} - policy {} - switch_mode {}",
                s.schema, s.default_policy, s.switch_mode
            ),
        }),
        Err(err) => checks.push(DoctorCheck {
            name: "settings".to_string(),
            ok: false,
            detail: format!("failed to parse {}: {err}", paths.settings_file),
        }),
    }

    // 3. Accounts & Vault checks.
    match store.load() {
        Ok(accounts) => {
            let legacy_count = accounts
                .order
                .iter()
                .filter_map(|e| accounts.get(e))
                .filter(|a| {
                    a.legacy_token_data
                        .as_deref()
                        .is_some_and(|t| !t.trim().is_empty())
                })
                .count();
            checks.push(DoctorCheck {
                name: "accounts".to_string(),
                ok: legacy_count == 0,
                detail: if legacy_count == 0 {
                    format!("{} saved account(s)", accounts.len())
                } else {
                    format!(
                        "{} saved account(s) - {} inline legacy token(s) need migration",
                        accounts.len(),
                        legacy_count
                    )
                },
            });

            let mut missing_tokens = 0usize;
            for email in &accounts.order {
                if let Some(acc) = accounts.get(email) {
                    if lookup_account_secret(vault, acc).ok().flatten().is_none() {
                        missing_tokens += 1;
                    }
                }
            }
            let vault_perm_ok = if eko::file::exists(&paths.vault_file) {
                eko::file::metadata(&paths.vault_file)
                    .map(|m| (m.mode() & 0o077) == 0)
                    .unwrap_or(false)
            } else {
                true
            };
            checks.push(DoctorCheck {
                name: "vault".to_string(),
                ok: missing_tokens == 0 && vault_perm_ok,
                detail: if !vault_perm_ok {
                    format!("{} has group/world permission bits set", paths.vault_file)
                } else if missing_tokens == 0 {
                    format!("all {} account secret(s) readable", accounts.len())
                } else {
                    format!("{missing_tokens} account(s) missing vault secret")
                },
            });
        }
        Err(err) => {
            checks.push(DoctorCheck {
                name: "accounts".to_string(),
                ok: false,
                detail: format!("failed to load {}: {err}", paths.accounts_file),
            });
        }
    }

    // 4. Active session check.
    let active_email = session.current_email();
    let has_session_tok = session
        .current_token()
        .is_some_and(|t| !t.trim().is_empty());
    let oauth_perm_ok = if eko::file::exists(&paths.agy_oauth_file) {
        eko::file::metadata(&paths.agy_oauth_file)
            .map(|m| (m.mode() & 0o077) == 0)
            .unwrap_or(false)
    } else {
        true
    };
    checks.push(DoctorCheck {
        name: "active_session".to_string(),
        ok: oauth_perm_ok,
        detail: match active_email {
            Some(email) => format!(
                "active={} token_present={} private_mode={}",
                email, has_session_tok, oauth_perm_ok
            ),
            None => "no active session configured".to_string(),
        },
    });

    // 5. Antigravity CLI binary check.
    match locate_agy_binary(paths) {
        Some(bin) => checks.push(DoctorCheck {
            name: "agy_cli".to_string(),
            ok: true,
            detail: format!("found executable at {bin}"),
        }),
        None => checks.push(DoctorCheck {
            name: "agy_cli".to_string(),
            ok: false,
            detail: "agy binary not found in PATH or ~/.local/bin (run 'agy-swap install-agy')"
                .to_string(),
        }),
    }

    // 6. History log check.
    match store.read_history(16) {
        Ok(entries) => checks.push(DoctorCheck {
            name: "history".to_string(),
            ok: true,
            detail: format!("{} recent history event(s) readable", entries.len()),
        }),
        Err(err) => checks.push(DoctorCheck {
            name: "history".to_string(),
            ok: false,
            detail: format!("cannot read {}: {err}", paths.history_file),
        }),
    }

    checks
}

/// Render a compact single-line status segment for shell prompts, tmux, or Starship.
pub fn render_statusline(accounts: &Accounts, active_email: Option<&str>, now_unix: i64) -> String {
    let Some(email) = active_email.filter(|e| !e.trim().is_empty()) else {
        return "agy-swap - idle".to_string();
    };
    let Some(acc) = accounts.get(email) else {
        return format!("agy-swap - {email}");
    };
    if acc.is_cooled_down(None, now_unix) {
        return format!("agy-swap - {email} - cooldown");
    }
    let Some(ref snap) = acc.quota else {
        return format!("agy-swap - {email} - quota unknown");
    };
    let mut parts = vec![format!("agy-swap - {email}")];
    if let Some(gem) = snap.gemini.effective_pct() {
        parts.push(format!("Gem {:.0}%", gem.clamp(0.0, 100.0)));
    }
    if let Some(cg) = snap.claude_gpt.effective_pct() {
        parts.push(format!("C/G {:.0}%", cg.clamp(0.0, 100.0)));
    }
    if parts.len() == 1 {
        parts.push("quota unknown".to_string());
    }
    parts.join(" | ")
}

/// Render a compact statusline from piped JSON telemetry when provided on stdin.
pub fn render_statusline_from_json(raw_json: &str) -> Result<String> {
    let val: serde_json::Value =
        serde_json::from_str(raw_json).map_err(|e| Error::Json(e.to_string()))?;
    let obj = val.as_object();
    let email = obj
        .and_then(|o| {
            o.get("email")
                .or_else(|| o.get("account_email"))
                .or_else(|| o.get("account"))
        })
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pct = obj.and_then(|o| {
        o.get("remaining_pct")
            .or_else(|| o.get("remaining_percent"))
            .or_else(|| o.get("quota_percent"))
            .and_then(|v| v.as_f64())
            .or_else(|| {
                o.get("remaining_fraction")
                    .and_then(|v| v.as_f64())
                    .map(|f| f * 100.0)
            })
    });
    let mut out = String::from("agy-swap");
    if !email.trim().is_empty() {
        out.push_str(" - ");
        out.push_str(email.trim());
    }
    match pct {
        Some(p) if p.is_finite() => {
            out.push_str(&format!(" - quota {:.0}%", p.clamp(0.0, 100.0)));
        }
        _ => out.push_str(" - quota unknown"),
    }
    Ok(out)
}

fn upsert_marked_block(file_path: &str, snippet: &str) -> Result<()> {
    const BEGIN: &str = "# >>> agy-swap statusline >>>";
    const END: &str = "# <<< agy-swap statusline <<<";
    let block = format!("{BEGIN}\n{snippet}\n{END}\n");

    let existing = if eko::file::exists(file_path) {
        eko::file::read_to_string(file_path)?
    } else {
        String::new()
    };

    let updated = if let (Some(start), Some(end)) = (existing.find(BEGIN), existing.find(END)) {
        if start < end {
            let after_end = end + END.len();
            let tail = existing[after_end..]
                .strip_prefix('\n')
                .unwrap_or(&existing[after_end..]);
            format!("{}{}{}", &existing[..start], block, tail)
        } else {
            format!("{existing}\n{block}")
        }
    } else if existing.is_empty() {
        block
    } else if existing.ends_with('\n') {
        format!("{existing}\n{block}")
    } else {
        format!("{existing}\n\n{block}")
    };

    if let Some(parent) = Path::new(file_path).parent().and_then(|p| p.to_str()) {
        if !parent.is_empty() {
            eko::file::create_dir_all(parent)?;
        }
    }
    atomic_write_private(file_path, updated.as_bytes())
}

/// Install an idempotent statusline integration snippet for `starship`, `tmux`, or `zsh`.
pub fn install_statusline(shell_or_tool: &str, paths: &Paths) -> Result<String> {
    let target = shell_or_tool.trim().to_ascii_lowercase();
    let (dest_path, snippet) = match target.as_str() {
        "starship" => (
            join_path(&paths.home, ".config/starship.toml"),
            "[custom.agy_swap]\ncommand = \"agy-swap statusline render\"\nwhen = true\nformat = \"[$output]($style) \"\n",
        ),
        "tmux" => (
            join_path(&paths.home, ".tmux.conf"),
            "set -g status-right \"#(agy-swap statusline render) | %H:%M\"",
        ),
        "zsh" | "" | "default" => (
            join_path(&paths.home, ".zshrc"),
            "agy_swap_prompt() { agy-swap statusline render 2>/dev/null; }",
        ),
        other => {
            return Err(Error::InvalidInput(format!(
                "unsupported statusline target '{other}': expected starship, tmux, or zsh"
            )));
        }
    };

    upsert_marked_block(&dest_path, snippet.trim_end())?;
    let store = Store::new(paths.clone());
    if let Ok(mut settings) = store.load_settings() {
        settings.statusline_installed = true;
        settings.statusline_command = Some("agy-swap statusline render".to_string());
        let _ = store.save_settings(&settings);
    }
    Ok(dest_path)
}

fn escape_prom_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

fn emit_pool_metrics(out: &mut String, acct_id: &str, pool_key: &str, pool: &PoolQuota) {
    let label_pool = escape_prom_label(pool_key);
    if let Some(pct) = pool.five_hour.remaining_pct {
        out.push_str(&format!(
            "agy_swap_quota_remaining{{account_id=\"{acct_id}\",pool=\"{label_pool}\",window=\"5h\"}} {:.2}\n",
            pct.clamp(0.0, 100.0)
        ));
    }
    if let Some(rst) = pool.five_hour.reset_at_unix {
        out.push_str(&format!(
            "agy_swap_quota_reset_unix{{account_id=\"{acct_id}\",pool=\"{label_pool}\",window=\"5h\"}} {rst}\n"
        ));
    }
    if let Some(pct) = pool.weekly.remaining_pct {
        out.push_str(&format!(
            "agy_swap_quota_remaining{{account_id=\"{acct_id}\",pool=\"{label_pool}\",window=\"weekly\"}} {:.2}\n",
            pct.clamp(0.0, 100.0)
        ));
    }
    if let Some(rst) = pool.weekly.reset_at_unix {
        out.push_str(&format!(
            "agy_swap_quota_reset_unix{{account_id=\"{acct_id}\",pool=\"{label_pool}\",window=\"weekly\"}} {rst}\n"
        ));
    }
}

/// Render anonymized Prometheus exposition metrics across all configured accounts.
pub fn render_prometheus_metrics(
    accounts: &Accounts,
    active_email: Option<&str>,
    now_unix: i64,
) -> String {
    let mut out = String::new();
    out.push_str("# HELP agy_swap_up Exporter health indicator.\n");
    out.push_str("# TYPE agy_swap_up gauge\n");
    out.push_str("agy_swap_up 1\n");
    out.push_str("# HELP agy_swap_accounts_total Number of configured accounts.\n");
    out.push_str("# TYPE agy_swap_accounts_total gauge\n");
    out.push_str(&format!("agy_swap_accounts_total {}\n", accounts.len()));

    for email in &accounts.order {
        let Some(acc) = accounts.get(email) else {
            continue;
        };
        let full_hash = sha256_hex(acc.email.to_ascii_lowercase().as_bytes());
        let acct_id = &full_hash[..12];
        let is_active = active_email
            .map(|a| a.eq_ignore_ascii_case(&acc.email))
            .unwrap_or(false);
        out.push_str(&format!(
            "agy_swap_active_account{{account_id=\"{acct_id}\"}} {}\n",
            if is_active { 1 } else { 0 }
        ));
        out.push_str(&format!(
            "agy_swap_account_cooldown{{account_id=\"{acct_id}\"}} {}\n",
            if acc.is_cooled_down(None, now_unix) {
                1
            } else {
                0
            }
        ));
        out.push_str(&format!(
            "agy_swap_account_error{{account_id=\"{acct_id}\"}} {}\n",
            if acc.last_error.is_some() || acc.verify_url.is_some() {
                1
            } else {
                0
            }
        ));
        if let Some(ref snap) = acc.quota {
            emit_pool_metrics(&mut out, acct_id, "gemini", &snap.gemini);
            emit_pool_metrics(&mut out, acct_id, "claude_gpt", &snap.claude_gpt);
            if let Some(ref argon) = snap.argon {
                emit_pool_metrics(&mut out, acct_id, "argon", argon);
            }
            for extra in &snap.extra_pools {
                emit_pool_metrics(&mut out, acct_id, &extra.name, extra);
            }
        }
    }

    out
}

/// Compute reset countdown and confidence forecasts for every pool across `accounts`.
pub fn compute_forecasts(accounts: &Accounts, now_unix: i64) -> Vec<ForecastEntry> {
    let mut out = Vec::new();
    for email in &accounts.order {
        let Some(acc) = accounts.get(email) else {
            continue;
        };
        let Some(ref snap) = acc.quota else {
            out.push(ForecastEntry {
                email: acc.email.clone(),
                pool: "all".to_string(),
                remaining_pct: None,
                reset_at_unix: None,
                seconds_until_reset: None,
                confidence: "unknown".to_string(),
            });
            continue;
        };
        let age = now_unix.saturating_sub(snap.fetched_at_unix);
        for pool in snap.all_pools() {
            let pct = pool.effective_pct();
            let rst = pool.next_reset_unix();
            let secs_until = rst.map(|r| (r - now_unix).max(0));
            let confidence = if pct.is_none() {
                "unknown"
            } else if rst.is_some_and(|r| r <= now_unix) || age > 1800 {
                "stale"
            } else {
                "observed"
            };
            let pool_name = if pool.name.trim().is_empty() {
                "pool".to_string()
            } else {
                pool.name.clone()
            };
            out.push(ForecastEntry {
                email: acc.email.clone(),
                pool: pool_name,
                remaining_pct: pct,
                reset_at_unix: rst,
                seconds_until_reset: secs_until,
                confidence: confidence.to_string(),
            });
        }
    }
    out
}

/// Aggregate event counts by kind and email across `entries`.
pub fn summarize_history(entries: &[HistoryEntry]) -> HistoryStats {
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_email: BTreeMap<String, usize> = BTreeMap::new();
    let mut oldest: Option<i64> = None;
    let mut newest: Option<i64> = None;

    for entry in entries {
        *by_kind.entry(entry.kind.clone()).or_insert(0) += 1;
        if let Some(ref em) = entry.email {
            if !em.is_empty() {
                *by_email.entry(em.clone()).or_insert(0) += 1;
            }
        }
        let ts = entry.timestamp_unix;
        oldest = Some(oldest.map_or(ts, |o| o.min(ts)));
        newest = Some(newest.map_or(ts, |n| n.max(ts)));
    }

    HistoryStats {
        total_events: entries.len(),
        by_kind,
        by_email,
        oldest_unix: oldest,
        newest_unix: newest,
    }
}

fn host_platform_key() -> Result<(&'static str, &'static str)> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok(("darwin", "arm64"))
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Ok(("darwin", "amd64"))
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Ok(("linux", "arm64"))
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok(("linux", "amd64"))
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
    )))]
    {
        Err(Error::InvalidInput(
            "unsupported OS or architecture for binary installer".to_string(),
        ))
    }
}

fn find_extracted_agy_binary(dir: &str) -> Option<String> {
    let entries = eko::fs::read_dir(dir).ok()?;
    for entry in entries {
        let Some(path_str) = entry.to_str() else {
            continue;
        };
        let Ok(meta) = eko::file::symlink_metadata(path_str) else {
            continue;
        };
        if meta.is_dir() {
            if let Some(found) = find_extracted_agy_binary(path_str) {
                return Some(found);
            }
        } else if meta.is_file() {
            let base = entry.file_name().and_then(|p| p.to_str());
            if matches!(base, Some("agy" | "antigravity")) {
                return Some(path_str.to_string());
            }
        }
    }
    None
}

fn write_executable_atomic(dest_path: &str, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = Path::new(dest_path).parent().and_then(|p| p.to_str()) {
        if !parent.is_empty() {
            eko::file::create_dir_all(parent)?;
        }
    }
    let pid = unsafe { eko::libc::getpid() };
    let tmp_path = format!("{dest_path}.tmp.{pid}");
    let mut f = File::create(&tmp_path)?;
    f.set_permissions_mode(0o755)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);

    let src_c = Path::new(&tmp_path).as_c();
    let dst_c = Path::new(dest_path).as_c();
    if unsafe { eko::libc::rename(src_c.as_ptr().cast(), dst_c.as_ptr().cast()) } != 0 {
        let err = eko::Errno::current();
        eko::file::remove_file(&tmp_path);
        return Err(Error::Sys(err));
    }
    Ok(())
}

/// Download, SHA-512 verify, and install the Antigravity CLI (`agy`) into `target_dir` (`~/.local/bin` by default).
pub fn install_agy(http: &HttpClient, paths: &Paths, target_dir: Option<&str>) -> Result<String> {
    let (os_name, arch_name) = host_platform_key()?;
    let platform = format!("{os_name}_{arch_name}");
    let base_url = eko::env::var("AGY_SWAP_AGY_INSTALL_URL")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_AGY_INSTALL_BASE_URL.to_string());
    let manifest_url = format!(
        "{}/manifests/{platform}.json",
        base_url.trim_end_matches('/')
    );

    let resp = http.get(&manifest_url, &[("Accept", "application/json")])?;
    if !resp.is_success() {
        return Err(Error::Network(format!(
            "Antigravity manifest request returned HTTP {}",
            resp.status
        )));
    }
    let manifest: AgyManifest = resp.json()?;
    let expected_sha512 = manifest.sha512.trim().to_ascii_lowercase();
    if manifest.url.trim().is_empty()
        || expected_sha512.len() != 128
        || !expected_sha512.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::InvalidInput(
            "Antigravity manifest is missing a valid URL or 128-hex SHA-512 digest".to_string(),
        ));
    }

    let dl = http.get(manifest.url.trim(), &[])?;
    if !dl.is_success() {
        return Err(Error::Network(format!(
            "Antigravity binary download returned HTTP {}",
            dl.status
        )));
    }
    let actual_sha512 = sha512_hex(&dl.body);
    if actual_sha512 != expected_sha512 {
        return Err(Error::Crypto(format!(
            "Antigravity CLI SHA-512 mismatch: expected {expected_sha512}, got {actual_sha512}"
        )));
    }

    let install_dir = target_dir
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| join_path(&paths.home, ".local/bin"));
    eko::file::create_dir_all(&install_dir)?;
    let dest_bin = join_path(&install_dir, "agy");

    let is_gzip = dl.body.len() >= 2 && dl.body[0] == 0x1f && dl.body[1] == 0x8b;
    if is_gzip || manifest.url.trim().ends_with(".tar.gz") {
        let pid = unsafe { eko::libc::getpid() };
        let work_dir = join_path(&install_dir, &format!(".agy-extract-{pid}"));
        let _ = eko::fs::remove_dir_all(&work_dir);
        eko::file::create_dir_all(&work_dir)?;
        let archive_path = join_path(&work_dir, "agy.tar.gz");
        atomic_write_private(&archive_path, &dl.body)?;

        let tar_out = Command::new("tar")
            .arg("-xzf")
            .arg(&archive_path)
            .arg("-C")
            .arg(&work_dir)
            .output();
        let Some(out) = tar_out else {
            let _ = eko::fs::remove_dir_all(&work_dir);
            return Err(Error::InvalidInput(
                "failed to spawn system tar".to_string(),
            ));
        };
        if !out.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let _ = eko::fs::remove_dir_all(&work_dir);
            return Err(Error::InvalidInput(format!(
                "tar extraction failed (code {}): {stderr}",
                out.code
            )));
        }
        let Some(found_bin) = find_extracted_agy_binary(&work_dir) else {
            let _ = eko::fs::remove_dir_all(&work_dir);
            return Err(Error::NotFound(
                "downloaded archive did not contain an agy or antigravity binary".to_string(),
            ));
        };
        let bin_bytes = eko::file::read(&found_bin)?;
        let _ = eko::fs::remove_dir_all(&work_dir);
        write_executable_atomic(&dest_bin, &bin_bytes)?;
    } else {
        write_executable_atomic(&dest_bin, &dl.body)?;
    }

    Ok(dest_bin)
}

fn find_checksum_for_asset(manifest_text: &str, asset_name: &str) -> Option<String> {
    for line in manifest_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let digest = parts.next()?;
        let raw_name = parts.next()?;
        let clean_name = raw_name.trim_start_matches('*').trim_start_matches("./");
        if clean_name == asset_name
            && digest.len() == 64
            && digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Some(digest.to_ascii_lowercase());
        }
    }
    None
}

/// Check for a newer `agy-swap-rs` GitHub release and atomically self-update when `check_only` is `false`.
pub fn self_update(http: &HttpClient, check_only: bool) -> Result<String> {
    let meta_url = eko::env::var("AGY_SWAP_UPDATE_URL")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_GITHUB_RELEASE_API.to_string());

    let resp = http.get(&meta_url, &[("Accept", "application/vnd.github+json")])?;
    if !resp.is_success() {
        return Err(Error::Network(format!(
            "release metadata request returned HTTP {}",
            resp.status
        )));
    }
    let release: GithubRelease = resp.json()?;
    let remote_ver = SemVer::parse(&release.tag_name)?;
    let local_ver = SemVer::parse(VERSION)?;

    if remote_ver.cmp(&local_ver) != Ordering::Greater {
        return Ok(format!("up to date (v{local_ver})"));
    }
    if check_only {
        return Ok(format!("update available: v{local_ver} -> v{remote_ver}"));
    }

    let (os_name, arch_name) = host_platform_key()?;
    let tag = if release.tag_name.starts_with('v') {
        release.tag_name.clone()
    } else {
        format!("v{}", release.tag_name)
    };
    let wanted_names = [
        format!("agy-swap-rs_{tag}_{os_name}_{arch_name}"),
        format!("agy-swap-rs-{os_name}-{arch_name}"),
    ];

    let checksum_asset = release
        .assets
        .iter()
        .find(|a| a.name == "checksums.txt")
        .ok_or_else(|| Error::NotFound("release is missing checksums.txt".to_string()))?;
    let matched_asset = release
        .assets
        .iter()
        .find(|a| wanted_names.iter().any(|w| w == &a.name))
        .ok_or_else(|| {
            Error::NotFound(format!(
                "no release asset found for {os_name}/{arch_name} in {tag}"
            ))
        })?;

    let cs_resp = http.get(&checksum_asset.browser_download_url, &[])?;
    if !cs_resp.is_success() {
        return Err(Error::Network(format!(
            "checksums.txt download returned HTTP {}",
            cs_resp.status
        )));
    }
    let cs_text = cs_resp.text()?;
    let expected_sha256 =
        find_checksum_for_asset(cs_text, &matched_asset.name).ok_or_else(|| {
            Error::Crypto(format!(
                "checksums.txt does not list SHA-256 for {}",
                matched_asset.name
            ))
        })?;

    let bin_resp = http.get(&matched_asset.browser_download_url, &[])?;
    if !bin_resp.is_success() {
        return Err(Error::Network(format!(
            "binary asset download returned HTTP {}",
            bin_resp.status
        )));
    }
    let actual_sha256 = sha256_hex(&bin_resp.body);
    if actual_sha256 != expected_sha256 {
        return Err(Error::Crypto(format!(
            "SHA-256 mismatch for {}: expected {expected_sha256}, got {actual_sha256}",
            matched_asset.name
        )));
    }

    let exe_bytes = eko::env::current_exe()
        .ok_or_else(|| Error::NotFound("cannot resolve current executable path".to_string()))?;
    let exe_path = core::str::from_utf8(&exe_bytes)
        .map_err(|_| Error::InvalidInput("current executable path is not UTF-8".to_string()))?;

    let bak_path = format!("{exe_path}.bak");
    if eko::file::exists(exe_path) {
        let _ = eko::file::copy(exe_path, &bak_path);
    }
    if let Err(err) = write_executable_atomic(exe_path, &bin_resp.body) {
        if eko::file::exists(&bak_path) {
            let bak_c = Path::new(&bak_path).as_c();
            let exe_c = Path::new(exe_path).as_c();
            unsafe {
                let _ = eko::libc::rename(bak_c.as_ptr().cast(), exe_c.as_ptr().cast());
            }
        }
        return Err(err);
    }
    eko::file::remove_file(&bak_path);

    Ok(format!("updated agy-swap-rs v{local_ver} -> v{remote_ver}"))
}
