use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agy_core::image::{
    classify_failure, compose_prompt, image_info, pick_result, run_kind_str, ImageFormat, RunKind,
};
use agy_core::isolate::{brain_images, run_isolated_agy_capture, Capture};
use agy_core::paths::{sha256_hex, wall_unix_ns};
use clap::ArgMatches;
use serde::Serialize;
use serde_json::Value;

use super::{explicit_account, opt_str, AppContext};

const DEFAULT_DIMENSION: u32 = 1024;
const DEFAULT_WAIT_SECONDS: u64 = 300;
const DEFAULT_PRINT_TIMEOUT: &str = "12m";
const POLL_INTERVAL_SECONDS: u64 = 2;
const RESPONSE_TAIL_MAX_CHARS: usize = 400;

struct WorkDirGuard {
    path: PathBuf,
}

impl WorkDirGuard {
    fn create() -> Result<Self, String> {
        let base = std::env::temp_dir();
        std::fs::create_dir_all(&base)
            .map_err(|e| format!("failed to prepare temp dir {}: {e}", base.display()))?;
        let pid = std::process::id();
        for attempt in 0..64u32 {
            let ns = wall_unix_ns();
            let candidate = base.join(format!("agy-swap-image-{pid}-{ns}-{attempt}"));
            #[allow(unused_mut)]
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&candidate) {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "failed to create temp work dir {}: {err}",
                        candidate.display()
                    ));
                }
            }
        }
        Err("failed to allocate unique temp work dir".to_string())
    }
}

impl Drop for WorkDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Serialize)]
struct ImageReport<'a> {
    status: &'static str,
    out: &'a str,
    requested: String,
    actual: String,
    converted: bool,
    source: String,
    conversation_id: String,
    response_tail: String,
}

fn exit_code_for_kind(kind: &RunKind) -> i32 {
    match kind {
        RunKind::Ok => 0,
        RunKind::QuotaExhausted => 3,
        RunKind::PermissionDenied => 4,
        RunKind::NoImage | RunKind::SizeMismatch | RunKind::AgyFailed => 1,
    }
}

fn emit_report(kind: &RunKind, report: &ImageReport<'_>) -> i32 {
    if let Ok(line) = serde_json::to_string(report) {
        println!("{line}");
    }
    exit_code_for_kind(kind)
}

fn tail_chars(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    let total = trimmed.chars().count();
    if total <= max_chars {
        trimmed.to_string()
    } else {
        trimmed.chars().skip(total - max_chars).collect()
    }
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// A converter on PATH, or in the usual install folders (a launcher's PATH often lacks Homebrew's).
fn find_tool(program: &str) -> Option<PathBuf> {
    find_in_path(program).or_else(|| {
        ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
            .iter()
            .map(|dir| Path::new(dir).join(program))
            .find(|p| is_executable_file(p))
    })
}

fn run_quiet(bin: &Path, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

/// PNG at exactly `w`x`h` with macOS `sips`: convert, scale to cover, centre crop (same result as the ffmpeg path).
fn convert_with_sips(sips: &Path, src: &str, out: &str, sw: u32, sh: u32, w: u32, h: u32) -> bool {
    if sw == 0 || sh == 0 {
        return false;
    }
    let scale = f64::max(f64::from(w) / f64::from(sw), f64::from(h) / f64::from(sh));
    let rw = ((f64::from(sw) * scale).ceil() as u32).max(w).to_string();
    let rh = ((f64::from(sh) * scale).ceil() as u32).max(h).to_string();
    let (ws, hs) = (w.to_string(), h.to_string());
    run_quiet(sips, &["-s", "format", "png", src, "--out", out])
        && run_quiet(sips, &["--resampleHeightWidth", &rh, &rw, out])
        && run_quiet(sips, &["--cropToHeightWidth", &hs, &ws, out])
        && std::fs::read(out)
            .ok()
            .and_then(|b| image_info(&b))
            .is_some_and(|i| i.width == w && i.height == h)
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path_val = eko::env::var("PATH")?;
    for dir in std::env::split_paths(std::ffi::OsStr::new(&path_val)) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(program);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn parse_json_object(raw: &str) -> Option<Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        if val.is_object() {
            return Some(val);
        }
    }
    for line in trimmed.lines().rev() {
        let l = line.trim();
        if l.starts_with('{') && l.ends_with('}') {
            if let Ok(val) = serde_json::from_str::<Value>(l) {
                if val.is_object() {
                    return Some(val);
                }
            }
        }
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            if let Ok(val) = serde_json::from_str::<Value>(&trimmed[start..=end]) {
                if val.is_object() {
                    return Some(val);
                }
            }
        }
    }
    None
}

fn parse_agy_stdout(stdout_raw: &str) -> (String, String) {
    if let Some(val) = parse_json_object(stdout_raw) {
        let conv_id = val
            .get("conversation_id")
            .or_else(|| val.get("conversationId"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let response = val
            .get("response")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| val.get("error").and_then(Value::as_str))
            .or_else(|| {
                val.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
            })
            .or_else(|| val.get("message").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        (conv_id, response)
    } else {
        (String::new(), stdout_raw.trim().to_string())
    }
}

fn parse_dimension(raw: Option<&str>, flag_name: &str) -> Result<u32, String> {
    let Some(s) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(DEFAULT_DIMENSION);
    };
    match s.parse::<u32>() {
        Ok(v) if v > 0 => Ok(v),
        _ => Err(format!(
            "invalid {flag_name} {s:?} (expected positive integer)"
        )),
    }
}

fn parse_wait_seconds(raw: Option<&str>) -> Result<u64, String> {
    let Some(s) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(DEFAULT_WAIT_SECONDS);
    };
    s.parse::<u64>()
        .map_err(|_| format!("invalid --wait-seconds {s:?} (expected non-negative integer)"))
}

pub fn cmd_image(ctx: &AppContext, m: &ArgMatches) -> i32 {
    let Some(sel) = explicit_account(m, "account")
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return ctx.fail_usage(
            "image",
            "--use-account=<slot|alias|email> is required for 'image' (no default account is used)",
        );
    };
    let Some(prompt_brief) = opt_str(m, "prompt")
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return ctx.fail_usage("image", "--prompt must not be empty");
    };
    let Some(out_path) = opt_str(m, "out").map(str::trim).filter(|s| !s.is_empty()) else {
        return ctx.fail_usage("image", "--out must not be empty");
    };
    let width = match parse_dimension(opt_str(m, "width"), "--width") {
        Ok(w) => w,
        Err(err) => return ctx.fail_usage("image", err),
    };
    let height = match parse_dimension(opt_str(m, "height"), "--height") {
        Ok(h) => h,
        Err(err) => return ctx.fail_usage("image", err),
    };
    let wait_seconds = match parse_wait_seconds(opt_str(m, "wait_seconds")) {
        Ok(secs) => secs,
        Err(err) => return ctx.fail_usage("image", err),
    };
    let print_timeout = opt_str(m, "print_timeout")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_PRINT_TIMEOUT);

    let accounts = match ctx.store.load() {
        Ok(a) => a,
        Err(err) => return ctx.fail("image", err),
    };
    let settings = ctx.store.load_settings().unwrap_or_default();
    let Some(email) = ctx.resolve_selector(&accounts, &settings, sel) else {
        return ctx.fail("image", format!("account {sel:?} not found"));
    };

    let work_dir = match WorkDirGuard::create() {
        Ok(g) => g,
        Err(err) => return ctx.fail("image", err),
    };
    let workdir_str = work_dir.path.to_string_lossy().into_owned();

    let mut ref_names: Vec<String> = Vec::new();
    let mut ref_hashes: Vec<String> = Vec::new();
    if let Some(refs) = m.try_get_many::<String>("ref").ok().flatten() {
        for (idx, ref_path) in refs.enumerate() {
            let trimmed_ref = ref_path.trim();
            if trimmed_ref.is_empty() {
                return ctx.fail_usage("image", "--ref path must not be empty");
            }
            let bytes = match std::fs::read(trimmed_ref) {
                Ok(b) => b,
                Err(err) => {
                    return ctx.fail("image", format!("cannot read --ref {trimmed_ref:?}: {err}"));
                }
            };
            ref_hashes.push(sha256_hex(&bytes));

            let raw_name = Path::new(trimmed_ref)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| !n.is_empty() && !n.starts_with('.'))
                .unwrap_or("ref.img");
            let mut dest_name = raw_name.to_string();
            if work_dir.path.join(&dest_name).exists() {
                dest_name = format!("ref_{}_{raw_name}", idx + 1);
            }
            let dest_path = work_dir.path.join(&dest_name);
            if let Err(err) = std::fs::write(&dest_path, &bytes) {
                return ctx.fail(
                    "image",
                    format!("cannot stage --ref into {}: {err}", dest_path.display()),
                );
            }
            ref_names.push(dest_name);
        }
    }

    let out_file_name = Path::new(out_path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("output.png");
    let requested = format!("{width}x{height}");
    let composed = compose_prompt(prompt_brief, width, height, out_file_name, &ref_names);
    // The terminal sandbox: an image run needs no shell, so commands stay fenced in.
    let mut agy_args = vec!["--sandbox".to_string()];
    if let Some(model) = opt_str(m, "model").map(str::trim).filter(|s| !s.is_empty()) {
        agy_args.push("--model".to_string());
        agy_args.push(model.to_string());
    }
    agy_args.extend([
        "--print-timeout".to_string(),
        print_timeout.to_string(),
        "--output-format".to_string(),
        "json".to_string(),
        "--add-dir".to_string(),
        workdir_str.clone(),
        "--print".to_string(),
        composed,
    ]);

    let stdout_file = work_dir.path.join(".agy-stdout.json");
    let stderr_file = work_dir.path.join(".agy-stderr.log");
    let stdout_path = stdout_file.to_string_lossy().into_owned();
    let stderr_path = stderr_file.to_string_lossy().into_owned();

    let started_ns = wall_unix_ns();
    let (exit_code, overlay_home) = match run_isolated_agy_capture(
        &ctx.paths,
        &ctx.store,
        &ctx.vault,
        &email,
        &agy_args,
        &Capture {
            cwd: &workdir_str,
            stdout_path: &stdout_path,
            stderr_path: &stderr_path,
        },
    ) {
        Ok(pair) => pair,
        Err(err) => {
            let kind = RunKind::AgyFailed;
            let report = ImageReport {
                status: run_kind_str(&kind),
                out: out_path,
                requested,
                actual: String::new(),
                converted: false,
                source: String::new(),
                conversation_id: String::new(),
                response_tail: tail_chars(&err.to_string(), RESPONSE_TAIL_MAX_CHARS),
            };
            return emit_report(&kind, &report);
        }
    };

    let stdout_raw = std::fs::read(&stdout_file)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let stderr_raw = std::fs::read(&stderr_file)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let (conversation_id, response) = parse_agy_stdout(&stdout_raw);
    let response_tail = if !response.trim().is_empty() {
        tail_chars(&response, RESPONSE_TAIL_MAX_CHARS)
    } else {
        tail_chars(&stderr_raw, RESPONSE_TAIL_MAX_CHARS)
    };

    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    let mut hash_cache: BTreeMap<(String, i64), String> = BTreeMap::new();
    let mut picked_source: Option<String> = None;

    loop {
        let raw_imgs = brain_images(&overlay_home);
        let mut cands: Vec<(String, i64, String, bool)> = Vec::with_capacity(raw_imgs.len());
        for (path, mtime_ns, conv_id) in raw_imgs {
            let key = (path.clone(), mtime_ns);
            let hash = if let Some(cached) = hash_cache.get(&key) {
                cached.clone()
            } else {
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                if bytes.is_empty() {
                    continue;
                }
                let h = sha256_hex(&bytes);
                hash_cache.insert(key, h.clone());
                h
            };
            let in_print_conv = !conversation_id.is_empty() && conv_id == conversation_id;
            cands.push((path, mtime_ns, hash, in_print_conv));
        }

        if let Some(idx) = pick_result(&cands, started_ns, &ref_hashes) {
            picked_source = Some(cands[idx].0.clone());
            break;
        }

        if matches!(
            classify_failure(&response, &stderr_raw, exit_code),
            RunKind::QuotaExhausted
        ) {
            break;
        }

        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let rem = deadline.duration_since(now);
        std::thread::sleep(rem.min(Duration::from_secs(POLL_INTERVAL_SECONDS)));
    }

    let Some(source_path) = picked_source else {
        let kind = classify_failure(&response, &stderr_raw, exit_code);
        ctx.record_history("image", Some(&email), run_kind_str(&kind));
        let report = ImageReport {
            status: run_kind_str(&kind),
            out: out_path,
            requested,
            actual: String::new(),
            converted: false,
            source: String::new(),
            conversation_id,
            response_tail,
        };
        return emit_report(&kind, &report);
    };

    let src_bytes = match std::fs::read(&source_path) {
        Ok(b) => b,
        Err(err) => {
            let kind = RunKind::NoImage;
            let report = ImageReport {
                status: run_kind_str(&kind),
                out: out_path,
                requested,
                actual: String::new(),
                converted: false,
                source: source_path,
                conversation_id,
                response_tail: tail_chars(
                    &format!("failed to read generated image: {err}"),
                    RESPONSE_TAIL_MAX_CHARS,
                ),
            };
            return emit_report(&kind, &report);
        }
    };

    let out_p = Path::new(out_path);
    if let Some(parent) = out_p.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                return ctx.fail(
                    "image",
                    format!("cannot create parent directory {}: {err}", parent.display()),
                );
            }
        }
    }
    if let Err(err) = std::fs::write(out_p, &src_bytes) {
        return ctx.fail("image", format!("cannot write {out_path:?}: {err}"));
    }

    let src_info = image_info(&src_bytes);
    let needs_convert = match &src_info {
        Some(info) => {
            !matches!(info.format, ImageFormat::Png) || info.width != width || info.height != height
        }
        None => true,
    };

    let mut converted = false;
    if needs_convert {
        if let Some(ffmpeg_bin) = find_tool("ffmpeg") {
            let vf = format!(
                "scale={width}:{height}:force_original_aspect_ratio=increase,crop={width}:{height}"
            );
            let status_ok = Command::new(&ffmpeg_bin)
                .args([
                    "-y",
                    "-v",
                    "error",
                    "-i",
                    &source_path,
                    "-vf",
                    &vf,
                    out_path,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|st| st.success())
                .unwrap_or(false);
            if status_ok {
                if let Ok(conv_bytes) = std::fs::read(out_p) {
                    if image_info(&conv_bytes).is_some() {
                        converted = true;
                    } else {
                        let _ = std::fs::write(out_p, &src_bytes);
                    }
                } else {
                    let _ = std::fs::write(out_p, &src_bytes);
                }
            } else {
                let _ = std::fs::write(out_p, &src_bytes);
            }
        }
    }

    if needs_convert && !converted {
        if let (Some(sips), Some(info)) = (find_tool("sips"), src_info) {
            converted = convert_with_sips(
                &sips,
                &source_path,
                out_path,
                info.width,
                info.height,
                width,
                height,
            );
            if !converted {
                let _ = std::fs::write(out_p, &src_bytes);
            }
        }
    }

    let final_bytes = std::fs::read(out_p).unwrap_or(src_bytes);
    let (kind, actual) = match image_info(&final_bytes) {
        Some(info) => {
            let act = format!("{}x{}", info.width, info.height);
            let k = if info.width == width && info.height == height {
                RunKind::Ok
            } else {
                RunKind::SizeMismatch
            };
            (k, act)
        }
        None => (RunKind::NoImage, String::new()),
    };

    ctx.record_history("image", Some(&email), run_kind_str(&kind));
    let report = ImageReport {
        status: run_kind_str(&kind),
        out: out_path,
        requested,
        actual,
        converted,
        source: source_path,
        conversation_id,
        response_tail,
    };
    emit_report(&kind, &report)
}
