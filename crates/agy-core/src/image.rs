//! Pure image header inspection, size-locked prompt composition, failure classification, and result selection.

#[allow(unused_imports)]
use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    Png,
    Jpeg,
    Webp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ImageInfo {
    pub width: u32,
    pub height: u32,
    pub format: ImageFormat,
}

/// Width, height and format from the file header bytes (PNG IHDR, JPEG SOFn, WebP VP8/VP8L/VP8X). None if unknown.
#[must_use]
pub fn image_info(bytes: &[u8]) -> Option<ImageInfo> {
    if let Some(info) = parse_png(bytes) {
        return Some(info);
    }
    if let Some(info) = parse_jpeg(bytes) {
        return Some(info);
    }
    if let Some(info) = parse_webp(bytes) {
        return Some(info);
    }
    None
}

fn parse_png(bytes: &[u8]) -> Option<ImageInfo> {
    const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if bytes.len() < 24 || bytes[..8] != PNG_SIG {
        return None;
    }

    let mut pos = 8usize;
    while pos.checked_add(16)? <= bytes.len() {
        let chunk_len =
            u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        let chunk_type = &bytes[pos + 4..pos + 8];
        if chunk_type == b"IHDR" {
            if chunk_len < 8 {
                return None;
            }
            let width = u32::from_be_bytes([
                bytes[pos + 8],
                bytes[pos + 9],
                bytes[pos + 10],
                bytes[pos + 11],
            ]);
            let height = u32::from_be_bytes([
                bytes[pos + 12],
                bytes[pos + 13],
                bytes[pos + 14],
                bytes[pos + 15],
            ]);
            if width == 0 || height == 0 {
                return None;
            }
            return Some(ImageInfo {
                width,
                height,
                format: ImageFormat::Png,
            });
        }
        if chunk_type == b"CgBI" {
            pos = pos.checked_add(12)?.checked_add(chunk_len)?;
            continue;
        }
        return None;
    }
    None
}

fn parse_jpeg(bytes: &[u8]) -> Option<ImageInfo> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None;
    }

    let mut pos = 2usize;
    while pos < bytes.len() {
        if bytes[pos] != 0xFF {
            return None;
        }
        while pos < bytes.len() && bytes[pos] == 0xFF {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
        let marker = bytes[pos];
        pos += 1;

        match marker {
            0x00 | 0xD9 => return None,
            0xD8 | 0x01 | 0xD0..=0xD7 => continue,
            0xC0..=0xCF if !matches!(marker, 0xC4 | 0xC8 | 0xCC) => {
                if pos.checked_add(7)? > bytes.len() {
                    return None;
                }
                let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if seg_len < 7 {
                    return None;
                }
                let height = u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]) as u32;
                let width = u16::from_be_bytes([bytes[pos + 5], bytes[pos + 6]]) as u32;
                if width == 0 || height == 0 {
                    return None;
                }
                return Some(ImageInfo {
                    width,
                    height,
                    format: ImageFormat::Jpeg,
                });
            }
            0xDA => {
                if pos.checked_add(2)? > bytes.len() {
                    return None;
                }
                let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if seg_len < 2 {
                    return None;
                }
                pos = pos.checked_add(seg_len)?;
                if pos > bytes.len() {
                    return None;
                }
                loop {
                    if pos >= bytes.len() {
                        return None;
                    }
                    if bytes[pos] != 0xFF {
                        pos += 1;
                        continue;
                    }
                    let mut look = pos + 1;
                    while look < bytes.len() && bytes[look] == 0xFF {
                        look += 1;
                    }
                    if look >= bytes.len() {
                        return None;
                    }
                    let next_marker = bytes[look];
                    if next_marker == 0x00 || (0xD0..=0xD7).contains(&next_marker) {
                        pos = look + 1;
                        continue;
                    }
                    break;
                }
            }
            _ => {
                if pos.checked_add(2)? > bytes.len() {
                    return None;
                }
                let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if seg_len < 2 {
                    return None;
                }
                pos = pos.checked_add(seg_len)?;
                if pos > bytes.len() {
                    return None;
                }
            }
        }
    }
    None
}

fn parse_webp(bytes: &[u8]) -> Option<ImageInfo> {
    if bytes.len() < 20 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return None;
    }

    let mut pos = 12usize;
    while pos.checked_add(8)? <= bytes.len() {
        let fourcc = &bytes[pos..pos + 4];
        let chunk_size = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        let data = pos + 8;

        if fourcc == b"VP8 " {
            if chunk_size < 10 || data.checked_add(10)? > bytes.len() {
                return None;
            }
            if (bytes[data] & 0x01) != 0
                || bytes[data + 3] != 0x9D
                || bytes[data + 4] != 0x01
                || bytes[data + 5] != 0x2A
            {
                return None;
            }
            let width = (u16::from_le_bytes([bytes[data + 6], bytes[data + 7]]) & 0x3FFF) as u32;
            let height = (u16::from_le_bytes([bytes[data + 8], bytes[data + 9]]) & 0x3FFF) as u32;
            if width == 0 || height == 0 {
                return None;
            }
            return Some(ImageInfo {
                width,
                height,
                format: ImageFormat::Webp,
            });
        }

        if fourcc == b"VP8L" {
            if chunk_size < 5 || data.checked_add(5)? > bytes.len() {
                return None;
            }
            if bytes[data] != 0x2F {
                return None;
            }
            let bits = u32::from_le_bytes([
                bytes[data + 1],
                bytes[data + 2],
                bytes[data + 3],
                bytes[data + 4],
            ]);
            let width = (bits & 0x3FFF) + 1;
            let height = ((bits >> 14) & 0x3FFF) + 1;
            return Some(ImageInfo {
                width,
                height,
                format: ImageFormat::Webp,
            });
        }

        if fourcc == b"VP8X" {
            if chunk_size < 10 || data.checked_add(10)? > bytes.len() {
                return None;
            }
            let w_minus_1 = (bytes[data + 4] as u32)
                | ((bytes[data + 5] as u32) << 8)
                | ((bytes[data + 6] as u32) << 16);
            let h_minus_1 = (bytes[data + 7] as u32)
                | ((bytes[data + 8] as u32) << 8)
                | ((bytes[data + 9] as u32) << 16);
            let width = w_minus_1 + 1;
            let height = h_minus_1 + 1;
            return Some(ImageInfo {
                width,
                height,
                format: ImageFormat::Webp,
            });
        }

        let padded = chunk_size.checked_add(chunk_size & 1)?;
        pos = data.checked_add(padded)?;
        if pos > bytes.len() {
            return None;
        }
    }
    None
}

/// The size-locked prompt sent to agy: the brief, the exact pixel size (never "square" when w != h),
/// that references (file names given) own identity, that the wrapper copies and converts the file
/// so the agent must only generate and must not try to copy, convert or save elsewhere.
#[must_use]
pub fn compose_prompt(
    brief: &str,
    width: u32,
    height: u32,
    out_file_name: &str,
    ref_names: &[String],
) -> String {
    let brief_clean = brief.trim();
    let aspect = if width == height {
        "square"
    } else if width > height {
        "landscape"
    } else {
        "portrait"
    };
    let target_desc = if out_file_name.trim().is_empty() {
        "the target output file".to_string()
    } else {
        out_file_name.trim().to_string()
    };

    let mut prompt = format!(
        "Generate exactly one image with the image-generator subagent.\n\
         Brief: {brief_clean}\n\
         Exact pixel size: {width}x{height} pixels (width {width} px, height {height} px, {aspect} canvas). \
         The generated image must be exact {width}x{height} pixels."
    );

    if !ref_names.is_empty() {
        let mut refs_joined = String::new();
        for (idx, name) in ref_names.iter().enumerate() {
            if idx > 0 {
                refs_joined.push_str(", ");
            }
            refs_joined.push_str(name.trim());
        }
        prompt.push_str(&format!(
            "\nReference image files ({refs_joined}): these references own identity - \
             preserve the exact subject identity, appearance, and defining visual traits from {refs_joined}."
        ));
    }

    prompt.push_str(&format!(
        "\nWrapper file handling: the wrapper copies and converts the generated image file to {target_desc} itself. \
         You must only generate the image and must not try to copy, convert, move, rename, or save the file to {target_desc} or elsewhere."
    ));

    prompt
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    Ok,
    QuotaExhausted,
    PermissionDenied,
    NoImage,
    SizeMismatch,
    AgyFailed,
}

/// Classify agy's response text + stderr when no image was found:
/// quota/limit/"try again" wording -> QuotaExhausted,
/// permission/denied/not allowed -> PermissionDenied,
/// non-zero exit -> AgyFailed, else NoImage.
#[must_use]
pub fn classify_failure(response: &str, stderr: &str, exit_code: i32) -> RunKind {
    let resp_low = response.to_ascii_lowercase();
    let err_low = stderr.to_ascii_lowercase();

    if has_quota_wording(&resp_low) || has_quota_wording(&err_low) {
        return RunKind::QuotaExhausted;
    }
    if has_permission_wording(&resp_low) || has_permission_wording(&err_low) {
        return RunKind::PermissionDenied;
    }
    if exit_code != 0 {
        return RunKind::AgyFailed;
    }
    RunKind::NoImage
}

fn has_quota_wording(lower: &str) -> bool {
    const QUOTA_SUBSTRINGS: [&str; 10] = [
        "quota",
        "try again",
        "rate limit",
        "rate-limit",
        "ratelimit",
        "rate limited",
        "rate-limited",
        "too many requests",
        "resource_exhausted",
        "resource exhausted",
    ];
    if QUOTA_SUBSTRINGS.iter().any(|pat| lower.contains(pat)) {
        return true;
    }
    contains_ascii_word(lower, "limit") || contains_ascii_word(lower, "limits")
}

fn has_permission_wording(lower: &str) -> bool {
    const PERM_SUBSTRINGS: [&str; 6] = [
        "permission",
        "denied",
        "not allowed",
        "not permitted",
        "eacces",
        "eperm",
    ];
    PERM_SUBSTRINGS.iter().any(|pat| lower.contains(pat))
}

fn contains_ascii_word(haystack: &str, word: &str) -> bool {
    let hay = haystack.as_bytes();
    let needle = word.as_bytes();
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    let last_start = hay.len() - needle.len();
    let mut i = 0usize;
    while i <= last_start {
        if &hay[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !hay[i - 1].is_ascii_alphabetic();
            let after_idx = i + needle.len();
            let after_ok = after_idx == hay.len() || !hay[after_idx].is_ascii_alphabetic();
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[must_use]
pub fn run_kind_str(kind: &RunKind) -> &'static str {
    match kind {
        RunKind::Ok => "ok",
        RunKind::QuotaExhausted => "quota_exhausted",
        RunKind::PermissionDenied => "permission_denied",
        RunKind::NoImage => "no_image",
        RunKind::SizeMismatch => "size_mismatch",
        RunKind::AgyFailed => "agy_failed",
    }
}

/// Pick the result among candidate files: (path, mtime_unix_ns, bytes_sha256_hex, in_print_conversation).
/// Only files with mtime >= started_ns, never a hash equal to a reference hash;
/// prefer in_print_conversation, then newest.
#[must_use]
pub fn pick_result(
    cands: &[(String, i64, String, bool)],
    started_ns: i64,
    ref_hashes: &[String],
) -> Option<usize> {
    let mut best_idx: Option<usize> = None;
    for (idx, (path, mtime_ns, sha256_hex, in_print_conv)) in cands.iter().enumerate() {
        if *mtime_ns < started_ns {
            continue;
        }
        if ref_hashes
            .iter()
            .any(|ref_hash| ref_hash.eq_ignore_ascii_case(sha256_hex))
        {
            continue;
        }
        let take = match best_idx {
            None => true,
            Some(cur) => {
                let (cur_path, cur_mtime, _, cur_in_conv) = &cands[cur];
                (*in_print_conv, *mtime_ns, path.as_str())
                    > (*cur_in_conv, *cur_mtime, cur_path.as_str())
            }
        };
        if take {
            best_idx = Some(idx);
        }
    }
    best_idx
}
