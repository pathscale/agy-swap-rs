use agy_core::image::{
    classify_failure, compose_prompt, image_info, pick_result, run_kind_str, ImageFormat,
    ImageInfo, RunKind,
};

fn build_minimal_png(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    // PNG signature (8 bytes)
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    // IHDR chunk length = 13 (big-endian)
    out.extend_from_slice(&13u32.to_be_bytes());
    // Chunk type
    out.extend_from_slice(b"IHDR");
    // Width and height (big-endian u32)
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    // Bit depth=8, color type=6 (RGBA), compression=0, filter=0, interlace=0
    out.extend_from_slice(&[8, 6, 0, 0, 0]);
    // Placeholder CRC
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

fn build_minimal_jpeg_app0_sof0(width: u16, height: u16) -> Vec<u8> {
    let mut out = Vec::new();
    // SOI
    out.extend_from_slice(&[0xFF, 0xD8]);
    // APP0 (JFIF) segment: length = 16 (includes 2 length bytes + 14 payload bytes)
    out.extend_from_slice(&[0xFF, 0xE0]);
    out.extend_from_slice(&16u16.to_be_bytes());
    out.extend_from_slice(b"JFIF\0");
    out.extend_from_slice(&[1, 1, 0, 0, 1, 0, 1, 0, 0]);
    // SOF0 (Baseline DCT): length = 17 (2 length + 1 prec + 2 h + 2 w + 1 ncomp + 9 comps)
    out.extend_from_slice(&[0xFF, 0xC0]);
    out.extend_from_slice(&17u16.to_be_bytes());
    out.push(8); // 8-bit sample precision
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&width.to_be_bytes());
    out.push(3); // 3 components (YCbCr)
    out.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]);
    // EOI
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

fn build_minimal_webp_vp8x(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(30);
    // RIFF header: total size 30 bytes -> RIFF size field = 22
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&22u32.to_le_bytes());
    out.extend_from_slice(b"WEBP");
    // VP8X chunk: 10 bytes payload
    out.extend_from_slice(b"VP8X");
    out.extend_from_slice(&10u32.to_le_bytes());
    // Flags (1 byte) + reserved (3 bytes)
    out.extend_from_slice(&[0, 0, 0, 0]);
    // Canvas width - 1 (24-bit little-endian)
    let wm1 = width - 1;
    out.extend_from_slice(&[wm1 as u8, (wm1 >> 8) as u8, (wm1 >> 16) as u8]);
    // Canvas height - 1 (24-bit little-endian)
    let hm1 = height - 1;
    out.extend_from_slice(&[hm1 as u8, (hm1 >> 8) as u8, (hm1 >> 16) as u8]);
    out
}

#[test]
fn image_info_parses_minimal_png_jpeg_and_webp_vp8x() {
    let png = build_minimal_png(1122, 1402);
    let png_info: ImageInfo = image_info(&png).expect("parse minimal PNG");
    assert_eq!(png_info.width, 1122);
    assert_eq!(png_info.height, 1402);
    assert!(matches!(png_info.format, ImageFormat::Png));

    let jpeg = build_minimal_jpeg_app0_sof0(1024, 768);
    let jpeg_info: ImageInfo = image_info(&jpeg).expect("parse minimal JPEG");
    assert_eq!(jpeg_info.width, 1024);
    assert_eq!(jpeg_info.height, 768);
    assert!(matches!(jpeg_info.format, ImageFormat::Jpeg));

    let webp = build_minimal_webp_vp8x(1280, 720);
    let webp_info: ImageInfo = image_info(&webp).expect("parse minimal WebP VP8X");
    assert_eq!(webp_info.width, 1280);
    assert_eq!(webp_info.height, 720);
    assert!(matches!(webp_info.format, ImageFormat::Webp));
}

#[test]
fn image_info_rejects_truncated_and_unknown_inputs() {
    assert!(image_info(&[]).is_none());
    assert!(image_info(b"plain text, not an image").is_none());

    let png = build_minimal_png(640, 480);
    assert!(image_info(&png[..8]).is_none());
    assert!(image_info(&png[..20]).is_none());

    let jpeg = build_minimal_jpeg_app0_sof0(800, 600);
    assert!(image_info(&jpeg[..2]).is_none());
    // Cut off after APP0 and SOF0 marker/length, before height/width complete
    assert!(image_info(&jpeg[..24]).is_none());

    let webp = build_minimal_webp_vp8x(1024, 1024);
    assert!(image_info(&webp[..12]).is_none());
    assert!(image_info(&webp[..26]).is_none());
}

#[test]
fn compose_prompt_locks_exact_pixels_and_omits_square_when_non_square() {
    let refs = vec!["subject_front.png".to_string(), "palette.jpg".to_string()];
    let prompt = compose_prompt(
        "editorial portrait on warm paper",
        1122,
        1402,
        "poster.png",
        &refs,
    );

    assert!(prompt.contains("editorial portrait on warm paper"));
    assert!(prompt.contains("1122x1402"));
    assert!(
        !prompt.to_ascii_lowercase().contains("square"),
        "non-square prompt must not contain 'square': {prompt}"
    );
    assert!(prompt.contains("subject_front.png"));
    assert!(prompt.contains("palette.jpg"));

    let landscape = compose_prompt("coastal lighthouse at dusk", 1920, 1080, "hero.png", &[]);
    assert!(landscape.contains("coastal lighthouse at dusk"));
    assert!(landscape.contains("1920x1080"));
    assert!(
        !landscape.to_ascii_lowercase().contains("square"),
        "landscape prompt must not contain 'square': {landscape}"
    );

    let square = compose_prompt("minimalist icon", 1024, 1024, "icon.png", &[]);
    assert!(square.contains("minimalist icon"));
    assert!(square.contains("1024x1024"));
}

#[test]
fn classify_failure_and_run_kind_str_cover_all_outcomes() {
    assert!(matches!(
        classify_failure("Image quota exceeded. Please try again later.", "", 0),
        RunKind::QuotaExhausted
    ));
    assert!(matches!(
        classify_failure("", "rate limit reached - try again in 5 hours", 1),
        RunKind::QuotaExhausted
    ));

    assert!(matches!(
        classify_failure("Permission denied writing to output path.", "", 0),
        RunKind::PermissionDenied
    ));
    assert!(matches!(
        classify_failure("", "action not allowed by policy", 1),
        RunKind::PermissionDenied
    ));

    assert!(matches!(
        classify_failure("unexpected tool crash", "fatal error", 1),
        RunKind::AgyFailed
    ));
    assert!(matches!(classify_failure("", "", 124), RunKind::AgyFailed));

    assert!(matches!(
        classify_failure("Completed without generating an image.", "", 0),
        RunKind::NoImage
    ));
    assert!(matches!(classify_failure("", "", 0), RunKind::NoImage));

    assert_eq!(run_kind_str(&RunKind::Ok), "ok");
    assert_eq!(run_kind_str(&RunKind::QuotaExhausted), "quota_exhausted");
    assert_eq!(
        run_kind_str(&RunKind::PermissionDenied),
        "permission_denied"
    );
    assert_eq!(run_kind_str(&RunKind::NoImage), "no_image");
    assert_eq!(run_kind_str(&RunKind::SizeMismatch), "size_mismatch");
    assert_eq!(run_kind_str(&RunKind::AgyFailed), "agy_failed");
}

#[test]
fn pick_result_filters_old_and_ref_hashes_and_prefers_print_conversation() {
    let started_ns: i64 = 1_700_000_000_000_000_000;
    let ref_hashes = vec!["deadbeef01".to_string(), "cafebabe02".to_string()];

    // Empty candidate list returns None
    assert_eq!(pick_result(&[], started_ns, &ref_hashes), None);

    // Older files and reference-hash matches are ignored; print conversation beats newer other conversation
    let cands = vec![
        // 0: older than started_ns, even though in print conversation
        (
            "/brain/c1/old.jpg".to_string(),
            started_ns - 1,
            "hash_old".to_string(),
            true,
        ),
        // 1: matches a reference hash, even though newest and in print conversation
        (
            "/brain/c1/ref_copy.jpg".to_string(),
            started_ns + 5_000,
            "deadbeef01".to_string(),
            true,
        ),
        // 2: newer, valid hash, outside print conversation
        (
            "/brain/c2/.tempmediaStorage/media_2.jpg".to_string(),
            started_ns + 4_000,
            "hash_other_conv".to_string(),
            false,
        ),
        // 3: valid, in print conversation, older than candidate 4
        (
            "/brain/c1/gen_early.jpg".to_string(),
            started_ns,
            "hash_conv_early".to_string(),
            true,
        ),
        // 4: valid, in print conversation, newest among print-conversation candidates
        (
            "/brain/c1/gen_latest.jpg".to_string(),
            started_ns + 2_000,
            "hash_conv_latest".to_string(),
            true,
        ),
    ];
    assert_eq!(pick_result(&cands, started_ns, &ref_hashes), Some(4));

    // When no eligible candidate is in the print conversation, pick the newest eligible fallback
    let fallback_cands = vec![
        (
            "/brain/c2/older.png".to_string(),
            started_ns + 100,
            "hash_a".to_string(),
            false,
        ),
        (
            "/brain/c3/newest.png".to_string(),
            started_ns + 900,
            "hash_b".to_string(),
            false,
        ),
        (
            "/brain/c1/ref_dup.png".to_string(),
            started_ns + 1_200,
            "cafebabe02".to_string(),
            true,
        ),
    ];
    assert_eq!(
        pick_result(&fallback_cands, started_ns, &ref_hashes),
        Some(1)
    );

    // Boundary check: mtime == started_ns is accepted when no newer file exists
    let boundary = vec![(
        "/brain/c1/exact_start.png".to_string(),
        started_ns,
        "hash_exact".to_string(),
        false,
    )];
    assert_eq!(pick_result(&boundary, started_ns, &ref_hashes), Some(0));

    // All candidates filtered out returns None
    let all_filtered = vec![
        (
            "/brain/c1/stale.png".to_string(),
            started_ns - 10,
            "hash_stale".to_string(),
            true,
        ),
        (
            "/brain/c1/ref.png".to_string(),
            started_ns + 10,
            "deadbeef01".to_string(),
            true,
        ),
    ];
    assert_eq!(pick_result(&all_filtered, started_ns, &ref_hashes), None);
}
