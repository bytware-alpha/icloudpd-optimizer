use std::ffi::OsStr;
use std::path::PathBuf;

use icloudpd_optimizer::conversion::{CommandPlan, ConversionError, plan_conversion};

fn args(plan: &CommandPlan) -> Vec<String> {
    plan.args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

fn contains_forbidden_action(plan: &CommandPlan) -> bool {
    std::iter::once(OsStr::new(&plan.program))
        .chain(plan.args.iter().map(|arg| arg.as_os_str()))
        .map(|part| part.to_string_lossy().to_ascii_lowercase())
        .any(|part| {
            part.contains("delete")
                || part.contains("upload")
                || part == "rm"
                || part == "unlink"
                || part.contains("icloud")
        })
}

#[test]
fn plans_exact_vips_exiftool_and_verification_commands() {
    let raw = PathBuf::from("/nas/raw/IMG_0001.dng");
    let output = PathBuf::from("/staging/IMG_0001.heic");

    let plan = plan_conversion(&raw, &output, 90).expect("conversion should plan");

    assert_eq!(plan.convert.program, "vips");
    assert_eq!(
        args(&plan.convert),
        vec![
            "copy",
            "/nas/raw/IMG_0001.dng",
            "/staging/IMG_0001.heic[Q=90]"
        ]
    );
    assert_eq!(plan.metadata.program, "exiftool");
    assert_eq!(
        args(&plan.metadata),
        vec![
            "-TagsFromFile",
            "/nas/raw/IMG_0001.dng",
            "-all:all",
            "-overwrite_original",
            "/staging/IMG_0001.heic"
        ]
    );
    assert_eq!(plan.verify_image.program, "vipsheader");
    assert_eq!(args(&plan.verify_image), vec!["/staging/IMG_0001.heic"]);
    assert_eq!(plan.verify_metadata.program, "exiftool");
    assert_eq!(
        args(&plan.verify_metadata),
        vec!["-json", "-a", "-G1", "-s", "/staging/IMG_0001.heic"]
    );
}

#[test]
fn includes_requested_heic_quality_in_vips_output_suffix() {
    let plan = plan_conversion(
        PathBuf::from("/nas/raw/IMG_0002.cr2"),
        PathBuf::from("/staging/IMG_0002.heic"),
        82,
    )
    .expect("conversion should plan");

    assert_eq!(
        args(&plan.convert),
        vec![
            "copy",
            "/nas/raw/IMG_0002.cr2",
            "/staging/IMG_0002.heic[Q=82]"
        ]
    );
}

#[test]
fn refuses_non_heic_output_paths() {
    let error = plan_conversion(
        PathBuf::from("/nas/raw/IMG_0003.dng"),
        PathBuf::from("/staging/IMG_0003.jpg"),
        90,
    )
    .expect_err("non-heic output should fail closed");

    assert!(matches!(
        error,
        ConversionError::InvalidOutputExtension { .. }
    ));
}

#[test]
fn refuses_raw_output_path_collisions() {
    let same_path = PathBuf::from("/staging/IMG_0004.heic");

    let error =
        plan_conversion(&same_path, &same_path, 90).expect_err("collision should fail closed");

    assert!(matches!(
        error,
        ConversionError::OutputCollidesWithRaw { .. }
    ));
}

#[test]
fn refuses_lexically_equivalent_raw_output_path_collisions() {
    let raw = PathBuf::from("/staging/IMG_0004.heic");
    let output = PathBuf::from("/staging/nested/../IMG_0004.heic");

    let error = plan_conversion(&raw, &output, 90).expect_err("collision should fail closed");

    assert!(matches!(
        error,
        ConversionError::OutputCollidesWithRaw { .. }
    ));
}

#[test]
fn refuses_parent_above_root_output_path_collisions() {
    let raw = PathBuf::from("/IMG_0004.heic");
    let output = PathBuf::from("/../IMG_0004.heic");

    let error = plan_conversion(&raw, &output, 90).expect_err("collision should fail closed");

    assert!(matches!(
        error,
        ConversionError::OutputCollidesWithRaw { .. }
    ));
}

#[cfg(unix)]
#[test]
fn refuses_hard_linked_raw_output_path_collisions() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let raw = tempdir.path().join("raw.dng");
    let output = tempdir.path().join("out.heic");
    std::fs::write(&raw, b"raw-bytes").expect("raw should be written");
    std::fs::hard_link(&raw, &output).expect("output should hard-link to raw");

    let error = plan_conversion(&raw, &output, 90).expect_err("hard-link collision should fail");

    assert!(matches!(
        error,
        ConversionError::OutputCollidesWithRaw { .. }
    ));
}

#[test]
fn plans_do_not_include_delete_or_upload_commands() {
    let plan = plan_conversion(
        PathBuf::from("/nas/raw/IMG_0005.raf"),
        PathBuf::from("/staging/IMG_0005.heic"),
        90,
    )
    .expect("conversion should plan");

    let all_plans = [
        &plan.convert,
        &plan.metadata,
        &plan.verify_image,
        &plan.verify_metadata,
    ];

    assert!(
        all_plans
            .iter()
            .all(|plan| !contains_forbidden_action(plan)),
        "conversion adapter must not plan deletion or upload"
    );
}
