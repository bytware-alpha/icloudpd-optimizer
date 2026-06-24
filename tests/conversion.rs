use std::ffi::OsStr;
use std::path::PathBuf;

use icloudpd_optimizer::conversion::{
    CommandPlan, ConversionError, plan_conversion, plan_conversion_for_target,
};
use icloudpd_optimizer::conversion_backend::TargetPlatform;

fn args(plan: &CommandPlan) -> Vec<String> {
    plan.args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

fn contains_forbidden_action(plan: &CommandPlan) -> bool {
    std::iter::once(OsStr::new(&plan.program))
        .chain(plan.args.iter().map(|arg| arg.as_os_str()))
        .chain(plan.stdout_path.iter().map(|path| path.as_os_str()))
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
fn plans_exact_sips_exiftool_and_verification_commands() {
    let raw = PathBuf::from("/nas/raw/IMG_0001.dng");
    let output = PathBuf::from("/staging/IMG_0001.heic");

    let plan =
        plan_conversion_for_target(TargetPlatform::new("macos", "aarch64"), &raw, &output, 90)
            .expect("conversion should plan");

    let conversion_programs: Vec<_> = plan
        .conversion_commands
        .iter()
        .map(|command| command.program.as_str())
        .collect();
    assert_eq!(conversion_programs, vec!["exiftool", "magick", "sips"]);
    assert_eq!(plan.convert.program, "exiftool");
    assert_eq!(
        args(&plan.conversion_commands[0]),
        vec!["-b", "-PreviewImage", "/nas/raw/IMG_0001.dng"]
    );
    assert_eq!(
        plan.conversion_commands[0].stdout_path,
        Some(PathBuf::from("/staging/IMG_0001.embedded-preview.jpg"))
    );
    assert_eq!(
        args(&plan.conversion_commands[1]),
        vec![
            "/staging/IMG_0001.embedded-preview.jpg",
            "-auto-orient",
            "jpg:-"
        ]
    );
    assert_eq!(
        plan.conversion_commands[1].stdout_path,
        Some(PathBuf::from("/staging/IMG_0001.oriented-preview.jpg"))
    );
    assert_eq!(
        args(&plan.conversion_commands[2]),
        vec![
            "-s",
            "format",
            "heic",
            "-s",
            "formatOptions",
            "90",
            "/staging/IMG_0001.oriented-preview.jpg",
            "--out",
            "/staging/IMG_0001.heic"
        ]
    );
    assert_eq!(plan.metadata.program, "exiftool");
    assert_eq!(
        args(&plan.metadata),
        vec![
            "-TagsFromFile",
            "/nas/raw/IMG_0001.dng",
            "-all:all",
            "-Orientation#=1",
            "-QuickTime:Rotation#=0",
            "-overwrite_original",
            "/staging/IMG_0001.heic"
        ]
    );
    assert_eq!(plan.verify_image.program, "heif-info");
    assert_eq!(args(&plan.verify_image), vec!["/staging/IMG_0001.heic"]);
    assert_eq!(plan.render_raw_preview.program, "sips");
    assert_eq!(
        args(&plan.render_raw_preview),
        vec![
            "-Z",
            "512",
            "-s",
            "format",
            "png",
            "/staging/IMG_0001.oriented-preview.jpg",
            "--out",
            "/staging/IMG_0001.raw-preview.png"
        ]
    );
    assert_eq!(plan.render_heic_preview.program, "sips");
    assert_eq!(
        args(&plan.render_heic_preview),
        vec![
            "-Z",
            "512",
            "-s",
            "format",
            "png",
            "/staging/IMG_0001.heic",
            "--out",
            "/staging/IMG_0001.heic-preview.png"
        ]
    );
    assert_eq!(plan.verify_visual_content.program, "magick");
    assert_eq!(
        args(&plan.verify_visual_content),
        vec![
            "/staging/IMG_0001.heic-preview.png",
            "-colorspace",
            "RGB",
            "-format",
            "%[fx:standard_deviation]",
            "info:"
        ]
    );
    assert_eq!(plan.verify_visual_match.program, "magick");
    assert_eq!(
        args(&plan.verify_visual_match),
        vec![
            "compare",
            "-metric",
            "RMSE",
            "/staging/IMG_0001.raw-preview.png",
            "/staging/IMG_0001.heic-preview.png",
            "null:"
        ]
    );
    assert_eq!(plan.verify_metadata.program, "exiftool");
    assert_eq!(
        args(&plan.verify_metadata),
        vec!["-json", "-a", "-G1", "-s", "/staging/IMG_0001.heic"]
    );
}

#[test]
fn includes_requested_heic_quality_in_sips_format_options() {
    let plan = plan_conversion_for_target(
        TargetPlatform::new("macos", "aarch64"),
        PathBuf::from("/nas/raw/IMG_0002.cr2"),
        PathBuf::from("/staging/IMG_0002.heic"),
        82,
    )
    .expect("conversion should plan");

    assert_eq!(
        args(&plan.conversion_commands[2]),
        vec![
            "-s",
            "format",
            "heic",
            "-s",
            "formatOptions",
            "82",
            "/staging/IMG_0002.oriented-preview.jpg",
            "--out",
            "/staging/IMG_0002.heic"
        ]
    );
}

#[test]
fn plans_linux_native_conversion_without_sips() {
    let plan = plan_conversion_for_target(
        TargetPlatform::new("linux", "x86_64"),
        PathBuf::from("/nas/raw/IMG_0006.dng"),
        PathBuf::from("/staging/IMG_0006.heic"),
        88,
    )
    .expect("linux conversion should plan");

    let conversion_programs: Vec<_> = plan
        .conversion_commands
        .iter()
        .map(|command| command.program.as_str())
        .collect();
    assert_eq!(conversion_programs, vec!["exiftool", "magick", "heif-enc"]);
    assert_eq!(plan.convert.program, "exiftool");
    assert_eq!(
        args(&plan.conversion_commands[0]),
        vec!["-b", "-PreviewImage", "/nas/raw/IMG_0006.dng"]
    );
    assert_eq!(
        plan.conversion_commands[0].stdout_path,
        Some(PathBuf::from("/staging/IMG_0006.embedded-preview.jpg"))
    );
    assert_eq!(
        args(&plan.conversion_commands[1]),
        vec![
            "/staging/IMG_0006.embedded-preview.jpg",
            "-auto-orient",
            "jpg:-"
        ]
    );
    assert_eq!(
        plan.conversion_commands[1].stdout_path,
        Some(PathBuf::from("/staging/IMG_0006.oriented-preview.jpg"))
    );
    assert_eq!(
        args(&plan.conversion_commands[2]),
        vec![
            "-q",
            "88",
            "/staging/IMG_0006.oriented-preview.jpg",
            "-o",
            "/staging/IMG_0006.heic"
        ]
    );
    assert_eq!(plan.conversion_commands[2].stdout_path, None);
    assert_eq!(plan.metadata.program, "exiftool");
    assert_eq!(
        args(&plan.metadata),
        vec![
            "-TagsFromFile",
            "/nas/raw/IMG_0006.dng",
            "-all:all",
            "-Orientation#=1",
            "-QuickTime:Rotation#=0",
            "-overwrite_original",
            "/staging/IMG_0006.heic"
        ]
    );
    assert_eq!(plan.verify_image.program, "heif-info");
    assert_eq!(plan.render_raw_preview.program, "magick");
    assert_eq!(
        args(&plan.render_raw_preview),
        vec![
            "/staging/IMG_0006.oriented-preview.jpg",
            "-resize",
            "512x512",
            "/staging/IMG_0006.raw-preview.png"
        ]
    );
    assert_eq!(plan.render_heic_preview.program, "magick");
    assert_eq!(plan.verify_visual_content.program, "magick");
    assert_eq!(plan.verify_visual_match.program, "magick");
    assert_eq!(plan.verify_metadata.program, "exiftool");

    let all_plans = [
        plan.conversion_commands.as_slice(),
        &[
            plan.metadata,
            plan.verify_image,
            plan.render_raw_preview,
            plan.render_heic_preview,
            plan.verify_visual_content,
            plan.verify_visual_match,
            plan.verify_metadata,
        ],
    ]
    .concat();

    assert!(
        all_plans.iter().all(|command| command.program != "sips"),
        "linux conversion plans must not require sips"
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
        plan.conversion_commands.as_slice(),
        &[
            plan.metadata,
            plan.verify_image,
            plan.render_raw_preview,
            plan.render_heic_preview,
            plan.verify_visual_content,
            plan.verify_visual_match,
            plan.verify_metadata,
        ],
    ]
    .concat();

    assert!(
        all_plans
            .iter()
            .all(|plan| !contains_forbidden_action(plan)),
        "conversion adapter must not plan deletion or upload"
    );
}
