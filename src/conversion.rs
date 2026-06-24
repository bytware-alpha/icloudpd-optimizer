use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::conversion_backend::TargetPlatform;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<OsString>,
    pub stdout_path: Option<PathBuf>,
}

impl CommandPlan {
    pub fn new(program: impl Into<String>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
            stdout_path: None,
        }
    }

    pub fn with_stdout_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.stdout_path = Some(path.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionPlan {
    pub convert: CommandPlan,
    pub conversion_commands: Vec<CommandPlan>,
    pub metadata: CommandPlan,
    pub verify_image: CommandPlan,
    pub render_raw_preview: CommandPlan,
    pub render_heic_preview: CommandPlan,
    pub verify_visual_content: CommandPlan,
    pub verify_visual_match: CommandPlan,
    pub verify_metadata: CommandPlan,
}

/// Builds non-destructive command plans for RAW-to-HEIC conversion and verification.
///
/// ```
/// # use icloudpd_optimizer::conversion::plan_conversion;
/// let plan = plan_conversion("/nas/photo.dng", "/tmp/photo.heic", 90)?;
/// assert!(!plan.convert.program.is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn plan_conversion(
    raw_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    heic_quality: u8,
) -> Result<ConversionPlan, ConversionError> {
    plan_conversion_for_target(
        TargetPlatform::current(),
        raw_path.as_ref(),
        output_path.as_ref(),
        heic_quality,
    )
}

pub fn plan_conversion_for_target(
    target: TargetPlatform,
    raw_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    heic_quality: u8,
) -> Result<ConversionPlan, ConversionError> {
    let raw_path = raw_path.as_ref();
    let output_path = output_path.as_ref();

    if paths_collide(raw_path, output_path) {
        return Err(ConversionError::OutputCollidesWithRaw {
            raw_path: raw_path.to_path_buf(),
            output_path: output_path.to_path_buf(),
        });
    }
    if !has_heic_extension(output_path) {
        return Err(ConversionError::InvalidOutputExtension {
            path: output_path.to_path_buf(),
        });
    }
    if !(1..=100).contains(&heic_quality) {
        return Err(ConversionError::InvalidHeicQuality {
            quality: heic_quality,
        });
    }

    let raw_arg = raw_path.as_os_str().to_os_string();
    let output_arg = output_path.as_os_str().to_os_string();
    let raw_preview_arg = visual_preview_path(output_path, "raw")
        .as_os_str()
        .to_os_string();
    let heic_preview_arg = visual_preview_path(output_path, "heic")
        .as_os_str()
        .to_os_string();
    match target.os {
        "linux" => linux_conversion_plan(
            raw_arg,
            output_arg,
            raw_preview_arg,
            heic_preview_arg,
            output_path,
            heic_quality,
        ),
        _ => macos_conversion_plan(
            raw_arg,
            output_arg,
            raw_preview_arg,
            heic_preview_arg,
            output_path,
            heic_quality,
        ),
    }
}

fn macos_conversion_plan(
    raw_arg: OsString,
    output_arg: OsString,
    raw_preview_arg: OsString,
    heic_preview_arg: OsString,
    output_path: &Path,
    heic_quality: u8,
) -> Result<ConversionPlan, ConversionError> {
    let embedded_preview_path = intermediate_preview_path(output_path);
    let embedded_preview_arg = embedded_preview_path.as_os_str().to_os_string();
    let extract_preview = CommandPlan::new(
        "exiftool",
        vec![
            OsString::from("-b"),
            OsString::from("-PreviewImage"),
            raw_arg.clone(),
        ],
    )
    .with_stdout_file(embedded_preview_path);
    let normalize_preview_orientation = CommandPlan::new(
        "exiftool",
        vec![
            OsString::from("-overwrite_original"),
            OsString::from("-Orientation#=1"),
            embedded_preview_arg.clone(),
        ],
    );
    let encode = CommandPlan::new(
        "sips",
        vec![
            OsString::from("-s"),
            OsString::from("format"),
            OsString::from("heic"),
            OsString::from("-s"),
            OsString::from("formatOptions"),
            OsString::from(heic_quality.to_string()),
            embedded_preview_arg.clone(),
            OsString::from("--out"),
            output_arg.clone(),
        ],
    );

    Ok(ConversionPlan {
        convert: extract_preview.clone(),
        conversion_commands: vec![extract_preview, normalize_preview_orientation, encode],
        metadata: CommandPlan::new(
            "exiftool",
            vec![
                OsString::from("-TagsFromFile"),
                raw_arg.clone(),
                OsString::from("-all:all"),
                OsString::from("-Orientation#=1"),
                OsString::from("-QuickTime:Rotation#=0"),
                OsString::from("-overwrite_original"),
                output_arg.clone(),
            ],
        ),
        verify_image: CommandPlan::new("heif-info", vec![output_arg.clone()]),
        render_raw_preview: CommandPlan::new(
            "sips",
            vec![
                OsString::from("-Z"),
                OsString::from("512"),
                OsString::from("-s"),
                OsString::from("format"),
                OsString::from("png"),
                embedded_preview_arg,
                OsString::from("--out"),
                raw_preview_arg.clone(),
            ],
        ),
        render_heic_preview: CommandPlan::new(
            "sips",
            vec![
                OsString::from("-Z"),
                OsString::from("512"),
                OsString::from("-s"),
                OsString::from("format"),
                OsString::from("png"),
                output_arg.clone(),
                OsString::from("--out"),
                heic_preview_arg.clone(),
            ],
        ),
        verify_visual_content: CommandPlan::new(
            "magick",
            vec![
                heic_preview_arg.clone(),
                OsString::from("-colorspace"),
                OsString::from("RGB"),
                OsString::from("-format"),
                OsString::from("%[fx:standard_deviation]"),
                OsString::from("info:"),
            ],
        ),
        verify_visual_match: CommandPlan::new(
            "magick",
            vec![
                OsString::from("compare"),
                OsString::from("-metric"),
                OsString::from("RMSE"),
                raw_preview_arg,
                heic_preview_arg,
                OsString::from("null:"),
            ],
        ),
        verify_metadata: CommandPlan::new(
            "exiftool",
            vec![
                OsString::from("-json"),
                OsString::from("-a"),
                OsString::from("-G1"),
                OsString::from("-s"),
                output_arg,
            ],
        ),
    })
}

fn linux_conversion_plan(
    raw_arg: OsString,
    output_arg: OsString,
    raw_preview_arg: OsString,
    heic_preview_arg: OsString,
    output_path: &Path,
    heic_quality: u8,
) -> Result<ConversionPlan, ConversionError> {
    let embedded_preview_path = intermediate_preview_path(output_path);
    let embedded_preview_arg = embedded_preview_path.as_os_str().to_os_string();
    let extract_preview = CommandPlan::new(
        "exiftool",
        vec![
            OsString::from("-b"),
            OsString::from("-PreviewImage"),
            raw_arg.clone(),
        ],
    )
    .with_stdout_file(embedded_preview_path);
    let encode = CommandPlan::new(
        "heif-enc",
        vec![
            OsString::from("-q"),
            OsString::from(heic_quality.to_string()),
            embedded_preview_arg.clone(),
            OsString::from("-o"),
            output_arg.clone(),
        ],
    );

    Ok(ConversionPlan {
        convert: extract_preview.clone(),
        conversion_commands: vec![extract_preview, encode],
        metadata: CommandPlan::new(
            "exiftool",
            vec![
                OsString::from("-TagsFromFile"),
                raw_arg.clone(),
                OsString::from("-all:all"),
                OsString::from("-overwrite_original"),
                output_arg.clone(),
            ],
        ),
        verify_image: CommandPlan::new("heif-info", vec![output_arg.clone()]),
        render_raw_preview: CommandPlan::new(
            "magick",
            vec![
                embedded_preview_arg,
                OsString::from("-resize"),
                OsString::from("512x512"),
                raw_preview_arg.clone(),
            ],
        ),
        render_heic_preview: CommandPlan::new(
            "magick",
            vec![
                output_arg.clone(),
                OsString::from("-resize"),
                OsString::from("512x512"),
                heic_preview_arg.clone(),
            ],
        ),
        verify_visual_content: CommandPlan::new(
            "magick",
            vec![
                heic_preview_arg.clone(),
                OsString::from("-colorspace"),
                OsString::from("RGB"),
                OsString::from("-format"),
                OsString::from("%[fx:standard_deviation]"),
                OsString::from("info:"),
            ],
        ),
        verify_visual_match: CommandPlan::new(
            "magick",
            vec![
                OsString::from("compare"),
                OsString::from("-metric"),
                OsString::from("RMSE"),
                raw_preview_arg,
                heic_preview_arg,
                OsString::from("null:"),
            ],
        ),
        verify_metadata: CommandPlan::new(
            "exiftool",
            vec![
                OsString::from("-json"),
                OsString::from("-a"),
                OsString::from("-G1"),
                OsString::from("-s"),
                output_arg,
            ],
        ),
    })
}

fn intermediate_preview_path(output_path: &Path) -> PathBuf {
    let mut preview_path = output_path.to_path_buf();
    preview_path.set_extension("embedded-preview.jpg");
    preview_path
}

fn visual_preview_path(output_path: &Path, label: &str) -> PathBuf {
    let mut preview_path = output_path.to_path_buf();
    preview_path.set_extension(format!("{label}-preview.png"));
    preview_path
}

fn has_heic_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("heic"))
}

fn paths_collide(raw_path: &Path, output_path: &Path) -> bool {
    if raw_path == output_path {
        return true;
    }
    if lexical_normalize(raw_path) == lexical_normalize(output_path) {
        return true;
    }
    if same_existing_file(raw_path, output_path) {
        return true;
    }

    match (raw_path.canonicalize(), output_path.canonicalize()) {
        (Ok(raw), Ok(output)) => raw == output,
        _ => false,
    }
}

#[cfg(unix)]
fn same_existing_file(left: &Path, right: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let (Ok(left), Ok(right)) = (std::fs::metadata(left), std::fs::metadata(right)) else {
        return false;
    };

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_existing_file(_left: &Path, _right: &Path) -> bool {
    false
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !normalized.has_root() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir | Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }

    normalized
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("HEIC output path must end in .heic: {path}")]
    InvalidOutputExtension { path: PathBuf },
    #[error("HEIC quality must be between 1 and 100, got {quality}")]
    InvalidHeicQuality { quality: u8 },
    #[error("output path {output_path} collides with RAW input {raw_path}")]
    OutputCollidesWithRaw {
        raw_path: PathBuf,
        output_path: PathBuf,
    },
}
