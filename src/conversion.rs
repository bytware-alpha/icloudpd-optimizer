use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::conversion_backend::TargetPlatform;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<OsString>,
    pub stdout_path: Option<PathBuf>,
    pub checked_output_path: Option<PathBuf>,
}

impl CommandPlan {
    pub fn new(program: impl Into<String>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
            stdout_path: None,
            checked_output_path: None,
        }
    }

    pub fn with_stdout_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.stdout_path = Some(path.into());
        self
    }

    pub fn with_checked_output_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.checked_output_path = Some(path.into());
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedPreviewTag {
    PreviewImage,
    JpgFromRaw,
}

impl EmbeddedPreviewTag {
    pub fn exiftool_arg(self) -> &'static str {
        match self {
            Self::PreviewImage => "-PreviewImage",
            Self::JpgFromRaw => "-JpgFromRaw",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExifOrientation {
    Normal,
    Rotate180,
    Rotate90Cw,
    Rotate270Cw,
    Unsupported(u16),
}

impl ExifOrientation {
    pub fn from_numeric(value: u16) -> Self {
        match value {
            1 => Self::Normal,
            3 => Self::Rotate180,
            6 => Self::Rotate90Cw,
            8 => Self::Rotate270Cw,
            other => Self::Unsupported(other),
        }
    }

    fn sips_rotation_degrees(self) -> Option<&'static str> {
        match self {
            Self::Normal => None,
            Self::Rotate180 => Some("180"),
            Self::Rotate90Cw => Some("90"),
            Self::Rotate270Cw => Some("270"),
            Self::Unsupported(_) => None,
        }
    }

    fn can_use_sips_orient(self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }
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
    plan_conversion_for_target_with_preview_tag(
        target,
        raw_path,
        output_path,
        heic_quality,
        EmbeddedPreviewTag::PreviewImage,
    )
}

pub fn plan_conversion_for_target_with_preview_tag(
    target: TargetPlatform,
    raw_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    heic_quality: u8,
    preview_tag: EmbeddedPreviewTag,
) -> Result<ConversionPlan, ConversionError> {
    plan_conversion_for_target_with_preview_tag_and_orientation(
        target,
        raw_path,
        output_path,
        heic_quality,
        preview_tag,
        None,
    )
}

pub fn plan_conversion_for_target_with_preview_tag_and_orientation(
    target: TargetPlatform,
    raw_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    heic_quality: u8,
    preview_tag: EmbeddedPreviewTag,
    orientation: Option<ExifOrientation>,
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
    let input = PlatformConversionPlanInput {
        raw_arg,
        output_arg,
        raw_preview_arg,
        heic_preview_arg,
        output_path,
        heic_quality,
        preview_tag,
        orientation,
    };
    match target.os {
        "linux" => linux_conversion_plan(input),
        _ => macos_conversion_plan(input),
    }
}

/// Builds a conversion plan that encodes an already-verified adjusted JPEG.
///
/// The RAW is still the metadata authority, but never a pixel source on this
/// path. The visual reference is rendered from the adjusted JPEG at its native
/// dimensions so a later verifier compares the encoded image to the exact
/// approved source.
pub fn plan_adjusted_source_conversion_for_target(
    target: TargetPlatform,
    raw_path: impl AsRef<Path>,
    adjusted_source_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    heic_quality: u8,
) -> Result<ConversionPlan, ConversionError> {
    let raw_path = raw_path.as_ref();
    let adjusted_source_path = adjusted_source_path.as_ref();
    let output_path = output_path.as_ref();

    if paths_collide(raw_path, output_path) || paths_collide(adjusted_source_path, output_path) {
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

    let input = AdjustedSourceConversionPlanInput {
        raw_arg: raw_path.as_os_str().to_os_string(),
        adjusted_source_arg: adjusted_source_path.as_os_str().to_os_string(),
        output_arg: output_path.as_os_str().to_os_string(),
        raw_preview_arg: visual_preview_path(output_path, "raw")
            .as_os_str()
            .to_os_string(),
        heic_preview_arg: visual_preview_path(output_path, "heic")
            .as_os_str()
            .to_os_string(),
        heic_quality,
    };
    match target.os {
        "linux" => linux_adjusted_source_conversion_plan(input),
        _ => macos_adjusted_source_conversion_plan(input),
    }
}

struct PlatformConversionPlanInput<'a> {
    raw_arg: OsString,
    output_arg: OsString,
    raw_preview_arg: OsString,
    heic_preview_arg: OsString,
    output_path: &'a Path,
    heic_quality: u8,
    preview_tag: EmbeddedPreviewTag,
    orientation: Option<ExifOrientation>,
}

struct AdjustedSourceConversionPlanInput {
    raw_arg: OsString,
    adjusted_source_arg: OsString,
    output_arg: OsString,
    raw_preview_arg: OsString,
    heic_preview_arg: OsString,
    heic_quality: u8,
}

fn macos_adjusted_source_conversion_plan(
    input: AdjustedSourceConversionPlanInput,
) -> Result<ConversionPlan, ConversionError> {
    let encode = CommandPlan::new(
        "sips",
        vec![
            OsString::from("-s"),
            OsString::from("format"),
            OsString::from("heic"),
            OsString::from("-s"),
            OsString::from("formatOptions"),
            OsString::from(input.heic_quality.to_string()),
            input.adjusted_source_arg.clone(),
            OsString::from("--out"),
            input.output_arg.clone(),
        ],
    );

    let render_raw_preview = CommandPlan::new(
        "sips",
        vec![
            OsString::from("-s"),
            OsString::from("format"),
            OsString::from("png"),
            input.adjusted_source_arg.clone(),
            OsString::from("--out"),
            input.raw_preview_arg.clone(),
        ],
    );
    let render_heic_preview = CommandPlan::new(
        "sips",
        vec![
            OsString::from("-s"),
            OsString::from("format"),
            OsString::from("png"),
            input.output_arg.clone(),
            OsString::from("--out"),
            input.heic_preview_arg.clone(),
        ],
    );
    Ok(adjusted_source_conversion_plan(
        encode,
        input,
        render_raw_preview,
        render_heic_preview,
    ))
}

fn linux_adjusted_source_conversion_plan(
    input: AdjustedSourceConversionPlanInput,
) -> Result<ConversionPlan, ConversionError> {
    let encode = CommandPlan::new(
        "heif-enc",
        vec![
            OsString::from("-q"),
            OsString::from(input.heic_quality.to_string()),
            input.adjusted_source_arg.clone(),
            OsString::from("-o"),
            input.output_arg.clone(),
        ],
    );

    let render_raw_preview = CommandPlan::new(
        "magick",
        vec![
            input.adjusted_source_arg.clone(),
            input.raw_preview_arg.clone(),
        ],
    );
    let render_heic_preview = CommandPlan::new(
        "magick",
        vec![input.output_arg.clone(), input.heic_preview_arg.clone()],
    );
    Ok(adjusted_source_conversion_plan(
        encode,
        input,
        render_raw_preview,
        render_heic_preview,
    ))
}

fn adjusted_source_conversion_plan(
    encode: CommandPlan,
    input: AdjustedSourceConversionPlanInput,
    render_raw_preview: CommandPlan,
    render_heic_preview: CommandPlan,
) -> ConversionPlan {
    ConversionPlan {
        convert: encode.clone(),
        conversion_commands: vec![encode],
        metadata: CommandPlan::new(
            "exiftool",
            vec![
                OsString::from("-TagsFromFile"),
                input.raw_arg,
                OsString::from("-all:all"),
                OsString::from("-Orientation#=1"),
                OsString::from("-QuickTime:Rotation#=0"),
                OsString::from("-overwrite_original"),
                input.output_arg.clone(),
            ],
        ),
        verify_image: CommandPlan::new("heif-info", vec![input.output_arg.clone()]),
        render_raw_preview,
        render_heic_preview,
        verify_visual_content: CommandPlan::new(
            "magick",
            vec![
                input.heic_preview_arg.clone(),
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
                input.raw_preview_arg,
                input.heic_preview_arg,
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
                input.output_arg,
            ],
        ),
    }
}

fn macos_conversion_plan(
    input: PlatformConversionPlanInput<'_>,
) -> Result<ConversionPlan, ConversionError> {
    let embedded_preview_path = intermediate_preview_path(input.output_path);
    let embedded_preview_arg = embedded_preview_path.as_os_str().to_os_string();
    let oriented_preview_path = oriented_preview_path(input.output_path);
    let oriented_preview_arg = oriented_preview_path.as_os_str().to_os_string();
    let extract_preview = CommandPlan::new(
        "exiftool",
        vec![
            OsString::from("-b"),
            OsString::from(input.preview_tag.exiftool_arg()),
            input.raw_arg.clone(),
        ],
    )
    .with_stdout_file(embedded_preview_path);
    let (orientation_commands, encode_input_arg) = macos_orientation_commands(
        input.raw_arg.clone(),
        embedded_preview_arg.clone(),
        oriented_preview_arg.clone(),
        &oriented_preview_path,
        input.orientation,
    );
    let encode = CommandPlan::new(
        "sips",
        vec![
            OsString::from("-s"),
            OsString::from("format"),
            OsString::from("heic"),
            OsString::from("-s"),
            OsString::from("formatOptions"),
            OsString::from(input.heic_quality.to_string()),
            encode_input_arg,
            OsString::from("--out"),
            input.output_arg.clone(),
        ],
    );
    let mut conversion_commands = vec![extract_preview.clone()];
    conversion_commands.extend(orientation_commands);
    conversion_commands.push(encode);

    Ok(ConversionPlan {
        convert: extract_preview.clone(),
        conversion_commands,
        metadata: CommandPlan::new(
            "exiftool",
            vec![
                OsString::from("-TagsFromFile"),
                input.raw_arg.clone(),
                OsString::from("-all:all"),
                OsString::from("-Orientation#=1"),
                OsString::from("-QuickTime:Rotation#=0"),
                OsString::from("-overwrite_original"),
                input.output_arg.clone(),
            ],
        ),
        verify_image: CommandPlan::new("heif-info", vec![input.output_arg.clone()]),
        render_raw_preview: CommandPlan::new(
            "sips",
            vec![
                OsString::from("-Z"),
                OsString::from("512"),
                OsString::from("-s"),
                OsString::from("format"),
                OsString::from("png"),
                oriented_preview_arg,
                OsString::from("--out"),
                input.raw_preview_arg.clone(),
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
                input.output_arg.clone(),
                OsString::from("--out"),
                input.heic_preview_arg.clone(),
            ],
        ),
        verify_visual_content: CommandPlan::new(
            "magick",
            vec![
                input.heic_preview_arg.clone(),
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
                input.raw_preview_arg,
                input.heic_preview_arg,
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
                input.output_arg,
            ],
        ),
    })
}

fn macos_orientation_commands(
    raw_arg: OsString,
    embedded_preview_arg: OsString,
    oriented_preview_arg: OsString,
    oriented_preview_path: &Path,
    orientation: Option<ExifOrientation>,
) -> (Vec<CommandPlan>, OsString) {
    match orientation {
        Some(ExifOrientation::Normal) => {
            let copy = CommandPlan::new(
                "cp",
                vec![embedded_preview_arg, oriented_preview_arg.clone()],
            )
            .with_checked_output_file(oriented_preview_path.to_path_buf());
            (vec![copy], oriented_preview_arg)
        }
        Some(orientation) if orientation.can_use_sips_orient() => {
            let degrees = orientation
                .sips_rotation_degrees()
                .expect("non-normal sips orientation should have rotation degrees");
            let orient = CommandPlan::new(
                "sips",
                vec![
                    OsString::from("--rotate"),
                    OsString::from(degrees),
                    embedded_preview_arg,
                    OsString::from("--out"),
                    oriented_preview_arg.clone(),
                ],
            )
            .with_checked_output_file(oriented_preview_path.to_path_buf());
            (vec![orient], oriented_preview_arg)
        }
        _ => {
            let copy_preview_orientation = CommandPlan::new(
                "exiftool",
                vec![
                    OsString::from("-TagsFromFile"),
                    raw_arg,
                    OsString::from("-Orientation#"),
                    OsString::from("-overwrite_original"),
                    embedded_preview_arg.clone(),
                ],
            );
            let orient_preview_pixels = CommandPlan::new(
                "magick",
                vec![
                    embedded_preview_arg,
                    OsString::from("-auto-orient"),
                    OsString::from("jpg:-"),
                ],
            )
            .with_stdout_file(oriented_preview_path.to_path_buf());
            (
                vec![copy_preview_orientation, orient_preview_pixels],
                oriented_preview_arg,
            )
        }
    }
}

fn linux_conversion_plan(
    input: PlatformConversionPlanInput<'_>,
) -> Result<ConversionPlan, ConversionError> {
    let embedded_preview_path = intermediate_preview_path(input.output_path);
    let embedded_preview_arg = embedded_preview_path.as_os_str().to_os_string();
    let oriented_preview_path = oriented_preview_path(input.output_path);
    let oriented_preview_arg = oriented_preview_path.as_os_str().to_os_string();
    let extract_preview = CommandPlan::new(
        "exiftool",
        vec![
            OsString::from("-b"),
            OsString::from(input.preview_tag.exiftool_arg()),
            input.raw_arg.clone(),
        ],
    )
    .with_stdout_file(embedded_preview_path);
    let copy_preview_orientation = CommandPlan::new(
        "exiftool",
        vec![
            OsString::from("-TagsFromFile"),
            input.raw_arg.clone(),
            OsString::from("-Orientation#"),
            OsString::from("-overwrite_original"),
            embedded_preview_arg.clone(),
        ],
    );
    let orient_preview_pixels = CommandPlan::new(
        "magick",
        vec![
            embedded_preview_arg.clone(),
            OsString::from("-auto-orient"),
            OsString::from("jpg:-"),
        ],
    )
    .with_stdout_file(oriented_preview_path);
    let encode = CommandPlan::new(
        "heif-enc",
        vec![
            OsString::from("-q"),
            OsString::from(input.heic_quality.to_string()),
            oriented_preview_arg.clone(),
            OsString::from("-o"),
            input.output_arg.clone(),
        ],
    );

    Ok(ConversionPlan {
        convert: extract_preview.clone(),
        conversion_commands: vec![
            extract_preview,
            copy_preview_orientation,
            orient_preview_pixels,
            encode,
        ],
        metadata: CommandPlan::new(
            "exiftool",
            vec![
                OsString::from("-TagsFromFile"),
                input.raw_arg.clone(),
                OsString::from("-all:all"),
                OsString::from("-Orientation#=1"),
                OsString::from("-QuickTime:Rotation#=0"),
                OsString::from("-overwrite_original"),
                input.output_arg.clone(),
            ],
        ),
        verify_image: CommandPlan::new("heif-info", vec![input.output_arg.clone()]),
        render_raw_preview: CommandPlan::new(
            "magick",
            vec![
                oriented_preview_arg,
                OsString::from("-resize"),
                OsString::from("512x512"),
                input.raw_preview_arg.clone(),
            ],
        ),
        render_heic_preview: CommandPlan::new(
            "magick",
            vec![
                input.output_arg.clone(),
                OsString::from("-resize"),
                OsString::from("512x512"),
                input.heic_preview_arg.clone(),
            ],
        ),
        verify_visual_content: CommandPlan::new(
            "magick",
            vec![
                input.heic_preview_arg.clone(),
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
                input.raw_preview_arg,
                input.heic_preview_arg,
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
                input.output_arg,
            ],
        ),
    })
}

fn intermediate_preview_path(output_path: &Path) -> PathBuf {
    let mut preview_path = output_path.to_path_buf();
    preview_path.set_extension("embedded-preview.jpg");
    preview_path
}

fn oriented_preview_path(output_path: &Path) -> PathBuf {
    let mut preview_path = output_path.to_path_buf();
    preview_path.set_extension("oriented-preview.jpg");
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
