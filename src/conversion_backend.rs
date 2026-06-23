const MACOS_REQUIRED_TOOLS: [&str; 4] = ["sips", "heif-info", "magick", "exiftool"];
const NON_MACOS_REQUIRED_TOOLS: [&str; 3] = ["heif-info", "magick", "exiftool"];

/// Compile-target platform used to decide whether host-native conversion is supported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetPlatform {
    pub os: &'static str,
    pub arch: &'static str,
}

impl TargetPlatform {
    /// Builds a target platform report key.
    ///
    /// ```
    /// use icloudpd_optimizer::conversion_backend::TargetPlatform;
    ///
    /// let target = TargetPlatform::new("linux", "x86_64");
    /// assert_eq!(target.os, "linux");
    /// assert_eq!(target.arch, "x86_64");
    /// ```
    pub const fn new(os: &'static str, arch: &'static str) -> Self {
        Self { os, arch }
    }

    /// Returns the platform of the currently compiled binary.
    pub const fn current() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        }
    }
}

/// Backend support status for host-native RAW-to-HEIC conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversionBackendReport {
    pub name: &'static str,
    pub workflow_convert_supported: bool,
    pub reason: &'static str,
}

/// Reports the conversion backend for a specific target platform.
///
/// ```
/// use icloudpd_optimizer::conversion_backend::{TargetPlatform, backend_report_for_target};
///
/// let report = backend_report_for_target(TargetPlatform::new("linux", "x86_64"));
/// assert_eq!(report.name, "manual-proof-linux");
/// assert!(!report.workflow_convert_supported);
/// ```
pub fn backend_report_for_target(target: TargetPlatform) -> ConversionBackendReport {
    match target.os {
        "macos" => ConversionBackendReport {
            name: "macos-sips",
            workflow_convert_supported: true,
            reason: "workflow convert is supported by the macOS host-native sips backend",
        },
        "linux" => ConversionBackendReport {
            name: "manual-proof-linux",
            workflow_convert_supported: false,
            reason: "workflow convert requires macOS sips; this Linux target supports proof and manifest workflows only",
        },
        _ => ConversionBackendReport {
            name: "unsupported-host",
            workflow_convert_supported: false,
            reason: "workflow convert requires macOS sips; this target has no supported host-native conversion backend",
        },
    }
}

/// Reports the backend for the currently compiled binary.
pub fn current_backend_report() -> ConversionBackendReport {
    backend_report_for_target(TargetPlatform::current())
}

/// Lists tools required by the current target's supported workflow surface.
///
/// ```
/// use icloudpd_optimizer::conversion_backend::{TargetPlatform, required_tools_for_target};
///
/// let tools = required_tools_for_target(TargetPlatform::new("linux", "x86_64"));
/// assert!(!tools.contains(&"sips"));
/// assert!(tools.contains(&"heif-info"));
/// ```
pub fn required_tools_for_target(target: TargetPlatform) -> &'static [&'static str] {
    match target.os {
        "macos" => &MACOS_REQUIRED_TOOLS,
        _ => &NON_MACOS_REQUIRED_TOOLS,
    }
}
