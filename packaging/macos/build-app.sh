#!/usr/bin/env bash
set -euo pipefail

app_name="iCloudPD Optimizer"
bundle_id="com.icloudpd-optimizer.dashboard"
service_app_name="iCloudPD Optimizer Service"
service_bundle_id="com.icloudpd-optimizer.monitor"
binary_path="target/release/icloudpd-optimizer"
output_dir="dist"
sign_identity=""
config_path=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      app_name="$2"
      shift 2
      ;;
    --bundle-id)
      bundle_id="$2"
      shift 2
      ;;
    --service-name)
      service_app_name="$2"
      shift 2
      ;;
    --service-bundle-id)
      service_bundle_id="$2"
      shift 2
      ;;
    --bin)
      binary_path="$2"
      shift 2
      ;;
    --output)
      output_dir="$2"
      shift 2
      ;;
    --sign)
      sign_identity="$2"
      shift 2
      ;;
    --config)
      config_path="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS app bundles can only be built on macOS" >&2
  exit 1
fi

if [ ! -f "$binary_path" ]; then
  echo "binary does not exist: $binary_path" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"

build_bundle() {
  local name="$1"
  local id="$2"
  local agent_mode="$3"
  local app_path="$output_dir/$name.app"
  local contents_path="$app_path/Contents"
  local macos_path="$contents_path/MacOS"
  local resources_path="$contents_path/Resources"

  rm -rf "$app_path"
  mkdir -p "$macos_path" "$resources_path"
  xcrun swiftc \
    -O \
    -framework AppKit \
    -framework SwiftUI \
    -framework Combine \
    "$script_dir/ICloudPDOptimizerApp.swift" \
    -o "$macos_path/ICloudPDOptimizerApp"
  cp "$binary_path" "$resources_path/icloudpd-optimizer"
  chmod 755 "$macos_path/ICloudPDOptimizerApp" "$resources_path/icloudpd-optimizer"

  cat > "$contents_path/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>ICloudPDOptimizerApp</string>
  <key>CFBundleIdentifier</key>
  <string>$id</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$name</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>0.1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSMultipleInstancesProhibited</key>
  <true/>
  <key>NSNetworkVolumesUsageDescription</key>
  <string>iCloudPD Optimizer needs access to your NAS mirror to verify local RAW backups before converting and replacing iCloud originals.</string>
  <key>NSRemovableVolumesUsageDescription</key>
  <string>iCloudPD Optimizer needs access to configured photo storage volumes when they are mounted as removable storage.</string>
  <key>NSDocumentsFolderUsageDescription</key>
  <string>iCloudPD Optimizer needs access to configured photo and service folders when they are stored under Documents.</string>
PLIST
  if [ "$agent_mode" = "1" ]; then
    cat >> "$contents_path/Info.plist" <<PLIST
  <key>LSUIElement</key>
  <true/>
PLIST
  fi
  cat >> "$contents_path/Info.plist" <<PLIST
</dict>
</plist>
PLIST

  if [ -n "$config_path" ]; then
    printf '%s\n' "$config_path" > "$resources_path/monitor-config-path"
  fi

  if [ -n "$sign_identity" ]; then
    codesign --force --options runtime --timestamp=none --sign "$sign_identity" "$resources_path/icloudpd-optimizer"
    codesign --force --options runtime --timestamp=none --sign "$sign_identity" "$macos_path/ICloudPDOptimizerApp"
    codesign --force --options runtime --timestamp=none --sign "$sign_identity" "$app_path"
  else
    codesign --force --sign - "$resources_path/icloudpd-optimizer"
    codesign --force --sign - "$macos_path/ICloudPDOptimizerApp"
    codesign --force --sign - "$app_path"
  fi

  codesign --verify --deep --strict "$app_path"
  echo "$app_path"
}

build_bundle "$app_name" "$bundle_id" 0
build_bundle "$service_app_name" "$service_bundle_id" 1
