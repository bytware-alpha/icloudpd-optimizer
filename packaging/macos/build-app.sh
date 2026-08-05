#!/usr/bin/env bash
set -euo pipefail

app_name="iCloudPD Optimizer"
bundle_id="com.icloudpd-optimizer.dashboard"
service_app_name="iCloudPD Optimizer Service"
service_bundle_id="com.icloudpd-optimizer.monitor"
binary_path="target/release/icloudpd-optimizer"
output_dir="dist"
sign_identity=""
keychain_path=""
config_path=""
authority_path=""

fail_build() {
  printf '%s\n' "$1" >&2
  exit 2
}

codesign_redacted() {
  if ! codesign "$@" >/dev/null 2>&1; then
    fail_build "macOS signing operation failed"
  fi
}

codesign_verify_redacted() {
  if ! codesign --verify "$@" >/dev/null 2>&1; then
    fail_build "macOS signature verification failed"
  fi
}

codesign_designated_requirement_equals() {
  local expected_requirement="$1"
  local signed_path="$2"
  local actual_requirement=""

  if ! actual_requirement="$(codesign -d -r- "$signed_path" 2>&1 | awk '
    /^designated => / { print; found = 1 }
    END { exit found ? 0 : 1 }
  ')" || [ "$actual_requirement" != "$expected_requirement" ]; then
    fail_build "macOS designated requirement verification failed"
  fi
}

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
    --keychain)
      keychain_path="$2"
      shift 2
      ;;
    --config)
      config_path="$2"
      shift 2
      ;;
    --authority)
      authority_path="$2"
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
if [ -z "$authority_path" ] || [ ! -f "$authority_path" ]; then
  echo "an explicit authorization authority is required" >&2
  exit 2
fi
if ! jq -e . "$authority_path" >/dev/null; then
  echo "authorization authority is malformed" >&2
  exit 2
fi
authority_mode="$(jq -r '.mode // empty' "$authority_path")"
if [ "$authority_mode" != "production" ] && [ "$authority_mode" != "disabled" ]; then
  echo "authorization authority mode is invalid" >&2
  exit 2
fi
if [ "$authority_mode" = "production" ] && [ -z "$sign_identity" ]; then
  echo "production authority rejects ad-hoc signing" >&2
  exit 2
fi
if [ "$authority_mode" = "production" ] && [ -z "$keychain_path" ]; then
  echo "production authority requires an explicit canonical login keychain" >&2
  exit 2
fi
if [ "$authority_mode" = "disabled" ] && [ -n "$sign_identity" ]; then
  echo "disabled authority is only for ad-hoc development builds" >&2
  exit 2
fi
if [ "$authority_mode" = "production" ]; then
  if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    echo "production authority requires a clean tracked and untracked source tree" >&2
    exit 2
  fi
  expected_dashboard_id="$(jq -r '.dashboard_bundle_identifier // empty' "$authority_path")"
  expected_service_id="$(jq -r '.service_bundle_identifier // empty' "$authority_path")"
  authority_kind="$(jq -r '.authority_kind // empty' "$authority_path")"
  authority_team="$(jq -r '.team_id // empty' "$authority_path")"
  helper_requirement="$(jq -r '.helper_designated_requirement // empty' "$authority_path")"
  dashboard_requirement="$(jq -r '.dashboard_designated_requirement // empty' "$authority_path")"
  service_requirement="$(jq -r '.service_designated_requirement // empty' "$authority_path")"
  canonical_requirement() {
    printf 'designated => anchor apple generic and identifier "%s" and certificate leaf[subject.OU] = "%s"' "$1" "$authority_team"
  }
  if [ "$authority_kind" != "apple_development_team" ] \
    || ! printf '%s' "$authority_team" | grep -Eq '^[A-Z0-9]{10}$' \
    || [ "$helper_requirement" != "$(canonical_requirement com.icloudpd-optimizer.helper)" ] \
    || [ "$dashboard_requirement" != "$(canonical_requirement "$expected_dashboard_id")" ] \
    || [ "$service_requirement" != "$(canonical_requirement "$expected_service_id")" ]; then
    fail_build "production authority is malformed"
  fi
  if [ "$bundle_id" != "$expected_dashboard_id" ] || [ "$service_bundle_id" != "$expected_service_id" ]; then
    echo "production authority bundle identifiers do not match" >&2
    exit 2
  fi
  effective_uid="$(id -u)"
  effective_user="$(id -un 2>/dev/null || true)"
  account_record="$(id -P 2>/dev/null || true)"
  record_count="$(printf '%s\n' "$account_record" | awk 'END { print NR }')"
  if [ "$(printf '%s\n' "$effective_user" | sed '/^$/d' | wc -l | tr -d ' ')" != "1" ] \
    || [ "$record_count" != "1" ] \
    || ! printf '%s\n' "$account_record" | awk -F: '
      NR == 1 {
        if (NF != 10 || $1 == "" || $3 !~ /^[0-9]+$/ || $9 == "" || $9 !~ /^\// || index($9, ":") != 0) invalid = 1
      }
      NR != 1 { invalid = 1 }
      END { exit NR == 1 && !invalid ? 0 : 1 }
    '; then
    fail_build "production authority could not resolve the effective account"
  fi
  trusted_user="$(printf '%s\n' "$account_record" | awk -F: 'NF { print $1 }')"
  trusted_uid="$(printf '%s\n' "$account_record" | awk -F: 'NF { print $3 }')"
  trusted_home="$(printf '%s\n' "$account_record" | awk -F: 'NR == 1 { print $9 }')"
  if [ "$trusted_user" != "$effective_user" ] || [ "$trusted_uid" != "$effective_uid" ]; then
    fail_build "production authority effective account does not match the POSIX account record"
  fi
  expected_keychain="$trusted_home/Library/Keychains/login.keychain-db"
  if [ "$keychain_path" != "$expected_keychain" ]; then
    fail_build "production authority keychain is not the canonical login keychain"
  fi
  for keychain_component in "$trusted_home" "$trusted_home/Library" "$trusted_home/Library/Keychains" "$expected_keychain"; do
    if [ -L "$keychain_component" ] || [ ! -e "$keychain_component" ]; then
      fail_build "production authority keychain path is unsafe"
    fi
    component_owner="$(stat -f '%u' "$keychain_component" 2>/dev/null || true)"
    component_mode="$(stat -f '%Lp' "$keychain_component" 2>/dev/null || true)"
    component_type="$(stat -f '%HT' "$keychain_component" 2>/dev/null || true)"
    if [ "$component_owner" != "$effective_uid" ] || [ -z "$component_mode" ] \
      || [ $((0$component_mode & 0022)) -ne 0 ]; then
      fail_build "production authority keychain path is unsafe"
    fi
    # The final keychain database is Security.framework-managed data, not an
    # executable admission surface.  Keep quarantine rejection on the path
    # directories, where it can affect path resolution, but do not reject the
    # canonical non-executable database solely for that metadata.
    if [ "$keychain_component" != "$expected_keychain" ] \
      && xattr -p com.apple.quarantine "$keychain_component" >/dev/null 2>&1; then
      fail_build "production authority keychain path is unsafe"
    fi
  done
  if [ "$(stat -f '%HT' "$trusted_home" 2>/dev/null || true)" != "Directory" ] \
    || [ "$(stat -f '%HT' "$trusted_home/Library" 2>/dev/null || true)" != "Directory" ] \
    || [ "$(stat -f '%HT' "$trusted_home/Library/Keychains" 2>/dev/null || true)" != "Directory" ] \
    || [ "$(stat -f '%HT' "$expected_keychain" 2>/dev/null || true)" != "Regular File" ]; then
    fail_build "production authority keychain path is unsafe"
  fi
  canonical_keychain="$(realpath "$expected_keychain" 2>/dev/null || true)"
  provided_keychain="$(realpath "$keychain_path" 2>/dev/null || true)"
  if [ "$canonical_keychain" != "$expected_keychain" ] || [ "$provided_keychain" != "$canonical_keychain" ]; then
    fail_build "production authority keychain is not the canonical login keychain"
  fi
  keychain_path="$expected_keychain"
  if ! identity_listing="$(security find-identity -v -p codesigning "$expected_keychain" 2>/dev/null)"; then
    fail_build "production authority signing identity lookup failed"
  fi
  requested_identity_sha1="$(printf '%s' "$sign_identity" | tr '[:lower:]' '[:upper:]')"
  identity_matches="$(printf '%s\n' "$identity_listing" | awk -v expected="$sign_identity" -v requested="$requested_identity_sha1" '
    /^[[:space:]]*[0-9]+\)[[:space:]]+[0-9A-Fa-f]{40}[[:space:]]+"/ {
      hash = $2; label = $0; sub(/^[^"]*"/, "", label); sub(/"[[:space:]]*$/, "", label)
      if (label == expected || toupper(hash) == requested) print toupper(hash)
    }
  ')"
  if [ "$(printf '%s\n' "$identity_matches" | sed '/^$/d' | wc -l | tr -d ' ')" != "1" ]; then
    fail_build "production authority requires exactly one explicit signing identity"
  fi
  leaf_sha1="$identity_matches"
  signing_probe="$(mktemp "${TMPDIR:-/tmp}/icloudpd-optimizer-codesign-probe.XXXXXX")"
  cleanup_signing_probe() { rm -f "$signing_probe"; }
  trap cleanup_signing_probe EXIT HUP INT TERM
  probe_team=""
  if ! codesign --force --options runtime --timestamp=none --keychain "$expected_keychain" --sign "$leaf_sha1" "$signing_probe" >/dev/null 2>&1 \
    || ! codesign --verify --strict "$signing_probe" >/dev/null 2>&1 \
    || ! probe_team="$(codesign -dvv "$signing_probe" 2>&1 | awk -F= '/^TeamIdentifier=/ { print $2 }')" \
    || [ "$probe_team" != "$authority_team" ]; then
    fail_build "production authority noninteractive signing probe failed"
  fi
  rm -f "$signing_probe"
  trap - EXIT HUP INT TERM
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
  local host_requirement=""

  if [ "$authority_mode" = "production" ]; then
    if [ "$id" = "$service_bundle_id" ]; then
      host_requirement="$service_requirement"
    else
      host_requirement="$dashboard_requirement"
    fi
  fi

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
  cp "$authority_path" "$resources_path/authorization-policy.json"
  chmod 755 "$macos_path/ICloudPDOptimizerApp" "$resources_path/icloudpd-optimizer"

  # The provenance hashes the final signed helper, before host signing seals it as a resource.
  if [ -n "$sign_identity" ]; then
    codesign_redacted --force --options runtime --timestamp=none --identifier com.icloudpd-optimizer.helper --keychain "$keychain_path" --sign "${leaf_sha1:-$sign_identity}" -r="$helper_requirement" "$resources_path/icloudpd-optimizer"
  else
    codesign_redacted --force --identifier com.icloudpd-optimizer.helper --sign - "$resources_path/icloudpd-optimizer"
  fi

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
  <key>NSLocalNetworkUsageDescription</key>
  <string>iCloudPD Optimizer needs local network access to connect directly to your configured NAS and verify atomic backup operations.</string>
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

  helper_sha256="$(shasum -a 256 "$resources_path/icloudpd-optimizer" | awk '{print $1}')"
  authority_sha256="$(shasum -a 256 "$resources_path/authorization-policy.json" | awk '{print $1}')"
  source_commit="$(git rev-parse HEAD)"
  cat > "$resources_path/authorization-provenance.json" <<JSON
{"schema_version":1,"source_commit":"$source_commit","authority_sha256":"$authority_sha256","helper_sha256":"$helper_sha256","helper_identifier":"com.icloudpd-optimizer.helper","dashboard_bundle_identifier":"$bundle_id","service_bundle_identifier":"$service_bundle_id","helper_relative_path":"Contents/Resources/icloudpd-optimizer","service_install_relative_path":"Library/Application Support/iCloudPD Optimizer/Service/iCloudPD Optimizer Service.app","owner":"effective_user"}
JSON
  chmod 644 "$resources_path/authorization-policy.json" "$resources_path/authorization-provenance.json"

  if [ -n "$sign_identity" ]; then
    codesign_redacted --force --options runtime --timestamp=none --identifier "$id" --keychain "$keychain_path" --sign "${leaf_sha1:-$sign_identity}" -r="$host_requirement" "$macos_path/ICloudPDOptimizerApp"
    codesign_redacted --force --options runtime --timestamp=none --identifier "$id" --keychain "$keychain_path" --sign "${leaf_sha1:-$sign_identity}" -r="$host_requirement" "$app_path"
  else
    codesign_redacted --force --identifier "$id" --sign - "$macos_path/ICloudPDOptimizerApp"
    codesign_redacted --force --identifier "$id" --sign - "$app_path"
  fi

  if [ "$authority_mode" = "production" ]; then
    codesign_verify_redacted --strict "-R=${helper_requirement#designated => }" "$resources_path/icloudpd-optimizer"
    codesign_verify_redacted --strict "-R=${host_requirement#designated => }" "$macos_path/ICloudPDOptimizerApp"
    codesign_verify_redacted --strict "-R=${host_requirement#designated => }" "$app_path"
    codesign_designated_requirement_equals "$helper_requirement" "$resources_path/icloudpd-optimizer"
    codesign_designated_requirement_equals "$host_requirement" "$macos_path/ICloudPDOptimizerApp"
    codesign_designated_requirement_equals "$host_requirement" "$app_path"
  fi

  codesign_verify_redacted --deep --strict "$app_path"
  echo "$app_path"
}

if [ "$authority_mode" = "production" ]; then
  build_bundle "$app_name" "$bundle_id" 0 >/dev/null
  build_bundle "$service_app_name" "$service_bundle_id" 1 >/dev/null
  echo "production bundles built"
else
  build_bundle "$app_name" "$bundle_id" 0
  build_bundle "$service_app_name" "$service_bundle_id" 1
fi
