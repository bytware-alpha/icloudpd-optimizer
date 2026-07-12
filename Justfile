# List available recipes.
default:
    @just --list

# List available recipes.
list:
    @just --list

# Check local Rust tooling and platform-specific runtime dependencies.
setup:
    #!/usr/bin/env sh
    set -eu

    missing=0

    require_tool() {
      tool="$1"
      install_hint="$2"

      if command -v "$tool" >/dev/null 2>&1; then
        printf 'ok: %s\n' "$tool"
      else
        printf 'missing: %s\n' "$tool"
        printf '  install: %s\n' "$install_hint"
        missing=1
      fi
    }

    require_tool cargo 'install Rust from https://rustup.rs'
    require_tool rustfmt 'rustup component add rustfmt'
    require_tool cargo-clippy 'rustup component add clippy'

    case "$(uname -s)" in
      Darwin)
        require_tool sips 'macOS: bundled with the OS'
        ;;
      *)
        printf 'skip: sips\n'
        printf '  note: Linux workflow convert uses exiftool, ImageMagick, and heif-enc instead of sips.\n'
        require_tool heif-enc 'Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y libheif-examples'
        ;;
    esac

    require_tool heif-info 'macOS: brew install libheif; Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y libheif-examples'
    require_tool magick 'macOS: brew install imagemagick; Debian/Ubuntu source installs need an ImageMagick magick command or a compatible convert/compare wrapper'
    require_tool exiftool 'macOS: brew install exiftool; Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y libimage-exiftool-perl'

    if command -v cargo >/dev/null 2>&1; then
      cargo build --locked
      cargo run --locked -- doctor --json
    fi

    if [ "$missing" -ne 0 ]; then
      printf '\nInstall the missing tools above, then rerun: just setup\n'
      exit 1
    fi

    printf '\nSetup checks passed. Run just check before opening a pull request.\n'

# Run formatting, clippy, and tests.
check:
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked

# Build and install the CLI into a local prefix.
install prefix='$HOME/.local':
    cargo build --release --locked
    mkdir -p "{{prefix}}/bin"
    cp target/release/icloudpd-optimizer "{{prefix}}/bin/icloudpd-optimizer"
    "{{prefix}}/bin/icloudpd-optimizer" doctor --json

# Build a signed macOS app bundle that owns the Network Volumes privacy prompt.
macos-app:
    #!/usr/bin/env sh
    set -eu
    cargo build --release --locked
    output="${ICLOUDPD_OPTIMIZER_APP_OUTPUT:-dist}"
    identity="${ICLOUDPD_OPTIMIZER_SIGN_IDENTITY:-}"
    config="${ICLOUDPD_OPTIMIZER_MONITOR_CONFIG:-}"
    set -- --bin target/release/icloudpd-optimizer --output "$output"
    if [ -n "$identity" ]; then
      set -- "$@" --sign "$identity"
    fi
    if [ -n "$config" ]; then
      set -- "$@" --config "$config"
    fi
    packaging/macos/build-app.sh "$@"

# Install the built macOS app bundle into ~/Applications.
macos-app-install:
    #!/usr/bin/env sh
    set -eu
    verify_bundle_value() {
      bundle="$1"
      key="$2"
      expected="$3"
      actual="$(/usr/libexec/PlistBuddy -c "Print :$key" "$bundle/Contents/Info.plist")"
      if [ "$actual" != "$expected" ]; then
        printf 'invalid %s for %s: expected %s, got %s\n' "$key" "$bundle" "$expected" "$actual" >&2
        exit 1
      fi
    }
    reject_true_bundle_value() {
      bundle="$1"
      key="$2"
      actual="$(/usr/libexec/PlistBuddy -c "Print :$key" "$bundle/Contents/Info.plist" 2>/dev/null || true)"
      if [ "$actual" = "true" ]; then
        printf 'invalid %s for dashboard bundle: must not be true\n' "$key" >&2
        exit 1
      fi
    }
    replace_verified_bundle() {
      staged="$1"
      installed="$2"
      backup="$3"
      rm -rf "$backup"
      if [ -e "$installed" ]; then
        mv "$installed" "$backup"
      fi
      mv "$staged" "$installed"
    }
    restore_bundle() {
      installed="$1"
      backup="$2"
      had_installed="$3"
      if [ -e "$backup" ]; then
        rm -rf "$installed"
        mv "$backup" "$installed"
      elif [ "$had_installed" -eq 0 ]; then
        rm -rf "$installed"
        rm -rf "$backup"
      fi
    }
    wait_for_dashboard_hosts() {
      pattern="$1"
      dashboard_waits=0
      while pgrep -f -x "$pattern" >/dev/null; do
        dashboard_waits=$((dashboard_waits + 1))
        if [ "$dashboard_waits" -eq 20 ]; then
          pkill -KILL -f -x "$pattern" || true
        elif [ "$dashboard_waits" -ge 40 ]; then
          printf 'dashboard host did not terminate: %s\n' "$pattern" >&2
          return 1
        fi
        sleep 0.25
      done
    }
    output="${ICLOUDPD_OPTIMIZER_APP_OUTPUT:-dist}"
    app="$output/iCloudPD Optimizer.app"
    service_app="$output/iCloudPD Optimizer Service.app"
    destination="${ICLOUDPD_OPTIMIZER_APP_INSTALL_DIR:-$HOME/Applications}"
    service_destination="${ICLOUDPD_OPTIMIZER_SERVICE_APP_INSTALL_DIR:-$HOME/Library/Application Support/iCloudPD Optimizer/Service}"
    if [ ! -d "$app" ]; then
      printf 'missing app bundle: %s\n' "$app" >&2
      printf 'run: just macos-app\n' >&2
      exit 1
    fi
    if [ ! -d "$service_app" ]; then
      printf 'missing service app bundle: %s\n' "$service_app" >&2
      printf 'run: just macos-app\n' >&2
      exit 1
    fi
    mkdir -p "$destination" "$service_destination"
    installed_app="$destination/iCloudPD Optimizer.app"
    installed_service_app="$service_destination/iCloudPD Optimizer Service.app"
    legacy_service_app="$destination/iCloudPD Optimizer Service.app"
    staged_app="$destination/.iCloudPD Optimizer.app.install.$$"
    staged_service_app="$service_destination/.iCloudPD Optimizer Service.app.install.$$"
    dashboard_backup="${installed_app}.backup.$$"
    service_backup="${installed_service_app}.backup.$$"
    dashboard_had_installed=0
    service_had_installed=0
    dashboard_replaced=0
    service_replaced=0
    if [ -e "$installed_app" ]; then
      dashboard_had_installed=1
    fi
    if [ -e "$installed_service_app" ]; then
      service_had_installed=1
    fi
    rollback_replacements() {
      if [ "$dashboard_replaced" -eq 1 ]; then
        restore_bundle "$installed_app" "$dashboard_backup" "$dashboard_had_installed"
        dashboard_replaced=0
      fi
      if [ "$service_replaced" -eq 1 ]; then
        restore_bundle "$installed_service_app" "$service_backup" "$service_had_installed"
        service_replaced=0
      fi
    }
    cleanup_staged_bundles() {
      rollback_replacements
      rm -rf "$staged_app" "$staged_service_app"
    }
    abort_install() {
      exit 1
    }
    trap cleanup_staged_bundles EXIT
    trap abort_install HUP INT TERM
    cleanup_staged_bundles
    ditto "$app" "$staged_app"
    ditto "$service_app" "$staged_service_app"
    codesign --verify --deep --strict "$staged_app"
    verify_bundle_value "$staged_app" CFBundleIdentifier com.icloudpd-optimizer.dashboard
    verify_bundle_value "$staged_app" CFBundleExecutable ICloudPDOptimizerApp
    reject_true_bundle_value "$staged_app" LSBackgroundOnly
    reject_true_bundle_value "$staged_app" LSUIElement
    codesign --verify --deep --strict "$staged_service_app"
    dashboard_host="$installed_app/Contents/MacOS/ICloudPDOptimizerApp"
    escaped_dashboard_host="$(printf '%s\n' "$dashboard_host" | sed 's/[][\\.^$*+?(){}|]/\\&/g')"
    dashboard_host_pattern="${escaped_dashboard_host}([[:space:]].*)?"
    if pgrep -f -x "$dashboard_host_pattern" >/dev/null; then
      pkill -TERM -f -x "$dashboard_host_pattern" || true
      wait_for_dashboard_hosts "$dashboard_host_pattern"
    fi
    rm -rf "$legacy_service_app"
    service_replaced=1
    replace_verified_bundle "$staged_service_app" "$installed_service_app" "$service_backup"
    dashboard_replaced=1
    replace_verified_bundle "$staged_app" "$installed_app" "$dashboard_backup"
    codesign --verify --deep --strict "$installed_app"
    verify_bundle_value "$installed_app" CFBundleIdentifier com.icloudpd-optimizer.dashboard
    verify_bundle_value "$installed_app" CFBundleExecutable ICloudPDOptimizerApp
    reject_true_bundle_value "$installed_app" LSBackgroundOnly
    reject_true_bundle_value "$installed_app" LSUIElement
    codesign --verify --deep --strict "$installed_service_app"
    service_replaced=0 dashboard_replaced=0
    rm -rf "$service_backup" "$dashboard_backup"
    printf '%s\n' "$installed_app"
    printf '%s\n' "$installed_service_app"

# Open the installed macOS dashboard app.
macos-app-launch:
    #!/usr/bin/env sh
    set -eu
    installed_app="${ICLOUDPD_OPTIMIZER_APP_PATH:-$HOME/Applications/iCloudPD Optimizer.app}"
    wait_for_dashboard_hosts() {
      pattern="$1"
      dashboard_waits=0
      while pgrep -f -x "$pattern" >/dev/null; do
        dashboard_waits=$((dashboard_waits + 1))
        if [ "$dashboard_waits" -eq 20 ]; then
          pkill -KILL -f -x "$pattern" || true
        elif [ "$dashboard_waits" -ge 40 ]; then
          printf 'dashboard host did not terminate: %s\n' "$pattern" >&2
          return 1
        fi
        sleep 0.25
      done
    }
    installed_host="$installed_app/Contents/MacOS/ICloudPDOptimizerApp"
    escaped_installed_host="$(printf '%s\n' "$installed_host" | sed 's/[][\\.^$*+?(){}|]/\\&/g')"
    installed_host_pattern="${escaped_installed_host}([[:space:]].*)?"
    if ! pgrep -f -x "$installed_host_pattern" >/dev/null; then
      dashboard_host_pattern='.*/ICloudPDOptimizerApp'
      if pgrep -f -x "$dashboard_host_pattern" >/dev/null; then
        pkill -TERM -f -x "$dashboard_host_pattern" || true
        wait_for_dashboard_hosts "$dashboard_host_pattern"
      fi
    fi
    open "$installed_app"

# Install the per-user LaunchAgent through the macOS app binary.
macos-app-service-install config:
    #!/usr/bin/env sh
    set -eu
    app="${ICLOUDPD_OPTIMIZER_SERVICE_APP_PATH:-$HOME/Library/Application Support/iCloudPD Optimizer/Service/iCloudPD Optimizer Service.app}"
    bin="$app/Contents/MacOS/ICloudPDOptimizerApp"
    "$bin" service install \
      --config "{{config}}" \
      --bin "$bin" \
      --associated-bundle-id com.icloudpd-optimizer.monitor

# Start the per-user macOS LaunchAgent installed by macos-app-service-install.
macos-app-service-start:
    #!/usr/bin/env sh
    set -eu
    app="${ICLOUDPD_OPTIMIZER_SERVICE_APP_PATH:-$HOME/Library/Application Support/iCloudPD Optimizer/Service/iCloudPD Optimizer Service.app}"
    "$app/Contents/MacOS/ICloudPDOptimizerApp" service start

# Verify the installed app, helper, LaunchAgent status, and app log path.
macos-app-verify:
    #!/usr/bin/env sh
    set -eu
    app="${ICLOUDPD_OPTIMIZER_APP_PATH:-$HOME/Applications/iCloudPD Optimizer.app}"
    service_app="${ICLOUDPD_OPTIMIZER_SERVICE_APP_PATH:-$HOME/Library/Application Support/iCloudPD Optimizer/Service/iCloudPD Optimizer Service.app}"
    dashboard_bin="$app/Contents/MacOS/ICloudPDOptimizerApp"
    bin="$service_app/Contents/MacOS/ICloudPDOptimizerApp"
    helper="$app/Contents/Resources/icloudpd-optimizer"
    codesign --verify --deep --strict "$app"
    codesign --verify --deep --strict "$service_app"
    "$dashboard_bin" --bundled-helper-environment-self-test
    "$helper" doctor --json
    "$bin" service status || true
    if [ -f "$HOME/Library/Logs/iCloudPD Optimizer/app.log" ]; then
      tail -n 20 "$HOME/Library/Logs/iCloudPD Optimizer/app.log"
    fi

# Build the standard OCI Linux image with Apple container.
apple-image-build tag='icloudpd-optimizer:local':
    container build --tag {{tag}} --file container/Containerfile .

# Run doctor inside the Apple container-built OCI image.
apple-image-doctor tag='icloudpd-optimizer:local':
    container run --rm {{tag}} doctor --json

# Smoke-test the same OCI image with another Linux OCI runtime.
oci-image-smoke tag='icloudpd-optimizer:local' runtime='podman':
    {{runtime}} run --rm {{tag}} doctor --json

# Run the test suite.
test:
    cargo test --locked
