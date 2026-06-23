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
        printf '  note: workflow convert is macOS host-native; sips is not required for proof/upload/delete-plan workflows on this platform.\n'
        ;;
    esac

    require_tool heif-info 'macOS: brew install libheif; Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y libheif-examples'
    require_tool magick 'macOS: brew install imagemagick; Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y imagemagick'
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
