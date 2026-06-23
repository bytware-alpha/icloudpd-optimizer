# List available recipes.
default:
    @just --list

# List available recipes.
list:
    @just --list

# Check local Rust tooling and runtime conversion dependencies.
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
    require_tool sips 'macOS: bundled with the OS'
    require_tool heif-info 'macOS: brew install libheif'
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

# Run the test suite.
test:
    cargo test --locked
