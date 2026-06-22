# Contributing

Thanks for contributing to `icloudpd-optimizer`. This project handles workflows that
can eventually lead to original media deletion, so changes should be conservative,
auditable, and fail closed.

## Development Setup

Install Rust and the external media tools used by the CLI:

```sh
cargo --version
vips --version
vipsheader --version
exiftool -ver
```

Build and test locally:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Contribution Guidelines

- Keep destructive actions out of the tool unless they are guarded by fresh proof
  revalidation and explicit operator intent.
- Prefer structured manifests and typed proofs over ad hoc text parsing.
- Add tests for every workflow transition, especially failure paths that must not mutate
  the manifest.
- Keep examples generic. Do not include local paths, private hostnames, credentials,
  tokens, usernames, phone numbers, or production asset identifiers.
- Do not add generated build artifacts, local manifests, media files, or machine-specific
  configuration.
- Update README examples when CLI names, arguments, or workflow sequencing change.

## Pull Requests

Each pull request should include:

- A short description of the behavior change.
- The safety impact, especially whether any delete-plan gate changed.
- The verification commands that passed.

The expected verification gate is:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
