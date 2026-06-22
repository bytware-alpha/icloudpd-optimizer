# icloudpd-optimizer

`icloudpd-optimizer` is a fail-closed helper for safely optimizing iCloud Photos
libraries managed by iCloudPD. Its first workflow focuses on RAW originals: prove the
RAW file is already captured on durable storage, record a verified HEIC replacement,
and produce an auditable delete plan only after every required proof is present.

The tool is intentionally conservative. It does not delete originals on its own, and it
does not treat a conversion or upload as trustworthy until the manifest contains
matching proofs for the file paths, hashes, sizes, age, and operator approval.

## What It Does

- Tracks each asset through explicit workflow states in a JSON manifest.
- Proves RAW files are inside a configured storage root before they can progress.
- Hashes RAW and HEIC files so later steps can detect changed bytes.
- Records conversion, HEIC verification, upload, source-age, and approval proofs.
- Revalidates persisted proofs before emitting a delete plan.
- Fails closed when a required proof is missing, stale, malformed, or inconsistent.

## What It Does Not Do

- It does not replace iCloudPD.
- It does not automatically upload files to iCloud.
- It does not automatically delete RAW originals.
- It does not bypass manual review or operator approval.

## Requirements

- Rust 2024 toolchain
- `vips`
- `vipsheader`
- `exiftool`

Run the doctor command to check required tools:

```sh
icloudpd-optimizer doctor --json
```

## Install From Source

```sh
cargo install --path . --locked
```

## Workflow Overview

The workflow records proofs into a manifest file. A typical integration is expected to
call these stages from a higher-level sync job:

```sh
icloudpd-optimizer workflow nas-verified \
  --manifest manifest.json \
  --asset-id <asset-id> \
  --raw-path <path-to-raw> \
  --nas-root <storage-root> \
  --min-age-days 30

icloudpd-optimizer workflow conversion-recorded \
  --manifest manifest.json \
  --asset-id <asset-id> \
  --heic-path <path-to-heic> \
  --heic-sha256 <sha256> \
  --size-bytes <bytes>

icloudpd-optimizer workflow heic-verified \
  --manifest manifest.json \
  --asset-id <asset-id> \
  --heic-path <path-to-heic> \
  --heic-sha256 <sha256> \
  --size-bytes <bytes> \
  --vipsheader-ok \
  --metadata-copied

icloudpd-optimizer workflow upload-verified \
  --manifest manifest.json \
  --asset-id <asset-id> \
  --uploaded-heic-asset-id <uploaded-asset-id> \
  --uploaded-heic-sha256 <sha256> \
  --uploaded-heic-path <path-to-uploaded-heic>

icloudpd-optimizer workflow mark-delete-eligible \
  --manifest manifest.json \
  --asset-id <asset-id>

icloudpd-optimizer workflow approve-delete \
  --manifest manifest.json \
  --asset-id <asset-id> \
  --operator <operator>

icloudpd-optimizer workflow delete-plan \
  --manifest manifest.json \
  --asset-id <asset-id>
```

`delete-plan` prints structured JSON and does not mutate or remove files.

## Development

Run the full local gate before publishing changes:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

MIT
