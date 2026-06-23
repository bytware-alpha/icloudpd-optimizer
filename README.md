# icloudpd-optimizer

Optimize large iCloud Photos libraries without losing the originals you care about.

`icloudpd-optimizer` is a small CLI helper for people who use iCloudPD and want a
safer path toward replacing old RAW originals with verified HEIC versions. It keeps a
manifest of every step, checks the files it is asked to trust, and only emits a delete
plan after the required proofs are present.

The important part: the tool does not delete your RAW files by itself.

## Why This Exists

RAW files are useful, but they are large. If your iCloud library contains many old RAW
captures, you may want to keep a smaller HEIC copy in iCloud while preserving the RAW on
your own storage.

That workflow is risky if it is held together with shell scripts alone. Before removing
an original from iCloud, you want proof that:

- the RAW exists on durable storage;
- the HEIC was created from that RAW;
- the HEIC was verified and metadata was copied;
- the uploaded HEIC matches what was verified;
- the original is old enough to be eligible;
- a human approved the delete plan.

`icloudpd-optimizer` records those checks in a manifest so each asset has an audit trail.

## Project Status

This project is early and intentionally conservative. Today it provides the safety and
manifest layer for a RAW-to-HEIC optimization workflow. It is meant to be called by a
higher-level sync job or automation.

The current CLI can:

- verify RAW files under a storage root;
- plan RAW-to-HEIC conversion commands;
- record conversion, upload, and verification proofs;
- validate upload-session inputs and fail closed until safe iCloud Photos upload support is implemented;
- reject incomplete or inconsistent workflow states;
- print a JSON delete plan for manual review.

It does not delete iCloud originals for you.

## Install

Install from source:

```sh
git clone https://github.com/bytware-alpha/icloudpd-optimizer.git
cd icloudpd-optimizer
cargo install --path . --locked
```

You will also need these tools available on `PATH`:

- `sips`
- `heif-info`
- `exiftool`

Check your environment:

```sh
icloudpd-optimizer doctor --json
```

## Quick Start

Show the CLI help:

```sh
icloudpd-optimizer --help
```

Inspect an existing manifest:

```sh
icloudpd-optimizer manifest show --manifest manifest.json
```

Verify that a RAW file is safely present under your storage root:

```sh
icloudpd-optimizer workflow nas-verified \
  --manifest manifest.json \
  --asset-id IMG_0001 \
  --raw-path /photos/raw/IMG_0001.dng \
  --nas-root /photos \
  --min-age-days 30
```

When every required stage has been recorded and approved, ask for a delete plan:

```sh
icloudpd-optimizer workflow delete-plan \
  --manifest manifest.json \
  --asset-id IMG_0001
```

The delete plan is JSON output. It does not remove files.

## Upload Status

`workflow upload-heic` is intentionally disabled today. iCloud Photos web uploads use
CloudKit asset-upload tokens plus record mutations, and a direct `uploadimagews` POST is
not a safe upload protocol for this workflow. Until that CloudKit path is implemented,
the command validates the session file and local HEIC, then fails without changing the
manifest.

The command requires an explicit pre-authenticated upload session JSON file. It does not
accept an Apple ID, Apple account password, or MFA input.

The session file must contain a DSID, an iCloud Photos upload service URL, and cookies
including `X-APPLE-WEBAUTH-TOKEN`:

```json
{
  "dsid": "123456789",
  "upload_url": "https://upload.icloud.com/uploadimagews",
  "cookies": [
    { "name": "X-APPLE-WEBAUTH-TOKEN", "value": "..." },
    { "name": "session", "value": "..." }
  ]
}
```

The upload URL may also be supplied as `webservices.uploadimagews.url`. Upload URLs must
be HTTPS iCloud hosts and must not include credentials, query strings, or fragments.
The DSID must be numeric. Cookie names and values are validated before any request is
sent; values must be printable ASCII without whitespace or semicolons.

```sh
icloudpd-optimizer workflow upload-heic \
  --manifest manifest.json \
  --asset-id IMG_0001 \
  --session /path/to/upload-session.json
```

Before the disabled upload boundary, the tool rechecks the local HEIC size and SHA-256
against the verified manifest proof. If the session is invalid, upload support is not
available, or the local file changes, the manifest is not updated. Upload proofs can
still be recorded with `workflow upload-verified` after an operator has independently
verified the iCloud asset id and uploaded HEIC identity.

## Safety Model

`icloudpd-optimizer` is designed to fail closed. If a proof is missing, stale, malformed,
or does not match the current file facts, the workflow stops.

Before a delete plan is emitted, the tool rechecks the stored evidence instead of blindly
trusting the manifest. That keeps accidental rewrites, moved files, bad paths, and
incomplete uploads from looking safe.

## Development

Install `just` first, using your platform package manager or Cargo:

```sh
cargo install just
```

Then prepare your local checkout:

```sh
just setup
```

`just setup` checks Rust tooling, builds the CLI, runs `icloudpd-optimizer doctor
--json`, and prints install commands for missing runtime tools such as
`heif-info` and `exiftool`.

Run the normal project gate before opening a pull request:

```sh
just check
```

## Contributing

Issues and pull requests are welcome. For changes that affect workflow state, proof
validation, or delete-plan eligibility, include tests for both the success path and the
failure path.

See [CONTRIBUTING.md](CONTRIBUTING.md) for project guidelines.

## License

MIT
