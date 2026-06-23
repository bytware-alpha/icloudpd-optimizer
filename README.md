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
- the conversion performance for the actual run was recorded;
- the HEIC was verified and metadata was copied;
- the uploaded HEIC matches what was verified;
- the original is old enough to be eligible;
- a human approved the delete plan.

`icloudpd-optimizer` records those checks in a manifest so each asset has an audit trail.

## Project Status

This project is early and intentionally conservative. Today it provides the safety and
manifest layer for a RAW-to-HEIC optimization workflow after another tool has downloaded
the originals.

It is not a drop-in replacement for `icloudpd` or `docker-icloudpd`. It does not create
Apple sessions, handle Apple ID authentication or MFA, enumerate iCloud libraries,
traverse albums, run incremental sync, or delete originals from iCloud.

| Capability | Owner |
|-|-|
| Apple ID auth, MFA, sessions, library listing, albums, Copy/Sync/Move downloads | `icloudpd` |
| Container scheduling, `/config/icloudpd.conf`, keyring, notifications, Telegram reauth | `docker-icloudpd` |
| RAW-on-storage proof, RAW-to-HEIC proof chain, verified upload proof, delete-plan JSON | `icloudpd-optimizer` |

The current CLI can:

- verify RAW files under a storage root;
- plan RAW-to-HEIC conversion commands;
- require visual validation before upload;
- upload verified HEIC files through an external iCloud Photos upload session;
- reject incomplete or inconsistent workflow states;
- print a JSON delete plan for manual review.

The conversion planner currently emits macOS `sips` commands and uses ImageMagick for
visual checks. Run it on a host or sidecar where those tools are available; do not assume
it can run inside the Alpine `docker-icloudpd` auth container.

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
- `magick`
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

## Working With iCloudPD

Use `icloudpd` or `docker-icloudpd` in a non-destructive download mode first. For
`icloudpd`, that means Copy mode rather than Move mode: do not use
`--keep-icloud-recent-days` or legacy `--delete-after-download` before this optimizer
has produced and you have reviewed a delete plan. For `docker-icloudpd`, keep
iCloud-deleting settings such as `delete_after_download` and
`keep_icloud_recent_only` disabled for the library this tool is auditing.

A safe side-by-side shape is:

```sh
# 1. Let icloudpd/docker-icloudpd download originals to storage.
# 2. Verify the downloaded RAW under that storage root.
icloudpd-optimizer workflow nas-verified --manifest manifest.json --asset-id IMG_0001 --raw-path /photos/raw/IMG_0001.dng --nas-root /photos --min-age-days 30

# 3. Run workflow convert to create the HEIC and record measured conversion proofs.
# 4. Record HEIC validation, upload proof, age proof, and approval.
# 5. Emit a delete plan for manual review.
icloudpd-optimizer workflow delete-plan --manifest manifest.json --asset-id IMG_0001
```

For `docker-icloudpd`, prefer running this tool on the host or as a separate sidecar:

```yaml
services:
  icloudpd:
    image: boredazfcuk/icloudpd
    environment:
      - download_path=/data
    volumes:
      - icloudpd-config:/config
      - photos-download:/data

  optimizer:
    image: icloudpd-optimizer
    command:
      - workflow
      - nas-verified
      - --manifest
      - /state/manifest.json
      - --asset-id
      - IMG_0001
      - --raw-path
      - /data/raw/IMG_0001.dng
      - --nas-root
      - /data
      - --min-age-days
      - "30"
    volumes:
      - photos-download:/data:ro
      - optimizer-state:/state
      - optimizer-staging:/staging
```

Do not mount the `docker-icloudpd` `/config` volume into the optimizer. That directory
contains auth cookies, keyring data, and `icloudpd.conf`; the optimizer should consume
downloaded media from a read-only media mount and write only its manifest/staging data.
The optimizer media mount must match the `docker-icloudpd` `download_path`; in the
example above, both services use `/data`.
Run `icloudpd-optimizer doctor --json` in the host/sidecar environment before automation.

## Conversion Performance

Prefer `workflow convert` for new runs. It executes the planned `sips` conversion and
metadata steps, measures elapsed time in Rust with `std::time::Instant`, hashes and
stats the actual HEIC output, and records `conversion` plus `conversion_performance`
in one manifest save after proof validation:

```sh
icloudpd-optimizer workflow convert \
  --manifest manifest.json \
  --asset-id IMG_0001 \
  --output-path /staging/IMG_0001.heic \
  --heic-quality 90 \
  --conversion-tool-version sips-macos
```

For manual/import workflows only, if the production conversion was run outside
`workflow convert`, keep using `workflow conversion-performance` after
`workflow conversion-recorded` and before `workflow heic-verified`:

```sh
icloudpd-optimizer workflow conversion-performance \
  --manifest manifest.json \
  --asset-id IMG_0001 \
  --conversion-tool manual-external-encoder \
  --conversion-tool-version external-run-2026-06-23 \
  --heic-quality 90 \
  --convert-wall-time-millis 1250 \
  --total-wall-time-millis 1500
```

For manual imports, use elapsed wall-clock durations from the production conversion,
measured by the caller with a monotonic clock. Repeated lab comparison runs are not the
manifest proof used for HEIC verification, upload readiness, or delete-plan gating.

## Uploading HEIC Files

`workflow upload-heic` is an experimental/manual upload helper. It uploads the verified
HEIC file and records the returned iCloud asset id in the manifest. The command only
runs after the HEIC proof includes structure, metadata, visual-content, and visual-match
checks.

The command requires an explicit pre-authenticated upload session JSON file. It does not
accept an Apple ID, Apple account password, or MFA input. `icloudpd` and
`docker-icloudpd` do not produce this file for the optimizer; their keyring and cookie
directories are not a supported upload-session source. External sessions can expire or
stop matching Apple's private upload API.

The session file must contain a DSID, a Photos upload service URL, and cookies
including `X-APPLE-WEBAUTH-TOKEN`:

```json
{
  "dsid": "123456789",
  "photosupload_url": "https://photosupload.icloud.com",
  "cookies": [
    { "name": "X-APPLE-WEBAUTH-TOKEN", "value": "..." },
    { "name": "session", "value": "..." }
  ]
}
```

The upload URL may also be supplied as `webservices.photosupload.url`. URLs must be
HTTPS iCloud Photos upload hosts and must not include credentials, query strings, or
fragments. The DSID must be numeric. Cookie names and values are validated before any
request is sent; values must be printable ASCII without whitespace or semicolons.

```sh
icloudpd-optimizer workflow upload-heic \
  --manifest manifest.json \
  --asset-id IMG_0001 \
  --session /path/to/upload-session.json
```

Before upload, the tool rechecks the local HEIC size and SHA-256 against the verified
manifest proof. If the session is invalid, the iCloud service rejects the upload, or the
local file changes, the manifest is not updated. Until a supported session handoff
exists, prefer recording upload proof with `workflow upload-verified` after an operator
has independently verified the iCloud asset id and uploaded HEIC identity.

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
--json`, and prints install commands for missing runtime tools such as `heif-info`,
ImageMagick, and `exiftool`.

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
