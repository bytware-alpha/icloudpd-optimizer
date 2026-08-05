# icloudpd-optimizer

Optimize large iCloud Photos libraries without losing the originals you care about.

`icloudpd-optimizer` is a small CLI helper for people who use iCloudPD and want a
safer path toward replacing old RAW originals with verified HEIC versions. It keeps a
manifest of every step, checks the files it is asked to trust, and only emits a delete
plan after the required proofs are present.

The important part: the tool is fail-closed. It only deletes iCloud originals when
the full lifecycle monitor is explicitly configured with upload/delete sessions,
local mirror proof, and `--auto-delete`; otherwise it stops at proof recording or
delete-plan output.

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
- an explicit delete approval was recorded, either manually or by the configured
  auto-delete operator.

`icloudpd-optimizer` records those checks in a manifest so each asset has an audit trail.

## Project Status

This project is early and intentionally conservative. Today it provides the safety,
manifest, conversion, upload, mirror-proof, and optional delete-execution layer for a
RAW-to-HEIC optimization workflow after another tool has downloaded the originals.

It is not a drop-in replacement for `icloudpd` or `docker-icloudpd`. It does not create
Apple sessions, handle Apple ID authentication or MFA, enumerate iCloud libraries,
traverse albums, or run incremental sync. Upload and delete commands require
pre-authenticated session JSON files; they are not a replacement for `icloudpd` auth.

| Capability | Owner |
|-|-|
| Apple ID auth, MFA, sessions, library listing, albums, Copy/Sync/Move downloads | `icloudpd` |
| Container scheduling, `/config/icloudpd.conf`, keyring, notifications, Telegram reauth | `docker-icloudpd` |
| RAW-on-storage proof, RAW-to-HEIC proof chain, verified upload proof, local mirror proof, optional CloudKit delete execution | `icloudpd-optimizer` |

The current CLI can:

- verify RAW files under a storage root;
- plan RAW-to-HEIC conversion commands;
- require visual validation before upload;
- monitor an iCloudPD download folder and convert matching old RAWs in the background;
- upload verified HEIC files through an external iCloud Photos upload session;
- resolve and delete original CloudKit RAW assets when the configured safety proofs pass;
- reject incomplete or inconsistent workflow states;
- print a JSON delete plan for manual review.

`workflow convert` is platform-native and fail-closed. On macOS it uses `sips`.
On Linux it extracts the DNG embedded rendered preview with `exiftool`, encodes
HEIC with `heif-enc`, and validates previews with ImageMagick. Do not run it inside
the Alpine `docker-icloudpd` auth container; use the host install or the separate
optimizer OCI image.

## Install

Install with Cargo:

```sh
cargo install --git https://github.com/bytware-alpha/icloudpd-optimizer --locked
```

Or install the Homebrew formula from a checkout until a tagged tap release exists:

```sh
git clone https://github.com/bytware-alpha/icloudpd-optimizer.git
brew install --HEAD ./icloudpd-optimizer/packaging/homebrew/icloudpd-optimizer.rb
```

Install from a source checkout:

```sh
git clone https://github.com/bytware-alpha/icloudpd-optimizer.git
cd icloudpd-optimizer
cargo install --path . --locked
```

For local development, `just install` builds the release binary and copies it to
`$HOME/.local/bin`:

```sh
just install
```

Check the active platform contract:

```sh
icloudpd-optimizer doctor --json
```

`doctor --json` is authoritative for platform-specific required tools. It reports
the host platform, active conversion backend, whether `workflow convert` is
supported, and the tools required for that platform.

For source installs on supported platforms, keep these runtime tools available on
`PATH`:

- `heif-info`
- `magick`
- `exiftool`

macOS host-native `workflow convert` requirements:

- `sips`
- `heif-info`
- `magick`
- `exiftool`

Linux source and OCI installs do not require `sips`. They support manifest, proof,
upload, delete-plan, and Linux-native `workflow convert` workflows.

Linux-native `workflow convert` requirements:

- `heif-enc`
- `heif-info`
- `magick`
- `exiftool`

## OCI Image

Apple `container` is the primary local image build/run path. It runs Linux
containers on Apple silicon macOS and builds an OCI-compatible image that can also
be used by Linux OCI runtimes.

Build the standard OCI Linux image:

```sh
container build --tag icloudpd-optimizer:local --file container/Containerfile .
```

Run the image doctor check with Apple `container`:

```sh
container run --rm icloudpd-optimizer:local doctor --json
```

The same OCI image can be tagged and pushed to GHCR, then run on Linux OCI runtimes:

```sh
podman run --rm icloudpd-optimizer:local doctor --json
```

The Linux image supports manifest, proof, upload, delete-plan, and Linux-native
`workflow convert` operations. The conversion backend extracts the DNG embedded
rendered preview with `exiftool`, encodes HEIC with `heif-enc`, validates previews
with ImageMagick, and records measured conversion performance before any
upload/delete workflow can proceed.

## Quick Start

Show the CLI help:

```sh
icloudpd-optimizer --help
```

Inspect an existing manifest:

```sh
icloudpd-optimizer manifest show --manifest manifest.json
```

Upgrade an existing v1 SQLite sidecar to the fenced v2 schema without importing or
exporting the manifest JSON:

```sh
icloudpd-optimizer manifest migrate --manifest manifest.json --from 1 --to 2
```

This command requires the exact v1 `manifest.state.sqlite3` schema and returns a JSON
summary with a safe database identifier. It rejects missing, empty, unknown, or already
v2 databases without bootstrapping or changing the manifest JSON. Normal writers and the
monitor refuse v1 state with an actionable migration-required error; they never migrate it
implicitly. Stop the local monitor before running this command: it holds the same
`manifest.monitor.lock` during validation and migration. Migration requires that legacy lock
file to already exist and never creates it; if it is absent, start and stop the local monitor
once to create its single-link lock file, then stop every writer before retrying. That flock is
local to one shared filesystem, so stop any cross-VM or Docker writers whose lock domain is not
shared before migrating. Schema migration is supported only on Unix hosts with OS file fencing
and refuses symbolic-link or hard-link state databases and lock files rather than risking an
alias write. It revalidates the manifest lock and the opened database inode before commit,
including a parent-directory change witness for path replacement. These checks fail closed for
ordinary races, but no POSIX path protocol can defend against a same-user actor with write access
deliberately coordinating hostile filesystem/VFS changes; run migration from a private directory
and stop such actors first.

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
# 4. Record HEIC validation, upload proof, and source age proof.
# 5. Mirror the uploaded HEIC to the local path icloudpd will download.
icloudpd-optimizer workflow icloudpd-local-mirror --manifest manifest.json --asset-id IMG_0001 --download-path /photos/IMG_0001.HEIC

# 6. Record approval and emit a delete plan for manual review.
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

## macOS SMB Credential Authorization

The dashboard's **Set SMB Credential** flow creates or refreshes exactly one
optimizer-owned Keychain Internet-password item. It is selected only when its
server, account, empty path, port, SMB protocol, `dflt` authentication type,
and the fixed `com.icloudpd-optimizer.smb.v1` security domain exactly match
the validated mount. Finder and legacy records (including NULL-auth records)
are neither read nor changed.

The signed embedded helper retrieves that exact credential and supplies its
material explicitly to NetFS; NetFS is never allowed to choose an ambient
credential. The helper's exact identifier and Team/designated requirement are
authorized, so ordinary rebuilds or leaf-certificate renewals under the same
Team continue to work. A changed Team, identifier, or designated requirement
requires explicit reauthorization.

Enter the password only in the dashboard's native secure field. It is written
once through an anonymous stdin pipe to the installed signed helper, zeroized,
and stored only in that dedicated Keychain item with an ACL for the exact helper
requirement. It is never sent through argv, environment, logs, or files. The
monitor and launchd service never refresh credentials or mutate Keychain access.
Credential setup then validates the exact SMB authority through the helper's
non-mutating authenticated connection path; a rejected authority returns only
the redacted `server_rejected` status and blocks all canary or asset work.

### Guided setup and approval boundaries

Use the signed dashboard for the complete setup, not Finder:

1. Choose **Authorize NAS Folder** to grant the dashboard access to the folder
   containing the configured roots, then choose **Set Up SMB Credential** and
   enter the NAS/SMB password (not the Mac login password).
2. Let the dashboard validate the exact server, account, share, and mount
   authority. If macOS presents the native Keychain prompt, approve only that
   explicit helper request.
3. Confirm the helper's noninteractive credential proof and exact SMB
   connection before starting a canary or processing assets.

NAS folder access and SMB login are separate permissions. The dashboard exposes
only the redacted result categories `authorized`, `not_found`, `ambiguous`,
`interaction_required`, `access_denied`, `server_rejected`, and
`integrity_mismatch`, with a safe category/stage/reason diagnostic. An
`integrity_mismatch` means the signed helper, sealed configuration, or dedicated
credential access control no longer matches; close and reopen the signed app and
run the explicit setup again. Do not use Finder, edit another Keychain record, or
widen an ACL to work around it.

The build reuses one explicit Apple Development signing identity from the
canonical login Keychain. Renewal of its leaf certificate under the same Team,
helper identifier, and designated requirement preserves the authorization;
changing any of those values requires setup again. Signing-key/keychain access,
the dedicated credential item's Keychain ACL, macOS privacy/TCC grants (NAS
folder and Local Network when requested), and launchd service registration are
independent gates. One prompt never authorizes another, so no prompt is treated
as the "last" approval. Rebuilding or re-signing can invalidate a TCC grant;
reopen the signed app and approve the exact folder again after such a change.

## Background Monitor

The monitor is a small foreground process that is meant to be launched by
`launchd`, systemd, cron, or a terminal. It polls the iCloudPD download folder,
proves matching RAW files are under the configured storage root and older than
the safety floor, then runs the existing measured conversion path with bounded
parallelism.

When conversion capacity is capped, the monitor spends those conversion slots on
the largest verified RAW files first. That keeps slow encoder time focused on the
assets with the highest likely storage savings while keeping the same proof gates.

By default the monitor is conversion-only and stops before iCloud mutation. With
`--full-lifecycle`, it can continue through HEIC verification, CloudKit original
resolution, upload, local mirror recording, and delete eligibility. With
`--rolling-lifecycle`, worker slots keep taking small groups of assets through the
next safe lifecycle stage instead of waiting for a whole scan to finish. It executes
original deletes only when `--auto-delete`, `--upload-session`, `--delete-session`,
and the required proofs are present.

Rolling mode keeps conversion quality and delete safety separate from queue tuning.
`rolling_worker_count` (`--rolling-worker-count`) controls queue and coordination
slots across lifecycle stages. For example, 64 lifecycle workers let up to 64 queued
assets make progress; they do not permit 64 simultaneous encoders. CPU-bound stages
default to the smaller of `jobs` (`--jobs`) and the host's available CPU
parallelism. `rolling_cpu_stage_count` can explicitly override that default and
may exceed both values. The encoder lane defaults to half the resolved CPU lane,
rounded up, and can be set with
`rolling_convert_stage_count` (`--rolling-convert-stage-count`), which is clamped
to the resolved CPU-stage limit. These controls do not change HEIC quality or any
verification gate.

`max_lifecycle_per_scan` (`--max-lifecycle-per-scan`) controls the normal active
lifecycle set. When deletion is enabled, it also caps the total number of delete
candidates admitted across all rolling passes in one scan; refilling the active set
cannot exceed that per-scan delete limit. Historical exact-match failures from original-asset resolution use
the remaining lifecycle capacity and have an independent cap:
`max_original_resolver_retries_per_scan`
(`--max-original-resolver-retries-per-scan`, default `16`). A failed resolver entry
must also be at least `original_resolver_retry_min_age_seconds`
(`--original-resolver-retry-min-age-seconds`, default `86400`, or 24 hours) old
before another attempt is admitted. This keeps a historical retry backlog from
crowding out normal work without weakening original-match or delete proof
requirements.

Other typed lifecycle failures use a separate admission policy.
`max_failed_retry_admissions_per_scan`
(`--max-failed-retry-admissions-per-scan`, default `16`) is applied independently,
in order: generic retryable failures may first use up to that cap, then
adjusted-source-required failures may use up to the same cap from the remaining
lifecycle capacity. Combined admissions can therefore exceed this configured number,
but can never exceed the shared `max_lifecycle_per_scan` capacity. The separate
`failed_retry_min_age_seconds` (`--failed-retry-min-age-seconds`, default `300`)
sets the minimum age for generic retryable failures. Adjusted-source resolution has
its own proof and attempt policy. Neither setting changes original-asset resolver
retries, which are considered afterward and continue to use the original-resolver
controls above and whatever lifecycle capacity remains. Only failure kinds explicitly
covered by the retry policy are admitted; malformed, exhausted, source-proof-invalid,
or downstream-proof-bearing records remain blocked or are marked for review.

If a DNG has no usable embedded preview, rolling full-lifecycle mode does not fall
back to an unproven conversion source. It records an adjusted-source requirement,
then uses the already verified original asset's CloudKit database, zone, and owner
binding to resolve and validate the full-resolution adjusted JPEG. The worker commits
that adjusted-source proof atomically before returning the record to `NasVerified`
and continuing through conversion, HEIC verification, upload, and local-mirror proof.
A missing or mismatched original proof, shared-zone owner, resource fingerprint, or
download leaves the record failed and ineligible for upload or deletion.

Retry admissions are re-evaluated at the start of every scan, including the first
scan after a restart. Attempt lineage and failure timestamps are durable; restarting
does not reset the retry budget or bypass the minimum age. When admission or
terminalization changes proof state, the monitor checkpoints that state before
lifecycle work begins.

Rolling mode also reserves part of the active worker set for conversion-ready RAWs
so encoder slots do not sit idle behind upload, mirror, or delete backlog. Use
`--max-conversions-per-scan` to cap how many new conversions a scan may start. Use
`--rolling-original-resolve-active-window-multiplier` and
`--rolling-original-resolve-batch-multiplier` to widen CloudKit original-resolution
work when many RAW candidates need proof before they can be converted and replaced.
Those resolver settings only affect how many CloudKit lookup batches are attempted;
they do not change HEIC quality, metadata copying, visual verification, upload
proofs, local mirror proofs, or delete gates.

Create a config:

```sh
icloudpd-optimizer monitor init \
  --config ~/.config/icloudpd-optimizer/monitor.json \
  --download-root /photos/PrimarySync \
  --nas-root /photos \
  --manifest ~/.local/state/icloudpd-optimizer/manifest.json \
  --heic-output-dir ~/.local/state/icloudpd-optimizer/heic \
  --jobs 4 \
  --scan-interval-seconds 300
```

For an opt-in full lifecycle monitor, add the session and mirror settings:

```sh
icloudpd-optimizer monitor init \
  --config ~/.config/icloudpd-optimizer/monitor.json \
  --download-root /photos/PrimarySync \
  --nas-root /photos \
  --mirror-root /photos/PrimarySync \
  --manifest ~/.local/state/icloudpd-optimizer/manifest.json \
  --heic-output-dir ~/.local/state/icloudpd-optimizer/heic \
  --upload-session ~/.local/state/icloudpd-optimizer/upload-session.json \
  --delete-session ~/.local/state/icloudpd-optimizer/delete-session.json \
  --full-lifecycle \
  --rolling-lifecycle \
  --auto-delete \
  --jobs 8 \
  --rolling-worker-count 64 \
  --max-lifecycle-per-scan 100 \
  --rolling-original-resolve-active-window-multiplier 4 \
  --rolling-original-resolve-batch-multiplier 4 \
  --scan-interval-seconds 300
```

Keep `--auto-delete` off until a one-asset canary has completed and the manifest,
stats, and local mirror path all show the expected proof trail.

### Deletion-disabled canary and capped rollout

Start with deletion disabled: omit `--auto-delete`, run one bounded scan, and
then run the signed SMB no-replace canary against the already authorized mount:

```sh
icloudpd-optimizer monitor run --config "$CONFIG" --once
icloudpd-optimizer monitor smb-noreplace-canary \
  --mount-root "$MOUNT_ROOT" --json
```

The canary exercises only the isolated write/rename/collision/cleanup path; it
does not upload an asset or delete an iCloud record. Keep the rollout capped with
`--max-lifecycle-per-scan 10` and `--max-conversions-per-scan 10` (or another
explicitly reviewed cap) while checking each receipt. Increase caps only after
the deletion-disabled receipts, local mirror, hash, image, and CloudKit identity
checks agree. A credential, NAS-folder, TCC/Local-Network, or exact-mount failure
returns a redacted failure and performs no canary or asset work.

The generated config also contains `local_mirror_timeout_seconds` (default `60`).
Raise it when measured copy, sync, and verification time on a slow SMB or NAS share
can exceed the default. A mirror timeout records a failure and leaves the asset
ineligible for deletion; it never bypasses mirror proof. Choose the timeout for the
storage path rather than treating one machine's value as a universal setting.

Run one scan manually:

```sh
icloudpd-optimizer monitor run --config ~/.config/icloudpd-optimizer/monitor.json --once
```

Run continuously:

```sh
icloudpd-optimizer monitor run --config ~/.config/icloudpd-optimizer/monitor.json
```

Show stats or the simple TUI:

```sh
icloudpd-optimizer monitor stats --config ~/.config/icloudpd-optimizer/monitor.json
icloudpd-optimizer monitor tui --config ~/.config/icloudpd-optimizer/monitor.json
```

### Audits and Gated Maintenance

The monitor also exposes narrow operational commands for auditing or repairing
durable proof state. Start with their read-only forms and preserve the JSON reports:

```sh
icloudpd-optimizer monitor original-assets-audit \
  --config "$CONFIG" > original-assets-audit.json
```

Reconcile one private destination with the exact values from that audit. For a
shared destination, change the scope to `shared` and add
`--owner-record-name "$OWNER_RECORD_NAME"` after `--zone-name`:

```sh
icloudpd-optimizer monitor original-assets-reconcile \
  --config "$CONFIG" \
  --database-scope private \
  --zone-name "$ZONE_NAME" \
  --expected-selected-target-count "$SELECTED_COUNT" \
  --expected-unselected-destination-target-count "$UNSELECTED_COUNT" \
  --expected-skipped-target-count "$SKIPPED_COUNT" \
  --expected-target-set-sha256 "$TARGET_SET_SHA256" \
  --expected-inventory-sha256 "$INVENTORY_SHA256" \
  --expected-records-scanned "$RECORDS_SCANNED" \
  --expected-exact-original-count "$EXACT_ORIGINAL_COUNT" \
  --expected-replacement-present-count "$REPLACEMENT_PRESENT_COUNT" \
  --expected-no-date-candidate-count "$NO_DATE_CANDIDATE_COUNT" \
  --expected-no-raw-resource-count "$NO_RAW_RESOURCE_COUNT" \
  --expected-raw-size-mismatch-count "$RAW_SIZE_MISMATCH_COUNT" \
  --expected-raw-hash-mismatch-count "$RAW_HASH_MISMATCH_COUNT" \
  --expected-ambiguous-count "$AMBIGUOUS_COUNT" \
  --expected-incomplete-transient-count "$INCOMPLETE_TRANSIENT_COUNT"
```

Reconcile input rules:

- Read-only is the default. Every flag in the template is required;
  `--owner-record-name` is additionally required for `shared` and omitted for
  `private`. No expectation flag becomes optional.
- Apply uses the same complete destination and expectation set, adds `--apply`, and
  requires the monitor to remain stopped.

```sh
icloudpd-optimizer monitor upload-verified-reverify \
  --config "$CONFIG" \
  --asset-id "$ASSET_ID" \
  --expected-target-count "$TARGET_COUNT" \
  --expected-target-set-sha256 "$TARGET_SET_SHA256"

icloudpd-optimizer monitor failed-assets-quarantine \
  --config "$CONFIG" \
  --evidence "$EVIDENCE_JSON" \
  --expected-evidence-sha256 "$EVIDENCE_SHA256" \
  --expected-failed-asset-count "$FAILED_COUNT" \
  --expected-side-effect-asset-count "$SIDE_EFFECT_COUNT"

icloudpd-optimizer monitor legacy-failures-classify \
  --config "$CONFIG"
```

After stopping the monitor, apply only the exact snapshots returned by those
read-only runs:

```sh
icloudpd-optimizer monitor failed-assets-quarantine \
  --config "$CONFIG" \
  --evidence "$EVIDENCE_JSON" \
  --expected-evidence-sha256 "$EVIDENCE_SHA256" \
  --expected-failed-asset-count "$FAILED_COUNT" \
  --expected-side-effect-asset-count "$SIDE_EFFECT_COUNT" \
  --expected-target-set-sha256 "$TARGET_SET_SHA256" \
  --apply

icloudpd-optimizer monitor legacy-failures-classify \
  --config "$CONFIG" \
  --expected-candidate-count "$CANDIDATE_COUNT" \
  --expected-target-set-sha256 "$TARGET_SET_SHA256" \
  --apply
```

`original-assets-audit`, `original-assets-reconcile`, and
`upload-verified-reverify` all require a valid `delete_session_path` in the monitor
config. They do not accept session credentials on the command line.

- `original-assets-audit` is read-only. It queries the configured CloudKit read
  session and reports each library destination's target-set and inventory hashes,
  owner-binding status, skip reasons, and resolution dispositions without changing
  the manifest.
- `original-assets-reconcile` re-queries exactly one destination. Even without
  `--apply`, it requires the audit's expected selected, unselected, and skipped
  counts; target-set and inventory hashes; records-scanned count; and every
  disposition count. Shared destinations also require the exact
  `--owner-record-name`; the command rejects a shared scope without that binding.
  The read-only run verifies an immutable snapshot. `--apply` atomically updates
  only the verified exact-CAS record set.
- `upload-verified-reverify` rechecks only the explicitly repeated `--asset-id`
  values. Their exact count and target-set SHA-256 are mandatory before any file or
  CloudKit verification. Every target must currently be `UploadVerified` with valid
  NAS, source-age, original-asset, conversion/performance, HEIC, upload, and iCloudPD
  local-mirror lineage. The upload proof must include its uploaded asset ID, hash,
  and path. The local HEIC and mirror copy must still match the stored hash and size,
  the oriented reference preview must pass the current image checks, and the remote
  replacement must resolve to the proven identity, hash, and size. Without `--apply`,
  the command reports unchanged and would-change targets and whether the JSON
  checkpoint is stale. With `--apply`, it atomically refreshes changed proof recipes;
  if no record changes but the checkpoint is stale, it can recover the checkpoint
  under the writer lease and reports `checkpoint_recovered`.
- `failed-assets-quarantine` verifies the evidence file's SHA-256, the complete
  Failed cohort count, and the historical remote-side-effect target count against
  an immutable snapshot. The read-only report supplies the exact target-set hash;
  `--apply` additionally requires that hash and atomically marks only the verified
  side-effect records for quarantine. Supplying that hash on a later read-only run
  revalidates the snapshot without applying changes.
- `legacy-failures-classify` is an offline, exact-match migration for legacy
  missing-preview failures. Its read-only report supplies the candidate count and
  target-set hash. Both are required with `--apply`; ambiguous or already typed
  records are not migrated.

### State, CloudKit, and reverify invariants

The writer lease serializes state mutations. Rolling workers read isolated,
immutable database snapshots; a stale witness, WAL, or exact-CAS mismatch fails
closed rather than widening the target set. The JSON checkpoint is refreshed only
after the durable database commit. If a report or output fails after a commit,
inspect durable state before retrying; `checkpoint_recovered` means only that a
stale checkpoint was repaired, not that any proof gate was bypassed.

CloudKit identity is bound to database scope and zone, plus the owner record for
shared destinations; a zone-only match is never sufficient. Reverification repeats
the exact asset IDs, count, and target-set SHA-256 before checking the remote
replacement. It also rechecks the local mirror path, HEIC bytes/size/SHA-256,
structure and metadata, the oriented reference preview and visual-match checks,
and the remote identity/hash/size. Upload success advances a record only to
`UploadVerified`; it never implies delete eligibility or enables `--auto-delete`.

Read-only invocations do not acquire the monitor's writer lease. Before using a
report to authorize mutation, stop the monitor and repeat the final dry-run so its
target set is stable. Keep the monitor stopped for `--apply`: mutating commands must
acquire the monitor run guard and writer lease, revalidate their exact target set,
commit atomically, and refresh the JSON checkpoint. A gate, lock, CAS, or checkpoint
failure stops the operation; it never widens the target set. If output fails after a
commit, inspect the durable state before retrying.

These maintenance commands read CloudKit where described, but none uploads an asset
or deletes a CloudKit record. They do not weaken the normal upload, mirror,
eligibility, approval, or delete-execution gates. Their reports and failures redact
local paths, session credentials, and raw manifest asset IDs where applicable, but
reports may still contain CloudKit record metadata, filenames, and proof hashes; keep
them as sensitive operational evidence.

The monitor writes structured events for each scan and lifecycle stage, including a
per-asset `conversion_finished` event with either the output size or the failure
reason. The stats and manifest-backed metrics provide durable lifetime totals for
completed work. The dashboard labels those totals separately from recent activity:
"Blocked assets (15m)" counts distinct asset IDs, while retry/failure attempts count
every attempt in that window, including repeated attempts for one asset and events
without an asset ID.

Exact space saved is the aggregate bytes of deleted RAW originals minus the aggregate
bytes of their replacement HEIC files. The dashboard marks that lifetime value
complete only when every deleted record has both size proofs and the aggregate is
representable; otherwise it labels the result partial or unavailable instead of
presenting an estimate as exact.

Generate a macOS LaunchAgent plist:

```sh
icloudpd-optimizer service install \
  --config ~/.config/icloudpd-optimizer/monitor.json
icloudpd-optimizer service start
icloudpd-optimizer service status
icloudpd-optimizer service logs --config ~/.config/icloudpd-optimizer/monitor.json
```

On macOS, `service install` writes a per-user LaunchAgent in a disabled state;
the generated plist uses `RunAtLoad` and `KeepAlive` in the user's `gui/<uid>`
launchd domain. This keeps the monitor running across process crashes and user
session restarts while the Mac is powered and that domain is available; it is not
literal uptime while the Mac is asleep or powered off. `service start` engages
the durable hard-stop, then explicitly enables, bootstraps, and kickstarts the
job. The hard-stop is removed only after every step succeeds; any failed or
unproven rollback leaves processing blocked while it attempts to disable and
unload the job. `service status` reads the exact launchd job state with
`launchctl print`. `service stop` engages the same hard-stop before it durably
disables and unloads the service across future logins. The app build creates
one visible dashboard app in `~/Applications` and one launchd-only service app
under `~/Library/Application Support/iCloudPD Optimizer/Service`. Keeping those
identities separate lets the dashboard open normally while the service keeps
running in the background. For NAS or SMB mounts, install and run the signed app
once before starting the service. The app asks you to select the NAS folder that
contains the configured roots, then safely reads those roots and writes, reads,
then removes a tiny hidden canary in the mirror/NAS directory.

Build the app on macOS:

Set `SIGNING_IDENTITY` to the exact Apple Development identity available in your
login keychain and pass that explicit canonical keychain path, then run:

```sh
ICLOUDPD_OPTIMIZER_SIGN_IDENTITY="$SIGNING_IDENTITY" \
ICLOUDPD_OPTIMIZER_KEYCHAIN="$HOME/Library/Keychains/login.keychain-db" \
ICLOUDPD_OPTIMIZER_MONITOR_CONFIG="$HOME/.config/icloudpd-optimizer/monitor.json" \
just macos-app
```

Install and open the app:

```sh
just macos-app-install
just macos-app-launch
```

The app opens a native SwiftUI service dashboard with cumulative savings,
per-worker lifecycle rows, queue bottlenecks, readable monitor events, and
throughput metrics. Lifetime uploaded/deleted totals and exact space savings come
from durable proof state; recent conversions, distinct blocked assets, and retry
attempts come from the visible event window. Worker rows show when an asset is
proving the original RAW, converting, uploading, proving its NAS mirror, waiting
for a bounded CPU slot, or ready for the separate safe delete batch. Use
`Authorize NAS` once to select the NAS folder that contains the configured
iCloudPD photo roots. Then install and start the LaunchAgent through the service
app executable:

```sh
just macos-app-service-install "$HOME/.config/icloudpd-optimizer/monitor.json"
just macos-app-service-start
just macos-app-verify
```

`just macos-app-verify` checks both installed app signatures, runs the bundled
helper's `doctor --json`, prints LaunchAgent status when installed, and tails the
native app wrapper log if it exists.

The macOS app writes its own wrapper/dashboard logs to
`~/Library/Logs/iCloudPD Optimizer/app.log`. The monitor workflow continues to
write scan summaries and events to the stdout/stderr paths configured in the
LaunchAgent.

The monitor logs a scan preflight error instead of hanging if macOS still denies
the NAS path. Replacing or re-signing the app after approval can invalidate the
macOS privacy grant; rebuild, reopen the app, and approve again after updates.

Production signing is anchored to the Apple Development Team ID plus each exact
bundle identifier, not to a private certificate authority. Renewing or rotating
the Apple Development leaf certificate under the same Team ID keeps the helper's
designated requirement unchanged, so it does not require SMB credential
reauthorization. A changed Team ID or helper identifier fails closed and requires
the explicit **Authorize SMB Credential** action again.

If you installed through Homebrew and use the default config path, Homebrew can own
the service lifecycle:

```sh
icloudpd-optimizer monitor init \
  --config "$(brew --prefix)/etc/icloudpd-optimizer/monitor.json" \
  --download-root /path/to/icloudpd/downloads \
  --manifest /path/to/optimizer/manifest.json \
  --heic-output-dir /path/to/optimizer/heic
brew services start icloudpd-optimizer
```

The lower-level plist generator remains available for custom service managers:

```sh
icloudpd-optimizer monitor launchd-plist \
  --config ~/.config/icloudpd-optimizer/monitor.json \
  --bin "$(command -v icloudpd-optimizer)" \
  --output ~/Library/LaunchAgents/com.icloudpd-optimizer.monitor.plist
```

## Conversion Performance

Prefer `workflow convert` for new runs. It executes the platform-native conversion
chain and metadata steps, measures elapsed time in Rust with `std::time::Instant`,
hashes and stats the actual HEIC output, and records `conversion` plus
`conversion_performance` in one manifest save after proof validation:

```sh
icloudpd-optimizer workflow convert \
  --manifest manifest.json \
  --asset-id IMG_0001 \
  --output-path /staging/IMG_0001.heic \
  --heic-quality 90 \
  --conversion-tool-version linux-container-2026-06-23
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

Conversion performance proof is also a storage-savings gate. If the replacement HEIC
is the same size as the RAW or larger, the proof is rejected and the asset cannot move
toward upload or delete. The RAW remains on storage and the manifest records no
successful conversion-performance proof for that asset.

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

After upload verification, record `workflow icloudpd-local-mirror` with the explicit
path that `icloudpd` will use for the uploaded HEIC before requesting delete
eligibility.

## Safety Model

`icloudpd-optimizer` is designed to fail closed. If a proof is missing, stale, malformed,
or does not match the current file facts, the workflow stops.

Before a delete plan is emitted, the tool rechecks the stored evidence instead of blindly
trusting the manifest. That keeps accidental rewrites, moved files, bad paths, and
incomplete uploads from looking safe. Upload rechecks the verified HEIC's size and
SHA-256; local mirror proof verifies the mirrored file; and deletion still requires
the quality, upload, original-match, source-age, mirror, eligibility, and approval
proof chain. Upload success alone never enables deletion: the explicit approval,
delete session, deletion-disabled canary, capped rollout, and every current
mirror/hash/image/original-match gate must still pass. A timeout or retry limit
delays work or records a failure but never promotes an asset past a missing proof.

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
ImageMagick, and `exiftool`. On Darwin/macOS it also requires `sips` for
host-native `workflow convert`; on Linux it requires `heif-enc` for the
container-native conversion backend.

On macOS, the app workflow is:

With `SIGNING_IDENTITY` set to the exact Apple Development identity available in
your keychain:

```sh
ICLOUDPD_OPTIMIZER_SIGN_IDENTITY="$SIGNING_IDENTITY" \
ICLOUDPD_OPTIMIZER_MONITOR_CONFIG="$HOME/.config/icloudpd-optimizer/monitor.json" \
just macos-app
just macos-app-install
just macos-app-launch
just macos-app-service-install "$HOME/.config/icloudpd-optimizer/monitor.json"
just macos-app-service-start
just macos-app-verify
```

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
