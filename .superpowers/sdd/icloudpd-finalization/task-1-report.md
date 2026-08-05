# Task 1 report: BLOCKED fail-closed

## Outcome

No recovery, mount operation, SMB canary, CloudKit lookup, journal resume, delete, upload, or production-state mutation was performed.

## Safety preflight evidence

- Remote host was reachable through the prescribed noninteractive SSH identity.
- Both signed inactive application bundles were present.
- The exact production label and stale recovery-canary label were not loaded.
- No monitor-helper or service process was present.
- No SecurityAgent process was present at the time of the fresh check.
- Exactly one SMB filesystem mount was present.
- The stale recovery-canary LaunchAgent file was absent.

## Concrete blocker

The production LaunchAgent plist is still present, is not loaded, but does **not** declare `Disabled=true`; the per-user launchd disabled-state query also did not prove a persistent disabled entry.  This fails the plan's requirement that production remain disabled.  Because a future login could reload a present, non-disabled LaunchAgent, proceeding with any recovery step would not preserve the required fail-closed production boundary.

Per the task's stop condition, the task stopped before touching the mount, Keychain, TCC, trust/signing state, configuration, manifest, journals, CloudKit, NAS originals, or delete adapter.  No credentials, asset names, record IDs, or full fingerprints were recorded here.

## Acceptance-criteria mapping

- Stable-helper noninteractive Keychain proof: not attempted after blocker.
- Exact unmount/remount and no-replace collision proof: not attempted after blocker.
- Signer-pinned reboot-device sidecar: not generated after blocker.
- Two authorized read-only CloudKit repairs: not attempted after blocker.
- Both `DeleteConfirmed` journals to `Complete` with unavailable delete adapter and `delete_calls=0`: not attempted after blocker.
- Exact CLI audits: not attempted after blocker.
- Production stopped: current processes/labels are stopped, but persistent disabled state is not proven; this is the blocker.

## Verification commands and results

1. Noninteractive remote preflight: succeeded; host reachable, two app bundles present, no monitor/service process, no SecurityAgent, one SMB mount.
2. `launchctl print` checks: succeeded; production and stale-canary labels not loaded.
3. Production plist `Disabled` check: failed the required condition (`Disabled=true` not present), while the plist itself remains present.

## Changes and commit

- Changed: this report only.
- Commit: none; no safe implementation change was authorized while the production-disabled proof is incomplete.

## Remediation: persistent stop contract

The production stop contract was a repository defect: `service stop` only
booted the job out, while the installed LaunchAgent retained `RunAtLoad=true`
and no persistent disabled state. Commit `bf7477e` repairs that contract:

- generated LaunchAgent plists now declare `Disabled=true`;
- `service stop` persists `launchctl disable` before `bootout`;
- `service start` explicitly runs `launchctl enable` before `bootstrap`, so a
  reviewed future production enable remains available;
- the existing service documentation and plist tests cover the disabled-by-
  default contract.

Focused and full verification passed before the deployment attempt: formatting,
clippy, the full locked test suite, the launchd-plist CLI test, and the
service-install plist test. The remote live state was repaired and proved for
the currently installed production contract: the production plist has
`Disabled=true`; production and stale-canary labels are persistently disabled
and unloaded; the stale-canary plist is absent; production service-wrapper and
helper process count is zero; and no `SecurityAgent` is present. No recovery,
mount, CloudKit, journal, or delete operation was run.

## Concrete blocker after remediation

The updated inactive bundle cannot be signed through the required existing
stable-CA identity without weakening the trust boundary. The local signing
identity produces a different team identity from the installed service. On the
remote host, a noninteractive disposable signing probe found no usable signing
identity matching the installed service team (and no usable signing identity at
all); it produced no SecurityAgent prompt and cleaned its staging directory.

Therefore the signed inactive redeploy required before recovery cannot be made
safely. Per the stop condition, Task 1 remains blocked here. Do not substitute
a differently signed bundle or request an interactive trust/password prompt.

## Updated acceptance-criteria mapping

- Persistent production/stale-canary stop: production disabled plus unloaded
  and service processes zero; stale label unloaded and stale plist absent.
- Stable-CA signed inactive redeploy: blocked by unavailable matching signing
  identity; no alternate signer was used.
- All remaining Task 1 recovery criteria: not attempted, because deploy proof
  is a required gate.

## Remediation verification

1. `cargo fmt --check`: passed.
2. `cargo clippy --locked --all-targets -- -D warnings`: passed.
3. `cargo test --locked`: passed.
4. `cargo test --locked monitor_stats_tui_and_launchd_plist_are_simple_and_non_secret`: passed (1 test).
5. `cargo test --locked service_install_creates_launchagent_with_stable_associated_identifier`: passed (1 test).
6. Remote launchd/process/SecurityAgent preflight: production persistently
   disabled and unloaded, stale canary unloaded/absent, production processes
   zero, no SecurityAgent.
7. Remote stable-signer probe: failed closed with zero matching usable signers;
   no deployment occurred.

## Remediation commit

- `bf7477e Persistently disable stopped macOS service`

## Fix round 1: start failure rollback

### Outcome

`service start` now treats every failed `launchctl` start phase as a failed
admission: after an `enable`, `bootstrap`, or `kickstart` failure it issues
`disable` followed by `bootout` before returning the error. A rollback failure
is preserved in the returned error alongside the original failure. Stop now
also attempts `bootout` even when `disable` fails, so it does not leave a
loaded job merely because persisting the override failed.

### Changed files

- `src/service.rs`: injectable launchctl command path, fail-closed rollback,
  rollback error reporting, and behavioral command-order tests.
- `README.md`: documents that failed starts are disabled and unloaded again.

### Acceptance-criteria evidence

- Failed start is fail-closed: the implementation runs `disable` then `bootout`
  after any failed enable/bootstrap/kickstart operation; bootstrap and kickstart
  regression tests assert the exact calls and order.
- Behavioral coverage: five unit tests assert stop ordering, successful start
  ordering, enable rollback, bootstrap rollback, and kickstart rollback.
- Deletion/data-integrity gates: untouched.
- No signing, deployment, recovery, or remote mutation: performed none.

### Verification

1. `cargo test --locked service::tests`: passed, 5 service tests passed.
2. `cargo fmt --check`: passed.
3. `cargo clippy --locked --all-targets -- -D warnings`: passed.
4. `cargo test --locked`: passed, 637 unit tests passed; all remaining test
   binaries completed with zero failures.
5. `git diff --check`: passed.

### Commit

`d6c478c Fail closed service start rollback`

### Remaining risk

This is local behavioral proof of command sequencing. It does not change the
existing blocked signing/deployment state and does not constitute remote
launchd proof.

### Agentception evaluation

No reusable learning was added. The remedy is a conventional fail-closed
rollback pattern already captured directly by the implementation and tests;
there was no non-obvious, independently reusable debugging discovery.

## Fix round 2: fail-closed start barrier

### Outcome

Service installation and stop create a durable per-plist processing hard-stop.
The generated service LaunchAgent passes that boundary to `monitor run`, which
refuses to acquire monitor processing state or run production work while it is
present. Explicit start keeps the boundary engaged through enable, bootstrap,
and kickstart, releasing it only after all three succeed. Any start failure
retains it, including disable, bootout, or combined rollback failures; the
returned error is redacted and tells the operator to inspect/repair launchd
before retrying. Stop engages the boundary before disable and unload.

### Changed files

- `src/service.rs`: durable hard-stop lifecycle and failure reporting.
- `src/monitor.rs`: service-specific LaunchAgent guard argument.
- `src/cli.rs`: monitor hard-stop enforcement and optional explicit stop plist.
- `tests/cli.rs`: installed plist and pre-processing hard-stop behavior.
- `README.md`: exact start/stop hard-stop contract.

### Acceptance-criteria evidence

- Unsuccessful start cannot leave production processing active: all failure
  paths retain the durable guard before returning, even when launchctl rollback
  commands fail.
- Explicit successful start still enables, bootstraps, kickstarts, then removes
  the guard; stop writes it before disable/bootout.
- Behavioral tests cover ordinary enable/bootstrap/kickstart failures, rollback
  disable failure, rollback bootout failure, combined rollback failure, redacted
  error text, service plist wiring, and monitor refusal before state acquisition.
- Deletion and data-integrity gates were not changed.

### Verification

1. `cargo fmt --check`: passed.
2. `cargo clippy --locked --all-targets -- -D warnings`: passed.
3. `cargo test --locked service::tests`: passed, 8 service tests.
4. `cargo test --locked service_hard_stop_blocks_monitor_before_it_acquires_processing_state`: passed.
5. `cargo test --locked service_install_creates_launchagent_with_stable_associated_identifier`: passed.
6. `cargo test --locked`: passed.
7. `git diff --check`: passed.

### Agentception evaluation

No reusable learning was added. The design is a local application of the
existing fail-closed boundary pattern, not a new broadly reusable incident
lesson.

## Fix round 3: durable barrier admission and behavioral proof

### Outcome

Hard-stop engagement now writes and syncs a unique temporary file, atomically
renames it into place, then syncs the parent directory. This makes both a new
barrier entry and a replacement of an older barrier durable before any
`launchctl` transition. Release continues to remove the barrier and sync its
parent directory.

### Changed files

- `src/service.rs`: durable atomic barrier replacement and parent-directory
  sync; direct behavioral command/order and barrier-at-call assertions.

### Acceptance-criteria evidence

- Barrier durability: every engagement fsyncs the barrier payload, atomically
  renames it, and fsyncs its parent directory before `launchctl` is called.
- Start/stop ordering: command closures assert the barrier exists at every
  start, rollback, and stop `launchctl` invocation.
- Partial and combined rollback: tests capture the full order and prove a
  rollback-disable failure still attempts `bootout`, while combined failures
  attempt both rollback commands.
- Stop failure: a disable failure still attempts `bootout`, with the barrier
  already engaged and retained.
- Existing successful start, basic failed-start, plist wiring, and monitor
  pre-state-acquisition refusal coverage remain in place.

### Verification

1. `cargo fmt --check`: passed.
2. `cargo clippy --locked --all-targets -- -D warnings`: passed.
3. `cargo test --locked service::tests`: passed, 10 tests passed.
4. `cargo test --locked service_hard_stop_blocks_monitor_before_it_acquires_processing_state`: passed.
5. `cargo test --locked service_install_creates_launchagent_with_stable_associated_identifier`: passed.
6. `cargo test --locked`: passed.
7. `git diff --check`: passed.

### Agentception evaluation

No learning was added. The fsync-temp-rename-fsync-parent sequence is an
established durability pattern already represented elsewhere in this codebase;
this fix adds no independently reusable discovery.
