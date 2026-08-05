# Exact SMB Keychain Authorization

> Status: implemented public contract. The signed dashboard/helper and current
> monitor use this workflow. Live deployment, macOS privacy grants, and canary
> admission remain environment-specific fail-closed gates and must be rechecked
> independently.

## Problem

The optimizer must open a second authenticated SMB session to prove no-replace
rename semantics and recover the sealed NAS mount without interactive fallback.
The exact signed helper currently finds the existing macOS Internet-password
item but receives `errSecInteractionNotAllowed` when it requests the secret from
SSH or launchd.

Finder's saved credential and an `Always Allow` prompt do not establish that the
headless helper's code-signing requirement is trusted by the item's legacy
file-keychain ACL. Launching the same helper through Finder, LaunchServices, and
a one-shot GUI LaunchAgent did not produce a durable headless grant. Repeating
those launch-context experiments is not an authorization design.

## Goals

- Provide one explicit user-authorized flow that creates or refreshes only an
  optimizer-owned, mount-derived Internet-password item.
- Select that item only by the mount-derived server, account, empty path, port,
  SMB protocol, `dflt` authentication type, and the fixed optimizer security
  domain; Finder and legacy items are never candidates or mutation targets.
- Leave every non-optimizer Keychain item and ACL untouched.
- Never inspect, copy, hash, log, or persist password bytes. The final
  credential-only proof may request the item data solely to prove access and
  must immediately release it through Security.framework without examining it.
- Bind authorization to the helper's stable designated requirement so normal
  rebuilds under the same Apple Development Team ID do not depend on a changing
  CodeDirectory hash.
- Verify noninteractive access immediately after authorization and before any
  SMB remount, reconciliation, canary, or production start.
- Keep every error and receipt redacted.

## Non-goals

- Do not grant all applications, all signed applications, `apple:`,
  `apple-tool:`, or a broad `codesign:` partition access.
- Do not accept a Team ID alone: authorization always includes the exact helper
  identifier and canonical designated requirement.
- Do not read, copy, mutate, or delete Finder/legacy credentials.
- Do not change the login Keychain password, search list, default Keychain,
  lock settings, trust settings, TCC database, or Finder credential.
- Do not provide an interactive fallback in the monitor or launchd service.

## Selected Architecture

Add a **Set SMB Credential** action to the signed dashboard app and a matching
GUI-only helper command. At the explicit action boundary, the native secure
field is cleared immediately and its value is copied into one bounded mutable
byte buffer, which is written directly to an anonymous stdin pipe and wiped.
The helper zeroizes its bounded input after the Security.framework write. This
is best effort: AppKit's internal secure-field storage is OS-managed and cannot
be honestly guaranteed zeroized by this app. The optimizer record has security domain
`com.icloudpd-optimizer.smb.v1`, an exact helper-only ACL, and no relationship
to Finder records. The command uses the legacy macOS Security.framework APIs:

1. Derive the SMB server, account, path, port, protocol, and mounted-volume
   binding from the exact validated mount. Search only for an Internet-password
   item with authentication type `dflt`; NULL-authentication items are not
   eligible. Hold the values in memory and expose only hashes and counts in
   logs or receipts.
2. Locate exactly one dedicated optimizer item by metadata alone; create it
   only when absent, with an ACL for the exact signed helper. Multiple dedicated
   records fail closed.
3. Existing dedicated records must already grant that exact helper; a foreign
   or broad ACL fails closed rather than being broadened or repaired.
4. Create a `SecTrustedApplication` from the installed embedded helper's exact
   canonical path. Reject missing, symlinked, translocated, quarantined,
   unexpected-owner, or signature-invalid paths.
5. Require the helper to satisfy the sealed Apple Development designated requirement,
   bundle identifier, and deployment provenance. Do not use CDHash equality as
   an update identity and never compare a CDHash with a Git commit.
6. Create new records with the helper-only access object, then re-read its ACL;
   if creation cannot be proven, remove only that just-created optimizer record.
7. Refresh only the dedicated record's password data. No password travels in
   argv, environment, a temporary file, logs, reports, or persistent storage
   other than Keychain.
8. Copy the ACL again and verify the exact helper requirement before accepting
   the write.
9. Run a credential-only noninteractive proof from the exact embedded helper.
   It requests the item data through the production Keychain lookup, checks only
   the OSStatus and nonzero length, immediately releases the returned content,
   and performs no NetFS, SMB, NAS, CloudKit, journal, upload, or delete
   operation. Only `authorized`, `not_found`, `ambiguous`,
   `interaction_required`, `access_denied`, `server_rejected`, or
   `integrity_mismatch` may be reported.
10. Before returning success, open the existing exact SMB session path only;
    it performs no canary, upload, deletion, or asset mutation. A failed
    session returns redacted `server_rejected` and blocks production.

Production and recovery pass the selected credential material explicitly to
NetFS. They never allow NetFS to select an ambient Keychain credential.

The dashboard calls this command only from an explicit user action. The monitor
and launchd service never mutate Keychain ACLs.

## Stable Signing Contract

Authorization is valid only for the existing stable Apple Development designated
requirement and helper identifier. Deployment must:

- select one explicit Apple Development identity from the canonical login
  Keychain, derive its Team ID with a disposable noninteractive signing probe,
  and require an exact match with the sealed policy;
- prove the explicit signing Keychain and key ACL noninteractively;
- deep-sign the helper before its host apps;
- verify strict signatures and canonical `anchor apple generic`, exact
  identifier, and exact Team-ID designated requirements, plus byte provenance,
  with no password or trust prompt;
- preserve the same designated requirement across updates.

Normal Apple Development certificate renewal under the same Team ID preserves
authorization. A changed Team ID, helper identifier, designated requirement, or
unverifiable signature invalidates authorization and blocks production until the
user runs the explicit authorization flow again.

## User Experience

The dashboard shows one explicit setup action:

1. **Set SMB Credential** with a native secure field (the same action refreshes
   the dedicated optimizer record).
2. A concise explanation that the password travels through an anonymous pipe
   only and is retained only by Keychain. The native field is cleared
   immediately and explicit mutable byte buffers are wiped; this does not claim
   zeroization of AppKit's OS-managed internal field storage.
3. A terminal redacted enum result.

The UI must not show the account, server, share, mount URL, Keychain label,
credential, record identifier, or full signing fingerprint.

## Atomicity and Failure Handling

- Refuse changes unless dedicated-record identity, helper identity, and ACL
  shape are uniquely proven.
- If dedicated-record creation cannot be sealed, remove only the just-created
  dedicated record; never roll back by touching a Finder/legacy record.
- After an apparent update, require a post-change structural comparison and the
  exact helper's credential-only proof.
- If verification fails, production remains disabled. Report that manual
  Keychain inspection is required; do not broaden the ACL or retry with a
  different application.
- Missing, ambiguous, interaction-required, or server-rejected credentials
  block before any canary or asset work.
- An exact SMB connection is required before success and performs no asset
  operation. If a post-store connection fails, the result is fail-closed
  `server_rejected`; the user must explicitly refresh the dedicated record.

## Verification

Implementation tests are added after the implementation and must cover:

- exact single-item discovery and zero/multiple-match rejection;
- helper path, ownership, symlink, quarantine, identifier, signature, Apple Development
  requirement, and provenance rejection;
- ACL copying that preserves existing applications, prompt selector,
  authorizations, description, and non-target ACLs;
- idempotent authorization when the helper requirement already exists;
- cancelled, denied, and failed `SecKeychainItemSetAccess` paths;
- post-write mismatch rejection;
- credential-only proof with no downstream adapters or NAS operations;
- complete redaction of success, error, debug, JSON, app-log, and stderr paths;
- stable designated-requirement acceptance across a same-Team-ID renewal and
  rejection of a wrong Team ID or identifier.

When live verification is performed, keep production stopped:

1. Reuse the stable signing identity and prove the signed helper, canonical
   Keychain, designated requirement, and bundle identifiers with zero prompts.
2. Run the explicit dashboard authorization once and approve only the exact
   credential item/TCC requests presented by macOS.
3. Prove repeated credential-only checks from launchd and SSH are
   interaction-free.
4. Prove exact unattended unmount/remount and SMB no-replace cleanup.
5. Resume the sealed journals with the delete adapter unavailable and
   `delete_calls=0`.
6. Run deletion-disabled cap-10 and cap-100 canaries before enabling production.

Signing approval, Keychain ACL authorization, TCC/NAS or Local Network grants,
and launchd service state are distinct gates; none authorizes another. A changed
Team, helper identifier, designated requirement, or privacy grant requires the
corresponding explicit reauthorization. Upload success never enables deletion.

## Documentation

The existing README documents the supported one-time authorization workflow,
stable-signing identity reuse, redacted verification statuses, service lifecycle,
deletion-disabled canaries, and the conditions that require reauthorization. It
does not document broad partition-list or allow-all workarounds.
