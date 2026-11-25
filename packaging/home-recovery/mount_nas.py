#!/usr/bin/env python3
"""Re-open the saved Finder SMB volume at login without embedding credentials.

This job must run in Michelle's Aqua launchd domain.  ``open smb://`` launched
from an SSH session is not a Finder mount request and can return success while
leaving the volume absent.  The AppleScript ``mount volume`` command delegates
to the logged-in session and its saved Keychain item; this helper never carries
or prints a password.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


DEFAULT_MOUNT = Path("/Volumes/home")
DEFAULT_OUTPUT = Path.home() / "icloudpd-optimizer" / "service" / "recovery-20261103" / "mount-health.json"
DEFAULT_URL = "smb://tushar@zeus._smb._tcp.local/home"
EXPECTED_HOST = "zeus._smb._tcp.local"
EXPECTED_SHARE = "home"


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _mount_source(mount: Path) -> str | None:
    """Return the redacted SMB source mounted at *mount*, if any."""
    try:
        proc = subprocess.run(
            ["/sbin/mount"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    target = f" on {mount} "
    for line in proc.stdout.splitlines():
        if target not in line:
            continue
        source = line.split(target, 1)[0].strip()
        # Never put a username or password-looking component in the receipt.
        source = re.sub(r"//[^/@]+@", "//", source)
        return source
    return None


def _disk_free(mount: Path) -> dict[str, Any] | None:
    try:
        proc = subprocess.run(
            ["/bin/df", "-Pk", str(mount)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    rows = [line.split() for line in proc.stdout.splitlines() if line.strip()]
    if len(rows) < 2 or len(rows[-1]) < 5:
        return None
    row = rows[-1]
    try:
        return {
            "filesystem": re.sub(r"//[^/@]+@", "//", row[0]),
            "blocks_1k": int(row[1]),
            "used_1k": int(row[2]),
            "available_1k": int(row[3]),
            "capacity": row[4],
        }
    except (TypeError, ValueError):
        return None


def _is_expected_mount(mount: Path) -> tuple[bool, str | None]:
    source = _mount_source(mount)
    if not os.path.ismount(mount) or not source:
        return False, source
    normalized = source.lower()
    expected = EXPECTED_HOST.lower()
    # mount(8) can render the Bonjour host as either a URL-like source or an
    # address-qualified SMB source.  Require both the NAS host and share.
    if expected not in normalized or f"/{EXPECTED_SHARE.lower()}" not in normalized:
        return False, source
    return True, source


def run(args: argparse.Namespace) -> int:
    started = time.time()
    mounted, source = _is_expected_mount(args.mount)
    report: dict[str, Any] = {
        "schema_version": 1,
        "checked_at_unix_seconds": started,
        "mount_path": str(args.mount),
        "status": "mounted" if mounted else "not_mounted",
        "attempted": False,
    }
    if source:
        report["source"] = source
    if mounted:
        report["free_space"] = _disk_free(args.mount)
        _atomic_json(args.output, report)
        return 0
    report["attempted"] = True
    escaped_url = args.url.replace("\\", "\\\\").replace('"', '\\"')
    script = f'mount volume "{escaped_url}"'
    try:
        proc = subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=args.mount_timeout_seconds,
            check=False,
        )
        report["mount_exit_code"] = proc.returncode
        if proc.returncode != 0:
            report["status"] = "mount_failed"
            report["error"] = "AppleScript mount volume returned nonzero"
    except subprocess.TimeoutExpired:
        report["status"] = "mount_timed_out"
        report["error"] = "AppleScript mount volume timed out waiting for the Aqua/Keychain session"
    except OSError as exc:
        report["status"] = "mount_unavailable"
        report["error"] = type(exc).__name__

    deadline = time.time() + args.wait_seconds
    while time.time() < deadline:
        mounted, source = _is_expected_mount(args.mount)
        if mounted:
            report["status"] = "mounted"
            report["source"] = source
            report["free_space"] = _disk_free(args.mount)
            break
        time.sleep(2)
    if report["status"] != "mounted" and os.path.ismount(args.mount):
        report["status"] = "wrong_mount"
        report["error"] = "mount path is occupied by an unexpected filesystem"
        report["source"] = _mount_source(args.mount)
    report["finished_at_unix_seconds"] = time.time()
    _atomic_json(args.output, report)
    return 0 if report["status"] == "mounted" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mount", type=Path, default=DEFAULT_MOUNT)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--mount-timeout-seconds", type=int, default=15)
    # Keep the old flag accepted for one manual invocation while the installed
    # launch agent rolls forward; it controls the same bounded mount call.
    parser.add_argument(
        "--open-timeout-seconds",
        dest="mount_timeout_seconds",
        type=int,
        default=argparse.SUPPRESS,
    )
    parser.add_argument("--wait-seconds", type=int, default=20)
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
