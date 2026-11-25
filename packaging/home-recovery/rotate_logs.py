#!/usr/bin/env python3
"""Bounded-tail rotation for the optimizer's two service stderr logs.

The full stderr files are intentionally truncated after their bounded tails are
sealed.  The initial receipt is retained separately from later no-op runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


SERVICE = Path.home() / "icloudpd-optimizer" / "service"
DEFAULT_LOGS = (SERVICE / "monitor.stderr.log", SERVICE / "monitor-shared.stderr.log")
DEFAULT_OUTPUT = SERVICE / "recovery-20261103" / "log-rotation.json"
TAIL_BYTES = 8 * 1024 * 1024
TAIL_RETENTION = 7


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


def _tail_copy(source: Path, destination: Path, limit: int) -> int:
    with source.open("rb") as handle:
        handle.seek(max(0, source.stat().st_size - limit))
        data = handle.read(limit)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(b"# bounded tail; original was intentionally truncated by rotate_logs.py\n")
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(destination)
        except FileNotFoundError:
            pass
        raise
    return destination.stat().st_size


def _prune_tails(source: Path, keep: int = TAIL_RETENTION) -> list[str]:
    candidates = sorted(source.parent.glob(f"{source.name}.*.tail"), key=lambda item: item.name, reverse=True)
    removed: list[str] = []
    for path in candidates[keep:]:
        try:
            path.unlink()
            removed.append(str(path))
        except FileNotFoundError:
            pass
    return removed


def rotate(logs: tuple[Path, ...], output: Path, threshold: int, tail_bytes: int) -> int:
    started = time.time()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "complete",
        "started_at_unix_seconds": started,
        "finished_at_unix_seconds": None,
        "tail_bytes_limit": tail_bytes,
        "threshold_bytes": threshold,
        "logs": [],
    }
    for source in logs:
        item: dict[str, Any] = {"path": str(source), "status": "skipped"}
        try:
            before = source.stat()
        except FileNotFoundError:
            item.update({"status": "absent"})
            receipt["logs"].append(item)
            continue
        item.update({"size_before_bytes": before.st_size, "mtime_ns_before": before.st_mtime_ns})
        if before.st_size <= threshold:
            item.update({"status": "below_threshold", "pruned_tail_paths": _prune_tails(source)})
            receipt["logs"].append(item)
            continue
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        tail = source.with_name(f"{source.name}.{stamp}.tail")
        tail_size = _tail_copy(source, tail, tail_bytes)
        tail_hash = hashlib.sha256(tail.read_bytes()).hexdigest()
        with source.open("r+b") as handle:
            handle.truncate(0)
            handle.flush()
            os.fsync(handle.fileno())
        after = source.stat()
        item.update({
            "status": "rotated",
            "tail_path": str(tail),
            "tail_size_bytes": tail_size,
            "tail_sha256": tail_hash,
            "size_after_bytes": after.st_size,
            "pruned_tail_paths": _prune_tails(source),
        })
        receipt["logs"].append(item)
    receipt["finished_at_unix_seconds"] = time.time()
    if output.exists():
        latest = output.with_name(f"{output.stem}-latest{output.suffix}")
        _atomic_json(latest, receipt)
    else:
        _atomic_json(output, receipt)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", action="append", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--threshold-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--tail-bytes", type=int, default=TAIL_BYTES)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    raise SystemExit(rotate(tuple(args.log or DEFAULT_LOGS), args.output, args.threshold_bytes, args.tail_bytes))
