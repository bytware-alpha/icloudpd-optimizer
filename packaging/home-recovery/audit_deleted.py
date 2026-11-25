#!/usr/bin/env python3
"""Read-only audit of NAS originals referenced by deleted manifest records.

The audit deliberately refuses to classify anything as missing until the NAS
root is a real mount.  It hashes each candidate while checking that the file's
identity, size, and modification time stay stable for the entire read.
"""

from __future__ import annotations

import argparse
import contextlib
import concurrent.futures
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


SHA256_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
DEFAULT_SERVICE = Path.home() / "icloudpd-optimizer" / "service"
DEFAULT_CONFIGS = (
    ("main", DEFAULT_SERVICE / "monitor.json"),
    ("shared", DEFAULT_SERVICE / "monitor-shared.json"),
)


def _json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _stat_signature(path: Path) -> tuple[int, int, int, int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_mode)


def _sha256_file(path: Path) -> tuple[str, int, tuple[int, int, int, int, int], tuple[int, int, int, int, int]]:
    before = _stat_signature(path)
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(8 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
    after = _stat_signature(path)
    return digest.hexdigest(), total, before, after


def _under_root(path: Path, root: Path) -> bool:
    try:
        root_resolved = Path(os.path.realpath(root))
        return os.path.commonpath((str(path), str(root_resolved))) == str(root_resolved)
    except ValueError:
        return False


def _mount_signature(root: Path) -> tuple[int, int, int, int] | None:
    if not os.path.ismount(root):
        return None
    try:
        stat = root.stat()
    except OSError:
        return None
    return (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_mtime_ns)


def _mount_is_stable(root: Path, expected: tuple[int, int, int, int] | None) -> bool:
    return expected is not None and _mount_signature(root) == expected


def _manifest_snapshot(path: Path) -> tuple[dict[str, Any], bytes, tuple[int, int, int, int, int]]:
    before = _stat_signature(path)
    raw = path.read_bytes()
    after = _stat_signature(path)
    if before != after:
        raise RuntimeError("manifest changed while being read")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("records"), list):
        raise ValueError("manifest has no records array")
    return value, raw, after


def _manifest_receipt(path: Path, raw: bytes, stat: tuple[int, int, int, int, int], records: list[Any]) -> dict[str, Any]:
    deleted = sum(1 for item in records if isinstance(item, dict) and item.get("state") == "deleted")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "stat": {
            "device": stat[0],
            "inode": stat[1],
            "size_bytes": stat[2],
            "mtime_ns": stat[3],
        },
        "records": len(records),
        "deleted_records": deleted,
    }


def _audit_record(
    library: str,
    index: int,
    cohort: str,
    record: dict[str, Any],
    nas_root: Path,
    mount_signature: tuple[int, int, int, int],
) -> dict[str, Any]:
    proof = record.get("proofs")
    nas = proof.get("nas") if isinstance(proof, dict) else None
    result: dict[str, Any] = {
        "library": library,
        "record_index": index,
        "asset_id": record.get("asset_id"),
        "state": record.get("state"),
        "cohort": cohort,
    }
    if not isinstance(nas, dict):
        result.update({"status": "proof_missing", "reason": "proofs.nas is absent"})
        return result

    canonical = nas.get("canonical_path")
    expected_hash = nas.get("sha256")
    expected_size = nas.get("size_bytes")
    if not isinstance(canonical, str) or not canonical:
        result.update({"status": "proof_missing", "reason": "proofs.nas.canonical_path is absent"})
        return result
    if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
        result.update({"status": "proof_missing", "reason": "proofs.nas.sha256 is invalid"})
        return result
    if not isinstance(expected_size, int) or expected_size < 0:
        result.update({"status": "proof_missing", "reason": "proofs.nas.size_bytes is invalid"})
        return result

    resolved = Path(os.path.realpath(canonical))
    result.update({
        "canonical_path": canonical,
        "resolved_path": str(resolved),
        "expected_sha256": expected_hash.lower(),
        "expected_size_bytes": expected_size,
    })
    if not _under_root(resolved, nas_root):
        result.update({"status": "unsafe_path", "reason": "canonical path escapes mounted NAS root"})
        return result
    if not _mount_is_stable(nas_root, mount_signature):
        result.update({"status": "mount_lost", "reason": "NAS mount changed before hash"})
        return result

    try:
        digest, size, before, after = _sha256_file(resolved)
    except FileNotFoundError:
        if not _mount_is_stable(nas_root, mount_signature):
            result.update({"status": "mount_lost", "reason": "NAS mount disappeared while opening original"})
        else:
            result.update({"status": "missing", "reason": "NAS original does not exist"})
        return result
    except OSError as exc:
        if not _mount_is_stable(nas_root, mount_signature):
            result.update({"status": "mount_lost", "reason": "NAS mount disappeared while reading original"})
        else:
            result.update({"status": "unreadable", "reason": f"{type(exc).__name__}: {exc}"})
        return result

    if not _mount_is_stable(nas_root, mount_signature):
        result.update({"status": "mount_lost", "reason": "NAS mount changed during hash"})
        return result
    result.update({
        "observed_sha256": digest,
        "observed_size_bytes": size,
        "stat_before": {"device": before[0], "inode": before[1], "size_bytes": before[2], "mtime_ns": before[3]},
        "stat_after": {"device": after[0], "inode": after[1], "size_bytes": after[2], "mtime_ns": after[3]},
    })
    if before != after:
        result.update({"status": "changed_during_hash", "reason": "NAS file stat changed during streaming hash"})
    elif size != expected_size:
        result.update({"status": "size_mismatch", "reason": "streamed size differs from manifest proof"})
    elif digest.lower() != expected_hash.lower():
        result.update({"status": "hash_mismatch", "reason": "streamed SHA-256 differs from manifest proof"})
    else:
        result.update({"status": "verified", "reason": "stable stat, size, and SHA-256 match"})
    return result


def _delete_review_candidate(record: dict[str, Any]) -> bool:
    if record.get("state") == "deleted":
        return True
    if record.get("state") not in {"needs_review", "failed"}:
        return False
    failures = record.get("failures")
    proof_keys = record.get("proofs")
    signals = json.dumps(failures, sort_keys=True).lower()
    if isinstance(proof_keys, dict):
        signals += " " + " ".join(str(key).lower() for key in proof_keys)
    return any(token in signals for token in ("delete", "recently", "expung", "cloudkit"))


def _expected_bytes(pending: Iterable[tuple[str, int, str, dict[str, Any]]]) -> int:
    total = 0
    for _library, _index, _cohort, record in pending:
        proofs = record.get("proofs")
        nas = proofs.get("nas") if isinstance(proofs, dict) else None
        size = nas.get("size_bytes") if isinstance(nas, dict) else None
        if isinstance(size, int) and size >= 0:
            total += size
    return total


def _records(manifests: Iterable[tuple[str, Path]]) -> tuple[list[tuple[str, int, str, dict[str, Any]]], list[dict[str, Any]]]:
    pending: list[tuple[str, int, str, dict[str, Any]]] = []
    receipts: list[dict[str, Any]] = []
    for library, path in manifests:
        value, raw, stat = _manifest_snapshot(path)
        records = value["records"]
        receipts.append(_manifest_receipt(path, raw, stat, records))
        for index, record in enumerate(records):
            if isinstance(record, dict) and _delete_review_candidate(record):
                cohort = "deleted" if record.get("state") == "deleted" else "delete_review"
                pending.append((library, index, cohort, record))
    return pending, receipts


def _manifest_sources(configs: Iterable[tuple[str, Path]]) -> tuple[tuple[str, Path], ...]:
    sources: list[tuple[str, Path]] = []
    for library, config_path in configs:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        manifest_path = config.get("manifest_path") if isinstance(config, dict) else None
        if not isinstance(manifest_path, str) or not manifest_path:
            raise ValueError(f"{config_path}: manifest_path is absent")
        sources.append((library, Path(manifest_path).expanduser()))
    return tuple(sources)


def _redact_mount_source(source: str) -> str:
    """Remove a username component before recording an SMB source."""
    return re.sub(r"(//)[^/@]+@", r"\1", source)


def _run(args: argparse.Namespace) -> int:
    output = Path(args.output).expanduser()
    nas_root = Path(args.nas_root).expanduser()
    started = time.time()
    base: dict[str, Any] = {
        "schema_version": 1,
        "audit": "deleted-nas-originals",
        "started_at_unix_seconds": started,
        "finished_at_unix_seconds": None,
        "status": "running",
        "nas_root": str(nas_root),
        "mount_required": True,
        "progress": {"total": 0, "completed": 0, "verified": 0, "issues": 0, "bytes_hashed": 0},
        "manifests": [],
        "records": [],
    }
    verifier_host = getattr(args, "verifier_host", None)
    mount_source = getattr(args, "mount_source", None)
    if verifier_host:
        base["verifier_host"] = verifier_host
    if mount_source:
        base["nas_source"] = _redact_mount_source(mount_source)
    mount_signature = _mount_signature(nas_root)
    if mount_signature is None:
        base.update({
            "status": "blocked_mount_missing",
            "reason": "NAS root is not a mounted filesystem; no records were classified",
            "finished_at_unix_seconds": time.time(),
        })
        _json_write(output, base)
        return 2

    try:
        pending, receipts = _records(args.manifest)
    except Exception as exc:  # fail closed and preserve a machine-readable receipt
        base.update({
            "status": "manifest_read_failed",
            "reason": f"{type(exc).__name__}: {exc}",
            "finished_at_unix_seconds": time.time(),
        })
        _json_write(output, base)
        return 3

    base["manifests"] = receipts
    base["progress"]["total"] = len(pending)
    expected_bytes = _expected_bytes(pending)
    base["progress"]["expected_bytes"] = expected_bytes
    _json_write(output, base)
    workers = max(1, min(int(getattr(args, "workers", 1)), 4))
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers) if workers > 1 else None
    completed = 0
    try:
        offset = 0
        while offset < len(pending):
            batch = pending[offset : offset + workers]
            if not _mount_is_stable(nas_root, mount_signature):
                base["status"] = "mount_lost"
                base["reason"] = "NAS mount changed during audit; later records were not classified"
                break
            if executor is None:
                results = [
                    _audit_record(library, index, cohort, record, nas_root, mount_signature)
                    for library, index, cohort, record in batch
                ]
            else:
                futures = [
                    executor.submit(_audit_record, library, index, cohort, record, nas_root, mount_signature)
                    for library, index, cohort, record in batch
                ]
                # Consume in manifest order so the receipt is deterministic even
                # though the SMB reads overlap.
                results = [future.result() for future in futures]
            for result in results:
                base["records"].append(result)
                completed += 1
                progress = base["progress"]
                progress["completed"] = completed
                progress["bytes_hashed"] += int(result.get("observed_size_bytes", 0) or 0)
                if result.get("status") == "verified":
                    progress["verified"] += 1
                else:
                    progress["issues"] += 1
                elapsed = max(time.time() - started, 0.001)
                progress["elapsed_seconds"] = elapsed
                progress["bytes_per_second"] = progress["bytes_hashed"] / elapsed
                remaining_bytes = max(expected_bytes - progress["bytes_hashed"], 0)
                progress["eta_seconds"] = (
                    remaining_bytes / progress["bytes_per_second"]
                    if progress["bytes_per_second"] > 0
                    else None
                )
                progress["eta_method"] = "expected_bytes"
                if completed == len(pending) or completed % max(args.progress_every, 1) == 0:
                    _json_write(output, base)
            offset += len(batch)
            if any(result.get("status") == "mount_lost" for result in results):
                base["status"] = "mount_lost"
                base["reason"] = "NAS mount changed during audit; later records were not classified"
                break
    finally:
        if executor is not None:
            executor.shutdown(wait=True)

    issues = [item for item in base["records"] if item.get("status") != "verified"]
    base["counts"] = {
        "deleted": sum(1 for item in base["records"] if item.get("cohort") == "deleted"),
        "delete_review": sum(1 for item in base["records"] if item.get("cohort") == "delete_review"),
        "verified": sum(1 for item in base["records"] if item.get("status") == "verified"),
        "issues": len(issues),
    }
    if base.get("status") == "running":
        base["status"] = "complete" if not issues else "complete_with_issues"
    base["finished_at_unix_seconds"] = time.time()
    base["progress"]["elapsed_seconds"] = base["finished_at_unix_seconds"] - started
    _json_write(output, base)
    if base["status"] == "mount_lost":
        return 5
    return 0 if not issues else 4


@contextlib.contextmanager
def _audit_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield None
            return
        yield handle
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def run(args: argparse.Namespace) -> int:
    lock_path = Path(args.lock).expanduser()
    with _audit_lock(lock_path) as lock:
        if lock is None:
            return 6
        if not args.force:
            try:
                previous = json.loads(Path(args.output).read_text(encoding="utf-8"))
                if previous.get("status") in {"complete", "complete_with_issues"}:
                    return 0
            except (OSError, ValueError):
                pass
        return _run(args)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nas-root", default="/Volumes/home")
    parser.add_argument("--output", default=str(DEFAULT_SERVICE / "recovery-20261103" / "deleted-nas-audit.json"))
    parser.add_argument("--lock", default=str(DEFAULT_SERVICE / "recovery-20261103" / "deleted-nas-audit.lock"))
    parser.add_argument("--force", action="store_true", help="re-run even when a completed receipt exists")
    parser.add_argument("--progress-every", type=int, default=10)
    parser.add_argument("--workers", type=int, default=1, help="parallel SMB hash workers (1-4; default 1)")
    parser.add_argument(
        "--verifier-host",
        help="provenance label for the machine that streamed the NAS files (for example, laptop)",
    )
    parser.add_argument(
        "--mount-source",
        help="redacted mount(8) source identity to record with the receipt",
    )
    parser.add_argument(
        "--config",
        action="append",
        metavar="LIBRARY=PATH",
        help="monitor config source; may be repeated (defaults to live monitor configs)",
    )
    parser.add_argument(
        "--manifest",
        action="append",
        metavar="LIBRARY=PATH",
        help="manifest source; may be repeated (defaults to main and shared production manifests)",
    )
    args = parser.parse_args(argv)
    if args.manifest:
        parsed: list[tuple[str, Path]] = []
        for item in args.manifest:
            if "=" not in item:
                parser.error("--manifest must be LIBRARY=PATH")
            library, path = item.split("=", 1)
            if not library or not path:
                parser.error("--manifest must be LIBRARY=PATH")
            parsed.append((library, Path(path).expanduser()))
        args.manifest = tuple(parsed)
    else:
        configs = DEFAULT_CONFIGS
        if args.config:
            parsed_configs: list[tuple[str, Path]] = []
            for item in args.config:
                if "=" not in item:
                    parser.error("--config must be LIBRARY=PATH")
                library, path = item.split("=", 1)
                if not library or not path:
                    parser.error("--config must be LIBRARY=PATH")
                parsed_configs.append((library, Path(path).expanduser()))
            configs = tuple(parsed_configs)
        args.manifest = _manifest_sources(configs)
    return args


if __name__ == "__main__":
    raise SystemExit(run(parse_args(sys.argv[1:])))
