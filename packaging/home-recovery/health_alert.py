#!/usr/bin/env python3
"""Send rate-limited Telegram alerts for the syncer's operational health.

The checker reads the existing icloudpd key/value config in memory only.  It
never prints or writes the Telegram token, chat ID, Apple ID, or cookie.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


SERVICE = Path.home() / "icloudpd-optimizer" / "service"
DEFAULT_CONFIG = Path.home() / "icloudpd" / "icloudpd.conf"
DEFAULT_STATE = SERVICE / "recovery-20261103" / "health-alert-state.json"
DEFAULT_REPORT = SERVICE / "recovery-20261103" / "health-alert.json"
DEFAULT_MOUNT = Path("/Volumes/home")
DEFAULT_DAYS = Path.home() / "icloudpd" / "DAYS_REMAINING"
DEFAULT_DOCKER_BIN = "/usr/local/bin/docker"
DEFAULT_DOCKER_CONTEXT = "desktop-linux"
DEFAULT_CONTAINER_NAME = "icloudpd"
DEFAULT_MONITOR_CONFIGS = (
    ("main", SERVICE / "monitor.json"),
    ("shared", SERVICE / "monitor-shared.json"),
)


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


def _parse_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip().lower()] = value.strip().strip("'\"")
    return values


def _monitor_manifest_paths(configs: tuple[tuple[str, Path], ...]) -> tuple[tuple[str, Path], ...]:
    paths: list[tuple[str, Path]] = []
    for library, config in configs:
        data = json.loads(config.read_text(encoding="utf-8"))
        manifest = data.get("manifest_path") if isinstance(data, dict) else None
        if isinstance(manifest, str) and manifest:
            paths.append((library, Path(manifest).expanduser()))
    return tuple(paths)


def _launchd_runtime_observation(label: str) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"label": label, "state": "unreadable", "detail": type(exc).__name__}
    output = proc.stdout + proc.stderr
    if proc.returncode != 0:
        return {"label": label, "state": "not_loaded"}
    state = re.search(r"^\s*state = ([^\n]+)", output, re.MULTILINE)
    active = re.search(r"^\s*active count = (\d+)", output, re.MULTILINE)
    return {
        "label": label,
        "state": state.group(1).strip() if state else "unknown",
        "active_count": int(active.group(1)) if active else None,
    }


def _docker_container_observation(
    docker_bin: str,
    docker_context: str,
    container_name: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Inspect one container state; this command has no Docker mutation verb."""
    command = [
        docker_bin,
        "--context",
        docker_context,
        "container",
        "inspect",
        "--format",
        "{{json .State}}",
        container_name,
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {"state": "unavailable", "reason": "docker_binary_missing"}
    except subprocess.TimeoutExpired:
        return {"state": "unavailable", "reason": "docker_inspection_timeout"}
    except OSError:
        return {"state": "unavailable", "reason": "docker_inspection_failed"}
    if result.returncode != 0:
        stderr = result.stderr.lower()
        if "no such object" in stderr or "no such container" in stderr:
            return {"state": "missing", "reason": "container_missing"}
        if "cannot connect" in stderr or "is the docker daemon running" in stderr:
            return {"state": "unavailable", "reason": "docker_daemon_unavailable"}
        return {"state": "unavailable", "reason": "docker_inspection_failed"}
    try:
        payload = json.loads(result.stdout.strip())
    except (ValueError, TypeError):
        return {"state": "unavailable", "reason": "docker_state_invalid"}
    if not isinstance(payload, dict):
        return {"state": "unavailable", "reason": "docker_state_invalid"}
    health = payload.get("Health")
    health_status = health.get("Status") if isinstance(health, dict) else None
    return {
        "state": payload.get("Status") if isinstance(payload.get("Status"), str) else "unknown",
        "health": health_status if isinstance(health_status, str) else None,
        "exit_code": payload.get("ExitCode") if isinstance(payload.get("ExitCode"), int) else None,
    }


def _container_observation(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any] | None]:
    runtime = _launchd_runtime_observation(args.container_label)
    docker = _docker_container_observation(args.docker_bin, args.docker_context, args.container_name)
    state_file = args.container_state
    observation = {"runtime": runtime, "docker": docker, "container_state": docker.get("state", "unknown")}
    state = docker.get("state")
    health = docker.get("health")
    if state == "running" and health in {None, "healthy"}:
        return observation, None
    if state == "running" and health == "unhealthy":
        return observation, {"id": "container_unhealthy", "message": "iCloudPD container reports unhealthy"}
    if state == "running" and health == "starting":
        return observation, {"id": "container_health_starting", "message": "iCloudPD container health check is starting"}
    if state in {"exited", "stopped", "dead"}:
        exit_code = docker.get("exit_code")
        suffix = f" (exit code {exit_code})" if isinstance(exit_code, int) else ""
        return observation, {"id": "container_exited", "message": f"iCloudPD container state is {state}{suffix}"}
    if state == "restarting":
        return observation, {"id": "container_restarting", "message": "iCloudPD container is restarting"}
    if state == "missing":
        return observation, {"id": "container_missing", "message": "iCloudPD container is missing from the configured Docker context"}
    # A local state file is retained as a diagnostic hint but never overrides
    # an unavailable Docker inspection, preventing stale state from looking
    # healthy after the container exits.
    state_file_hint = None
    try:
        raw = state_file.read_text(encoding="utf-8", errors="replace").strip()
        if raw:
            try:
                data = json.loads(raw)
                state_file_hint = str(data.get("state", "unknown")).lower() if isinstance(data, dict) else "unknown"
            except json.JSONDecodeError:
                state_file_hint = raw.splitlines()[-1].lower()
    except OSError:
        pass
    if state_file_hint:
        observation["state_file_hint"] = state_file_hint
    reason = docker.get("reason")
    if reason == "docker_daemon_unavailable":
        return observation, {"id": "container_runtime_not_running", "message": "configured Docker runtime is not reachable"}
    if reason == "docker_binary_missing":
        return observation, {"id": "container_runtime_unavailable", "message": "configured Docker binary is unavailable"}
    if reason == "docker_inspection_timeout":
        return observation, {"id": "container_inspection_timeout", "message": "Docker container inspection timed out"}
    return observation, {"id": "container_state_unknown", "message": "iCloudPD container state is not observable"}


def _progress_projection(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered == "failures" or lowered.endswith("_at") or "timestamp" in lowered:
                continue
            result[str(key)] = _progress_projection(item)
        return result
    if isinstance(value, list):
        return [_progress_projection(item) for item in value]
    return value


def _success_updated_at(value: Any) -> float | None:
    if not isinstance(value, dict) or not isinstance(value.get("records"), list):
        return None
    candidates: list[float] = []
    for record in value["records"]:
        if not isinstance(record, dict) or record.get("state") in {"failed", "needs_review"}:
            continue
        stamp = record.get("updated_at")
        if not isinstance(stamp, str):
            continue
        clean = stamp.rstrip("Z")
        try:
            candidates.append(float(clean))
        except ValueError:
            continue
    return max(candidates) if candidates else None


def _progress_state(
    manifests: tuple[tuple[str, Path], ...],
    previous: dict[str, Any],
    now: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prior_progress = previous.get("progress", {}) if isinstance(previous, dict) else {}
    next_progress: dict[str, Any] = {}
    observations: list[dict[str, Any]] = []
    for library, manifest in manifests:
        try:
            value = json.loads(manifest.read_text(encoding="utf-8"))
            signature = hashlib.sha256(json.dumps(_progress_projection(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        except (OSError, ValueError, TypeError):
            observations.append({"library": library, "status": "unreadable"})
            next_progress[library] = {"status": "unreadable"}
            continue
        prior = prior_progress.get(library, {}) if isinstance(prior_progress, dict) else {}
        changed = "signature" in prior and prior.get("signature") != signature
        last_change = now if changed else prior.get("last_change_unix_seconds")
        seeded_from = None
        if last_change is None:
            seeded = _success_updated_at(value)
            if seeded is not None and seeded <= now:
                last_change = seeded
                seeded_from = "newest_success_updated_at"
        if last_change is None:
            status = "unknown"
            age = None
        else:
            status = "stale" if now - float(last_change) > 24 * 60 * 60 else "recent"
            age = max(0.0, now - float(last_change))
        next_progress[library] = {
            "signature": signature,
            "last_change_unix_seconds": last_change,
            "seeded_from": seeded_from or prior.get("seeded_from"),
        }
        observations.append({
            "library": library,
            "status": status,
            "last_change_unix_seconds": last_change,
            "age_seconds": age,
            "signature": signature,
        })
    return observations, next_progress


def _issues(args: argparse.Namespace, previous: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    observations: dict[str, Any] = {}
    if not os.path.ismount(args.mount):
        issues.append({"id": "mount_missing", "message": "NAS mount /Volumes/home is missing"})

    container_observation, container_issue = _container_observation(args)
    observations["container"] = container_observation
    if container_issue:
        issues.append(container_issue)

    try:
        remaining = int(args.days.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        remaining = None
    if remaining is None:
        issues.append({"id": "cookie_days_unreadable", "message": "iCloud cookie expiry state is unreadable"})
    elif remaining <= args.cookie_warning_days:
        issues.append({"id": "cookie_expiring", "message": f"iCloud cookie expires in {remaining} day(s)"})

    try:
        manifests = _monitor_manifest_paths(tuple(args.monitor_config))
    except (OSError, ValueError, json.JSONDecodeError):
        manifests = ()
    now = time.time()
    progress_observations, next_progress = _progress_state(manifests, previous, now)
    observations["progress"] = progress_observations
    for item in progress_observations:
        library = item["library"]
        if item["status"] == "unreadable":
            issues.append({"id": f"progress_missing_{library}", "message": f"{library} sync manifest is unreadable"})
        elif item["status"] == "unknown":
            issues.append({"id": f"progress_unknown_{library}", "message": f"{library} sync progress age is unknown"})
        elif item["status"] == "stale":
            age = float(item["age_seconds"])
            issues.append({
                "id": f"no_progress_{library}",
                "message": f"{library} sync success state has not changed for {age / 3600:.1f} hours",
                "age_seconds": age,
            })
    if not manifests:
        issues.append({"id": "progress_unreadable", "message": "sync manifest paths are not readable"})
    return issues, observations, next_progress


def _telegram_url(config: dict[str, str]) -> tuple[str, str] | None:
    token = config.get("telegram_token", "").strip()
    chat_id = config.get("telegram_chat_id", "").strip()
    if not token or not chat_id:
        return None
    server = config.get("telegram_server", "api.telegram.org").strip() or "api.telegram.org"
    scheme = "http" if config.get("telegram_http", "false").lower() == "true" else "https"
    return f"{scheme}://{server}/bot{token}/sendMessage", chat_id


def _send(url_chat: tuple[str, str], text: str) -> None:
    url, chat_id = url_chat
    payload = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"Telegram HTTP {response.status}")
        try:
            body = json.loads(response.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("Telegram returned invalid JSON") from exc
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise RuntimeError("Telegram API rejected request")


def run(args: argparse.Namespace) -> int:
    try:
        previous = json.loads(args.state.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = {"active": {}, "last_sent": {}}
    current, observations, next_progress = _issues(args, previous)
    current_by_id = {item["id"]: item for item in current}
    previous_active = previous.get("active", {}) if isinstance(previous, dict) else {}
    last_sent = previous.get("last_sent", {}) if isinstance(previous, dict) else {}
    now = time.time()
    notify: list[tuple[str, str]] = []
    for issue_id, issue in current_by_id.items():
        if issue_id not in previous_active or now - float(last_sent.get(issue_id, 0)) >= args.repeat_seconds:
            notify.append((issue_id, f"iCloudPD alert: {issue['message']}"))
    for issue_id, old_issue in previous_active.items():
        if issue_id not in current_by_id:
            notify.append((issue_id, f"iCloudPD resolved: {old_issue.get('message', issue_id)}"))

    delivery = "not_needed"
    delivery_error: str | None = None
    if notify:
        try:
            config = _parse_config(args.config)
            endpoint = _telegram_url(config)
            if endpoint is None:
                delivery = "telegram_unconfigured"
            else:
                for issue_id, message in notify:
                    _send(endpoint, message)
                    last_sent[issue_id] = now
                delivery = "sent"
        except Exception as exc:  # keep state so a later run can retry without leaking credentials
            delivery = "failed"
            delivery_error = type(exc).__name__

    report: dict[str, Any] = {
        "schema_version": 1,
        "checked_at_unix_seconds": now,
        "status": "healthy" if not current else "unhealthy",
        "issues": current,
        "observations": observations,
        "notifications_considered": len(notify),
        "delivery": delivery,
    }
    if delivery_error:
        report["delivery_error"] = delivery_error
    _atomic_json(args.report, report)
    _atomic_json(args.state, {
        "schema_version": 1,
        "checked_at_unix_seconds": now,
        "active": current_by_id,
        "last_sent": last_sent,
        "progress": next_progress,
    })
    return 0 if not current else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--mount", type=Path, default=DEFAULT_MOUNT)
    parser.add_argument("--days", type=Path, default=DEFAULT_DAYS)
    parser.add_argument("--container-label", default="homebrew.mxcl.colima")
    parser.add_argument("--container-state", type=Path, default=Path.home() / "icloudpd" / "container.state")
    parser.add_argument("--docker-bin", default=DEFAULT_DOCKER_BIN)
    parser.add_argument("--docker-context", default=DEFAULT_DOCKER_CONTEXT)
    parser.add_argument("--container-name", default=DEFAULT_CONTAINER_NAME)
    parser.add_argument("--cookie-warning-days", type=int, default=3)
    parser.add_argument("--no-progress-seconds", type=int, default=24 * 60 * 60)
    parser.add_argument("--repeat-seconds", type=int, default=6 * 60 * 60)
    parser.add_argument("--monitor-config", action="append", metavar="LIBRARY=PATH")
    args = parser.parse_args()
    configs: list[tuple[str, Path]] = []
    for item in args.monitor_config or []:
        if "=" not in item:
            parser.error("--monitor-config must be LIBRARY=PATH")
        library, path = item.split("=", 1)
        configs.append((library, Path(path).expanduser()))
    args.monitor_config = tuple(configs or DEFAULT_MONITOR_CONFIGS)
    return args


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
