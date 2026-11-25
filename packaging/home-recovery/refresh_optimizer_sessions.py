#!/usr/bin/env python3
"""Validate fresh iCloud cookies and export optimizer session adapters.

This command deliberately supplies a password provider that returns ``None``.
An expired cookie can therefore fail closed, but cannot trigger a password or
2FA prompt.  Existing optimizer session files are touched only after the
account, service URLs, cookies, destination metadata, and all output shapes
have passed validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit


APPLE_ID = "tushartheawesome@icloud.com"
DEFAULT_COOKIE_DIRECTORY = Path.home() / "icloudpd-optimizer" / "cloudkit-auth-v1.32.3"
DEFAULT_SESSION_DIRECTORY = Path.home() / "icloudpd-optimizer" / "service" / "private-runtime"
UPLOAD_FILE = "upload-session-production.json"
DELETE_PRODUCTION_FILE = "delete-session-production.json"
SESSION_FILES = (UPLOAD_FILE, DELETE_PRODUCTION_FILE)
SAFE_QUERY_NAMES = frozenset(
    {"clientBuildNumber", "clientMasteringNumber", "clientId", "dsid", "remapEnums", "getCurrentSyncToken"}
)
SAFE_DESTINATION = re.compile(r"\A[A-Za-z0-9_.:-]+\Z")
DSID = re.compile(r"\A[0-9]+\Z")


class SessionRefreshError(RuntimeError):
    """A redacted, fail-closed validation or write error."""


def _redacted_error(exc: BaseException) -> SessionRefreshError:
    if isinstance(exc, SessionRefreshError):
        return exc
    return SessionRefreshError(f"{type(exc).__name__}: session validation failed")


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SessionRefreshError(f"cannot read session file ({type(exc).__name__})") from exc
    if not isinstance(value, dict):
        raise SessionRefreshError("session file must contain an object")
    return value, raw


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _file_proof(paths: Iterable[Path]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in paths:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            result.append({"path": str(path), "exists": False, "sha256": None})
            continue
        result.append({"path": str(path), "exists": True, "mode": oct(mode), "sha256": _sha256(path)})
    return result


def _normalize_dsid(value: Any) -> str:
    if isinstance(value, bool):
        raise SessionRefreshError("account DSID has an invalid type")
    text = str(value)
    if not DSID.fullmatch(text):
        raise SessionRefreshError("account DSID has an invalid shape")
    return text


def _validate_existing_session(value: dict[str, Any], kind: str) -> None:
    if kind == "upload":
        required = {"cookies", "dsid", "photosupload_url", "time_zone_offset_minutes", "local_time_zone_id"}
    else:
        required = {"cookies", "dsid", "ckdatabasews_url", "cloudkit_query_params", "database_scope", "zone_name", "owner_record_name"}
    missing = sorted(key for key in required if key not in value)
    if missing:
        raise SessionRefreshError(f"{kind} session is missing required fields")
    _normalize_dsid(value["dsid"])
    if not isinstance(value["cookies"], list) or not value["cookies"]:
        raise SessionRefreshError(f"{kind} session has no cookies")
    for cookie in value["cookies"]:
        if not isinstance(cookie, dict) or not isinstance(cookie.get("name"), str) or not isinstance(cookie.get("value"), str):
            raise SessionRefreshError(f"{kind} session cookie shape is invalid")
    if kind == "upload":
        if not isinstance(value["local_time_zone_id"], str) or not value["local_time_zone_id"]:
            raise SessionRefreshError("upload timezone identifier is invalid")
        if not isinstance(value["time_zone_offset_minutes"], int) or isinstance(value["time_zone_offset_minutes"], bool):
            raise SessionRefreshError("upload timezone offset is invalid")
    else:
        for field in ("database_scope", "zone_name", "owner_record_name"):
            item = value.get(field)
            if not isinstance(item, str) or not SAFE_DESTINATION.fullmatch(item):
                raise SessionRefreshError(f"delete destination field {field} is invalid")
        query = value["cloudkit_query_params"]
        if not isinstance(query, list) or not query:
            raise SessionRefreshError("delete query parameters are missing")
        names: set[str] = set()
        for item in query:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
                raise SessionRefreshError("delete query parameter shape is invalid")
            name = item["name"]
            if name not in SAFE_QUERY_NAMES or name in names:
                raise SessionRefreshError("delete query parameters contain an unsafe or duplicate name")
            names.add(name)


def _fresh_url(webservices: Any, key: str) -> str:
    if not isinstance(webservices, dict):
        raise SessionRefreshError("authenticated response has no webservices map")
    entry = webservices.get(key)
    if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
        raise SessionRefreshError(f"authenticated response is missing {key} service")
    url = entry["url"].strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SessionRefreshError(f"authenticated {key} service URL is unsafe")
    return url


def _fresh_cookies(service: Any) -> list[dict[str, str]]:
    session = getattr(service, "session", None)
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        raise SessionRefreshError("authenticated service has no cookie jar")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for cookie in cookies:
        name = getattr(cookie, "name", None)
        value = getattr(cookie, "value", None)
        if not isinstance(name, str) or not name or not isinstance(value, str) or not value or name in seen:
            raise SessionRefreshError("authenticated cookie jar contains an invalid or duplicate cookie")
        seen.add(name)
        result.append({"name": name, "value": value})
    if not result:
        raise SessionRefreshError("authenticated cookie jar is empty")
    return result


def _session_expiry(service: Any) -> int | None:
    """Earliest expiry of the X-APPLE-WEBAUTH cookies, the ones Apple checks."""
    expiries = [
        cookie.expires
        for cookie in getattr(getattr(service, "session", None), "cookies", None) or []
        if str(getattr(cookie, "name", "")).startswith("X-APPLE-WEBAUTH")
        and isinstance(getattr(cookie, "expires", None), int)
    ]
    return min(expiries) if expiries else None


def _fresh_auth(service: Any) -> tuple[str, dict[str, Any], list[dict[str, str]]]:
    data = getattr(service, "data", None)
    if not isinstance(data, dict) or not isinstance(data.get("dsInfo"), dict):
        raise SessionRefreshError("existing iCloud auth cookies are invalid or require reauthentication")
    try:
        if bool(getattr(service, "requires_2fa")) or bool(getattr(service, "requires_2sa")):
            raise SessionRefreshError("existing iCloud auth session requires 2FA")
    except SessionRefreshError:
        raise
    except Exception as exc:
        raise SessionRefreshError("existing iCloud auth cookies are invalid or require reauthentication") from exc
    dsid = _normalize_dsid(data["dsInfo"].get("dsid"))
    webservices = data.get("webservices")
    urls = {
        "photosupload_url": _fresh_url(webservices, "photosupload"),
        "ckdatabasews_url": _fresh_url(webservices, "ckdatabasews"),
    }
    return dsid, urls, _fresh_cookies(service)


def _safe_query(existing: dict[str, Any], fresh_dsid: str) -> list[dict[str, str]]:
    query = existing.get("cloudkit_query_params")
    if not isinstance(query, list) or not query:
        raise SessionRefreshError("delete query parameters are missing")
    result: list[dict[str, str]] = []
    for item in query:
        if not isinstance(item, dict):
            raise SessionRefreshError("delete query parameter shape is invalid")
        name = item.get("name")
        value = item.get("value")
        if not isinstance(name, str) or not isinstance(value, str) or name not in SAFE_QUERY_NAMES:
            raise SessionRefreshError("delete query parameters contain an unsafe value")
        if name == "dsid" and value != fresh_dsid:
            raise SessionRefreshError("delete query DSID does not match authenticated account")
        result.append({"name": name, "value": value})
    return result


def prepare_export(existing: dict[str, dict[str, Any]], service: Any) -> dict[str, dict[str, Any]]:
    """Validate all inputs and build both output objects without writing.

    One account session serves every library; each monitor lane binds it to
    its own zone, so there is no per-library session file.
    """

    for kind, key in (("upload", UPLOAD_FILE), ("delete", DELETE_PRODUCTION_FILE)):
        _validate_existing_session(existing[key], kind)
    fresh_dsid, urls, cookies = _fresh_auth(service)
    expires_at = _session_expiry(service)
    for key in SESSION_FILES:
        if _normalize_dsid(existing[key]["dsid"]) != fresh_dsid:
            raise SessionRefreshError("authenticated account DSID does not match an existing optimizer session")

    upload_old = existing[UPLOAD_FILE]
    upload = {
        "cookies": cookies,
        "dsid": fresh_dsid,
        "local_time_zone_id": upload_old["local_time_zone_id"],
        "photosupload_url": urls["photosupload_url"],
        "time_zone_offset_minutes": upload_old["time_zone_offset_minutes"],
    }
    old = existing[DELETE_PRODUCTION_FILE]
    delete: dict[str, Any] = {
        "ckdatabasews_url": urls["ckdatabasews_url"],
        "cloudkit_query_params": _safe_query(old, fresh_dsid),
        "cookies": cookies,
        "database_scope": old["database_scope"],
        "dsid": fresh_dsid,
        "owner_record_name": old["owner_record_name"],
        "zone_name": old["zone_name"],
    }
    for field in ("local_time_zone_id", "time_zone_offset_minutes"):
        if field in old:
            delete[field] = old[field]
    if expires_at is not None:
        upload["expires_at_unix_seconds"] = expires_at
        delete["expires_at_unix_seconds"] = expires_at
    return {UPLOAD_FILE: upload, DELETE_PRODUCTION_FILE: delete}


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _backup(paths: list[Path], directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path in paths:
        destination = directory / path.name
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)


def _build_service(cookie_directory: Path, apple_id: str, service_factory: Callable[..., Any] | None = None) -> Any:
    if service_factory is None:
        try:
            from pyicloud_ipd import PyiCloudService
        except Exception as exc:
            raise SessionRefreshError("installed pyicloud_ipd API is unavailable") from exc
        service_factory = PyiCloudService
    try:
        return service_factory(
            "com",
            apple_id,
            lambda: None,
            cookie_directory=str(cookie_directory),
            verify=True,
            http_timeout=30.0,
        )
    except Exception as exc:
        raise SessionRefreshError("existing iCloud auth cookies are invalid or require reauthentication") from exc


def run(args: argparse.Namespace, service_factory: Callable[..., Any] | None = None) -> int:
    session_dir = Path(args.session_dir).expanduser()
    paths = [session_dir / name for name in SESSION_FILES]
    before = _file_proof(paths)
    try:
        existing = {path.name: _read_json(path)[0] for path in paths}
        service = _build_service(Path(args.cookie_directory).expanduser(), args.apple_id, service_factory)
        outputs = prepare_export(existing, service)
        for path in paths:
            payload = _json_bytes(outputs[path.name])
            if len(payload) > 2 * 1024 * 1024:
                raise SessionRefreshError("generated session payload is unexpectedly large")
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup_dir = session_dir / "refresh-backups" / timestamp
        _backup(paths, backup_dir)
        old_bytes = {path: path.read_bytes() for path in paths}
        try:
            for path in paths:
                _atomic_write(path, _json_bytes(outputs[path.name]))
                if stat.S_IMODE(path.stat().st_mode) != 0o600:
                    raise SessionRefreshError("generated session file mode is not 0600")
                json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            for path, payload in old_bytes.items():
                try:
                    _atomic_write(path, payload)
                except Exception:
                    pass
            raise _redacted_error(exc)
        after = _file_proof(paths)
        print(json.dumps({"status": "updated", "backup": str(backup_dir), "files": after}, sort_keys=True))
        return 0
    except Exception as exc:
        error = _redacted_error(exc)
        after = _file_proof(paths)
        unchanged = all(item.get("sha256") == old.get("sha256") for item, old in zip(after, before))
        print(json.dumps({"status": "blocked", "reason": str(error), "unchanged": unchanged, "files": after}, sort_keys=True), file=sys.stderr)
        return 2


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apple-id", default=APPLE_ID)
    parser.add_argument("--cookie-directory", type=Path, default=DEFAULT_COOKIE_DIRECTORY)
    parser.add_argument("--session-dir", type=Path, default=DEFAULT_SESSION_DIRECTORY)
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
