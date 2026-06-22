#!/usr/bin/env python3
"""Upload one verified HEIC to iCloud Photos using pyicloud."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _error(kind: str, message: str) -> int:
    print(json.dumps({"error": kind, "message": message}), file=sys.stderr)
    return 1


def _asset_value(asset: Any, *names: str) -> str | None:
    for name in names:
        value = getattr(asset, name, None)
        if isinstance(value, str) and value.strip():
            return value
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Upload one file to iCloud Photos")
    parser.add_argument("--apple-id", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--album")
    parser.add_argument("--cookie-directory")
    parser.add_argument("--accept-terms", action="store_true")
    args = parser.parse_args(argv)

    upload_path = Path(args.file)
    if not upload_path.is_file():
        return _error("missing_file", f"File does not exist: {upload_path}")

    try:
        from pyicloud import PyiCloudService
        from pyicloud.exceptions import (
            PyiCloud2SARequiredException,
            PyiCloud2FARequiredException,
            PyiCloudAcceptTermsException,
            PyiCloudAPIResponseException,
            PyiCloudAuthRequiredException,
            PyiCloudFailedLoginException,
            PyiCloudNoStoredPasswordAvailableException,
            PyiCloudPasswordException,
            PyiCloudServiceNotActivatedException,
            PyiCloudServiceUnavailable,
        )
    except Exception as exc:
        return _error("missing_pyicloud", f"Could not import pyicloud: {exc}")

    try:
        api = PyiCloudService(
            args.apple_id,
            cookie_directory=args.cookie_directory,
            accept_terms=args.accept_terms,
        )
        if api.requires_2fa or api.requires_2sa:
            return _error("mfa_required", "iCloud session requires MFA before upload")

        asset = api.photos.upload(str(upload_path), album=args.album)
        if asset is None:
            return _error("upload_empty", "pyicloud did not return an uploaded asset")

        asset_id = _asset_value(asset, "asset_id", "id")
        if asset_id is None:
            return _error("missing_asset_id", "Uploaded asset did not expose an asset id")

        payload = {
            "asset_id": asset_id,
            "filename": _asset_value(asset, "filename"),
            "master_id": _asset_value(asset, "master_id"),
        }
        print(json.dumps(payload, sort_keys=True))
        return 0
    except PyiCloud2FARequiredException:
        return _error("mfa_required", "iCloud session requires MFA before upload")
    except PyiCloud2SARequiredException:
        return _error("mfa_required", "iCloud session requires MFA before upload")
    except PyiCloudAuthRequiredException as exc:
        return _error("auth_required", str(exc))
    except PyiCloudNoStoredPasswordAvailableException as exc:
        return _error("auth_required", str(exc))
    except PyiCloudPasswordException as exc:
        return _error("password_required", str(exc))
    except PyiCloudAcceptTermsException as exc:
        return _error("terms_required", str(exc))
    except PyiCloudFailedLoginException as exc:
        return _error("login_failed", str(exc))
    except PyiCloudServiceNotActivatedException as exc:
        return _error("photos_unavailable", str(exc))
    except PyiCloudServiceUnavailable as exc:
        return _error("service_unavailable", str(exc))
    except PyiCloudAPIResponseException as exc:
        return _error("api_error", str(exc))
    except Exception as exc:
        return _error("unexpected", str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
