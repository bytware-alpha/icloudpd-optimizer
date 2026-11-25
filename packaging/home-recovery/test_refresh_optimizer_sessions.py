import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("refresh_optimizer_sessions.py")
SPEC = importlib.util.spec_from_file_location("refresh_optimizer_sessions", MODULE_PATH)
assert SPEC and SPEC.loader
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


class Cookie:
    def __init__(self, name, value, expires=None):
        self.name = name
        self.value = value
        self.expires = expires


class FakeService:
    requires_2fa = False
    requires_2sa = False

    def __init__(self, dsid="123"):
        self.data = {
            "dsInfo": {"dsid": dsid},
            "webservices": {
                "photosupload": {"url": "https://fresh-photosupload.icloud.com"},
                "ckdatabasews": {"url": "https://fresh-ckdatabasews.icloud.com"},
            },
        }
        cookies = [
            Cookie("session", "fresh-cookie", 1900000000),
            Cookie("X-APPLE-WEBAUTH-TOKEN", "fresh-token", 1800000000),
            Cookie("X-APPLE-WEBAUTH-USER", "fresh-user", 1810000000),
        ]
        self.session = type("Session", (), {"cookies": cookies})()


def service_factory_for(service):
    def factory(domain, apple_id, password_provider, **kwargs):
        if password_provider() is not None:
            raise AssertionError("exporter supplied a password provider")
        return service

    return factory


class RefreshOptimizerSessionsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.session_dir = self.root / "private-runtime"
        self.session_dir.mkdir()
        self.old_cookie = [{"name": "old", "value": "old-cookie"}]
        self._write_fixtures()

    def tearDown(self):
        self.tempdir.cleanup()

    def _write_fixtures(self, dsid="123", missing_query=False):
        upload = {
            "cookies": self.old_cookie,
            "dsid": dsid,
            "local_time_zone_id": "America/Los_Angeles",
            "photosupload_url": "https://old-photosupload.icloud.com",
            "time_zone_offset_minutes": -420,
        }
        query = [
            {"name": "clientBuildNumber", "value": "build"},
            {"name": "clientMasteringNumber", "value": "master"},
            {"name": "clientId", "value": "client-id"},
            {"name": "dsid", "value": dsid},
            {"name": "remapEnums", "value": "true"},
            {"name": "getCurrentSyncToken", "value": "true"},
        ]
        delete = {
            "ckdatabasews_url": "https://old-ckdatabasews.icloud.com",
            "cloudkit_query_params": [] if missing_query else query,
            "cookies": self.old_cookie,
            "database_scope": "private",
            "dsid": dsid,
            "owner_record_name": "_owner123",
            "zone_name": "PrimarySync",
        }
        for name, value in ((EXPORTER.UPLOAD_FILE, upload), (EXPORTER.DELETE_PRODUCTION_FILE, delete)):
            (self.session_dir / name).write_text(json.dumps(value, indent=2) + "\n")
            os.chmod(self.session_dir / name, 0o600)

    def _args(self):
        return Namespace(
            apple_id="tushartheawesome@icloud.com",
            cookie_directory=self.root / "cookies",
            session_dir=self.session_dir,
        )

    def _hashes(self):
        return {name: hashlib.sha256((self.session_dir / name).read_bytes()).hexdigest() for name in EXPORTER.SESSION_FILES}

    def test_valid_export_preserves_destinations_and_writes_0600(self):
        before = self._hashes()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = EXPORTER.run(self._args(), service_factory_for(FakeService()))
        self.assertEqual(rc, 0)
        self.assertNotEqual(before, self._hashes())
        upload = json.loads((self.session_dir / EXPORTER.UPLOAD_FILE).read_text())
        delete = json.loads((self.session_dir / EXPORTER.DELETE_PRODUCTION_FILE).read_text())
        self.assertEqual(upload["photosupload_url"], "https://fresh-photosupload.icloud.com")
        self.assertEqual(upload["cookies"][0]["value"], "fresh-cookie")
        self.assertEqual(delete["ckdatabasews_url"], "https://fresh-ckdatabasews.icloud.com")
        self.assertEqual(delete["owner_record_name"], "_owner123")
        self.assertEqual(delete["zone_name"], "PrimarySync")
        self.assertEqual(delete["expires_at_unix_seconds"], 1800000000)
        self.assertEqual(upload["expires_at_unix_seconds"], 1800000000)
        self.assertFalse((self.session_dir / "delete-session-shared-production.json").exists())
        for name in EXPORTER.SESSION_FILES:
            self.assertEqual(stat.S_IMODE((self.session_dir / name).stat().st_mode), 0o600)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["status"], "updated")
        self.assertTrue((self.session_dir / "refresh-backups").is_dir())

    def assert_blocked_without_mutation(self, service, expected_fragment):
        before = self._hashes()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = EXPORTER.run(self._args(), service_factory_for(service))
        self.assertEqual(rc, 2)
        self.assertEqual(before, self._hashes())
        self.assertIn(expected_fragment, stderr.getvalue())
        self.assertFalse((self.session_dir / "refresh-backups").exists())

    def test_missing_service_is_blocked_without_mutation(self):
        service = FakeService()
        del service.data["webservices"]["photosupload"]
        self.assert_blocked_without_mutation(service, "blocked")

    def test_account_mismatch_is_blocked_without_mutation(self):
        self.assert_blocked_without_mutation(FakeService(dsid="999"), "blocked")

    def test_invalid_existing_query_is_blocked_without_mutation(self):
        self._write_fixtures(missing_query=True)
        self.assert_blocked_without_mutation(FakeService(), "blocked")


if __name__ == "__main__":
    unittest.main()
