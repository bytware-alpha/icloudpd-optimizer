import hashlib
import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("audit_deleted.py")
SPEC = importlib.util.spec_from_file_location("audit_deleted", MODULE_PATH)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class AuditDeletedTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "nas"
        self.root.mkdir()
        self.original = self.root / "Photos" / "iCloud" / "original.dng"
        self.original.parent.mkdir(parents=True)
        self.original.write_bytes(b"full-quality-original")
        self.mount_signature = (1, 2, 3, 4)

    def tearDown(self):
        self.tempdir.cleanup()

    def record(self, expected_hash=None, expected_size=None, path=None):
        target = Path(path or self.original)
        data = target.read_bytes() if target.exists() else self.original.read_bytes()
        return {
            "asset_id": "raw-test",
            "state": "deleted",
            "proofs": {
                "nas": {
                    "canonical_path": str(target),
                    "sha256": expected_hash or hashlib.sha256(data).hexdigest(),
                    "size_bytes": expected_size if expected_size is not None else len(data),
                }
            },
        }

    def test_correct_hash_is_verified(self):
        with mock.patch.object(AUDIT, "_mount_is_stable", return_value=True):
            result = AUDIT._audit_record("main", 0, "deleted", self.record(), self.root, self.mount_signature)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["observed_size_bytes"], len(self.original.read_bytes()))

    def test_hash_mismatch_is_reported(self):
        with mock.patch.object(AUDIT, "_mount_is_stable", return_value=True):
            result = AUDIT._audit_record("main", 0, "deleted", self.record(expected_hash="0" * 64), self.root, self.mount_signature)
        self.assertEqual(result["status"], "hash_mismatch")

    def test_missing_original_is_reported_only_with_stable_mount(self):
        missing = self.root / "Photos" / "iCloud" / "missing.dng"
        with mock.patch.object(AUDIT, "_mount_is_stable", return_value=True):
            result = AUDIT._audit_record("main", 0, "deleted", self.record(path=missing), self.root, self.mount_signature)
        self.assertEqual(result["status"], "missing")

    def test_missing_mount_does_not_classify_records(self):
        output = Path(self.tempdir.name) / "audit.json"
        args = Namespace(
            output=str(output),
            nas_root=str(self.root),
            manifest=(),
            progress_every=1,
            lock=str(Path(self.tempdir.name) / "audit.lock"),
            force=False,
        )
        with mock.patch.object(AUDIT, "_mount_signature", return_value=None):
            rc = AUDIT.run(args)
        receipt = json.loads(output.read_text())
        self.assertEqual(rc, 2)
        self.assertEqual(receipt["status"], "blocked_mount_missing")
        self.assertEqual(receipt["records"], [])

    def test_parallel_workers_preserve_verified_results(self):
        second = self.root / "Photos" / "iCloud" / "second.dng"
        second.write_bytes(b"second-original")
        manifest = Path(self.tempdir.name) / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "records": [
                        self.record(),
                        self.record(path=second),
                    ]
                }
            )
        )
        output = Path(self.tempdir.name) / "parallel-audit.json"
        args = Namespace(
            output=str(output),
            nas_root=str(self.root),
            manifest=(("main", manifest),),
            progress_every=1,
            workers=2,
            verifier_host="test",
            mount_source="//zeus._smb._tcp.local/home",
            lock=str(Path(self.tempdir.name) / "parallel.lock"),
            force=True,
        )
        with mock.patch.object(AUDIT, "_mount_signature", return_value=self.mount_signature), mock.patch.object(
            AUDIT, "_mount_is_stable", return_value=True
        ):
            rc = AUDIT.run(args)
        receipt = json.loads(output.read_text())
        self.assertEqual(rc, 0)
        self.assertEqual(receipt["status"], "complete")
        self.assertEqual(receipt["progress"]["verified"], 2)
        self.assertGreater(receipt["progress"]["expected_bytes"], 0)
        self.assertEqual(receipt["progress"]["eta_method"], "expected_bytes")
        self.assertEqual(receipt["verifier_host"], "test")
        self.assertEqual(receipt["nas_source"], "//zeus._smb._tcp.local/home")


if __name__ == "__main__":
    unittest.main()
