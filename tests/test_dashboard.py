import json
import importlib.util
import os
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


_MODULE_PATH = Path(__file__).resolve().parents[1] / "packaging" / "dashboard" / "icloudpd_dashboard.py"
_SPEC = importlib.util.spec_from_file_location("icloudpd_dashboard", _MODULE_PATH)
assert _SPEC and _SPEC.loader
dashboard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(dashboard)


class DashboardSnapshotTests(unittest.TestCase):
    def write_json(self, root: Path, name: str, value: object) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_manifest_metrics_keep_exact_space_saved_and_proof_counts_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.write_json(root, "manifest.json", {"records": [
                {"state": "deleted", "updated_at": "2026-11-03T00:00:00Z", "proofs": {
                    "nas": {"size_bytes": 100}, "heic": {"size_bytes": 20},
                    "icloudpd_local_mirror": {"size_bytes": 20}, "upload": {},
                }},
                {"state": "needs_review", "proofs": {"nas": {"size_bytes": 80}}},
                {"state": "conversion_verified", "proofs": {"nas": {"size_bytes": 50}}},
            ]})
            config = self.write_json(root, "monitor.json", {
                "manifest_path": str(manifest), "stats_path": str(root / "stats.json"),
                "smb_expected_mount_root": str(root / "missing-mount"), "auto_delete": False,
            })
            args = Namespace(config=str(config), shared_config=None, audit=str(root / "audit.json"),
                             days_remaining=str(root / "DAYS_REMAINING"), monitor_label="missing-test",
                             shared_monitor_label="missing-shared", stuck_age_seconds=3600,
                             docker_bin="/definitely/missing/docker", docker_context="test", container_name="icloudpd")
            snapshot = dashboard.DashboardState(args).snapshot()
            metrics = snapshot["lanes"][0]["metrics"]
            self.assertEqual(metrics["total_records"], 3)
            self.assertEqual(metrics["nas_proof_records"], 3)
            self.assertEqual(metrics["uploaded_replacements"], 1)
            self.assertEqual(metrics["deleted_originals"], 1)
            self.assertEqual(metrics["space_saved"]["status"], "exact")
            self.assertEqual(metrics["space_saved"]["bytes"], 80)
            self.assertEqual(metrics["needs_review_records"], 1)
            self.assertEqual(metrics["pending_records"], 1)
            self.assertEqual(snapshot["lanes"][0]["deletion"]["status"], "paused")

    def test_blocked_mount_audit_does_not_turn_absence_into_missing_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = self.write_json(root, "deleted-nas-audit.json", {
                "schema_version": 1, "status": "blocked_mount_missing",
                "manifests": [{"deleted_records": 2618}], "records": [],
                "progress": {"total": 0, "verified": 0, "issues": 0},
                "final": {"deleted": 0, "delete_review": 0, "verified": 0, "issues": 0},
            })
            result = dashboard._audit_snapshot(audit, known_deleted=2618, known_delete_review=1)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["live_hash_verification"]["count"], 0)
            self.assertEqual(result["unverified"]["count"], 2618)
            self.assertEqual(result["unverified_delete_review"]["count"], 1)
            self.assertEqual(result["unverified_total"]["count"], 2619)
            self.assertEqual(result["progress"]["total"], 2619)
            self.assertEqual(result["recorded_deleted"]["count"], 2618)
            self.assertIn("unverified", result["recovery_statement"])

    def test_completed_audit_uses_deleted_and_review_counts_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = self.write_json(root, "deleted-nas-audit.json", {
                "schema_version": 1, "status": "complete_with_issues",
                "verifier_host": "laptop", "nas_source": "//zeus._smb._tcp.local/home",
                "manifests": [], "records": [],
                "progress": {"total": 5, "completed": 5, "verified": 3, "issues": 2},
                "counts": {"deleted": 4, "delete_review": 1, "verified": 3, "issues": 2},
            })
            result = dashboard._audit_snapshot(audit)
            self.assertEqual(result["recorded_deleted"]["count"], 4)
            self.assertEqual(result["recorded_delete_review"]["count"], 1)
            self.assertEqual(result["live_hash_verification"]["count"], 3)
            self.assertEqual(result["unverified"]["count"], 2)

    def test_running_audit_counts_unprocessed_records_as_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = self.write_json(root, "deleted-nas-audit.json", {
                "schema_version": 1, "status": "running", "manifests": [], "records": [],
                "progress": {"total": 5, "completed": 2, "verified": 2, "issues": 0},
                "counts": {},
            })
            result = dashboard._audit_snapshot(audit)
            self.assertEqual(result["live_hash_verification"]["count"], 2)
            self.assertEqual(result["unverified"]["count"], 3)

    def test_completed_audit_exposes_progress_issue_counts_and_safe_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = self.write_json(root, "deleted-nas-audit.json", {
                "schema_version": 1, "status": "complete_with_issues",
                "verifier_host": "laptop", "nas_source": "//zeus._smb._tcp.local/home",
                "progress": {
                    "total": 3, "completed": 3, "verified": 1,
                    "bytes_hashed": 2048, "elapsed_seconds": 4,
                    "bytes_per_second": 512, "eta_seconds": 99,
                },
                "counts": {"deleted": 2, "delete_review": 1, "verified": 1, "issues": 2},
                "records": [
                    {"library": "main", "cohort": "deleted", "asset_id": "asset-missing",
                     "canonical_path": "/private/session/secret/DCIM/missing.heic",
                     "status": "missing", "reason": "nas_unavailable"},
                    {"library": "main", "cohort": "deleted", "asset_id": "asset-hash",
                     "canonical_path": "/private/session/secret/DCIM/hash.heic",
                     "status": "hash_mismatch", "reason": "sha256_mismatch"},
                    {"library": "shared", "cohort": "delete_review", "asset_id": "asset-ok",
                     "canonical_path": "/private/session/secret/DCIM/ok.heic", "status": "verified"},
                ],
            })
            result = dashboard._audit_snapshot(audit)
            self.assertEqual(result["progress"]["completed"], 3)
            self.assertEqual(result["progress"]["total"], 3)
            self.assertEqual(result["progress"]["bytes_per_second"], 512.0)
            self.assertEqual(result["progress"]["eta_seconds"], 99.0)
            self.assertFalse(result["progress"]["stale"])
            self.assertEqual(result["issue_counts"], {"missing": 1, "hash_mismatch": 1})
            self.assertEqual(result["reason_counts"], {"nas_unavailable": 1, "sha256_mismatch": 1})
            self.assertEqual(result["missing"]["count"], 1)
            self.assertEqual(result["unverified"]["count"], 2)
            self.assertEqual(result["unverified_delete_review"]["count"], 0)
            self.assertEqual(result["unverified_total"]["count"], 2)
            self.assertEqual(result["verification_source"]["verifier_host"], "laptop")
            self.assertEqual(result["verification_source"]["nas_source"], "//zeus._smb._tcp.local/home")
            self.assertEqual([row["filename"] for row in result["issue_examples"]], ["missing.heic", "hash.heic"])
            self.assertNotIn("/private", json.dumps(result))
            self.assertIn("asset-missing", json.dumps(result))

    def test_running_audit_with_stale_file_withholds_eta(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = self.write_json(root, "deleted-nas-audit.json", {
                "schema_version": 1, "status": "running",
                "progress": {
                    "total": 4, "completed": 1, "verified": 1,
                    "bytes_hashed": 512, "bytes_per_second": 128, "eta_seconds": 60,
                },
                "records": [],
            })
            stale = time.time() - dashboard.AUDIT_PROGRESS_STALE_SECONDS - 1
            os.utime(audit, (stale, stale))
            result = dashboard._audit_snapshot(audit)
            self.assertTrue(result["progress"]["stale"])
            self.assertIsNone(result["progress"]["eta_seconds"])
            self.assertEqual(result["progress"]["total"], 4)

    def test_bind_rejects_public_and_wildcard_addresses(self):
        with self.assertRaises(SystemExit):
            dashboard._validate_bind("0.0.0.0")
        with self.assertRaises(SystemExit):
            dashboard._validate_bind("192.168.1.10")
        dashboard._validate_bind("100.112.55.61")
        dashboard._validate_bind("127.0.0.1")

    def test_timestamp_accepts_numeric_unix_seconds_with_z_suffix(self):
        self.assertAlmostEqual(
            dashboard._timestamp("1787299139.353615000Z"),
            1787299139.353615,
        )

    def test_container_health_reports_exited_state_without_restart(self):
        with mock.patch.object(
            dashboard,
            "_docker_container_observation",
            return_value={"state": "exited", "health": None, "exit_code": 1},
        ):
            health = dashboard._container_health("/usr/local/bin/docker", "desktop-linux", "icloudpd")
        self.assertEqual(health["status"], "exited")
        self.assertIn("exit code 1", health["detail"])

    def test_container_health_reports_unhealthy_state(self):
        with mock.patch.object(
            dashboard,
            "_docker_container_observation",
            return_value={"state": "running", "health": "unhealthy"},
        ):
            health = dashboard._container_health("/usr/local/bin/docker", "desktop-linux", "icloudpd")
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["label"], "Container unhealthy")


if __name__ == "__main__":
    unittest.main()
