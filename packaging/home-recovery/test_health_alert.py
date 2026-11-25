import importlib.util
import json
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("health_alert.py")
SPEC = importlib.util.spec_from_file_location("health_alert", MODULE_PATH)
assert SPEC and SPEC.loader
HEALTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HEALTH)


class HealthAlertTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.mount = root / "mount"
        self.mount.mkdir()
        self.manifest = root / "manifest.json"
        old = time.time() - 3 * 24 * 60 * 60
        self.manifest.write_text(json.dumps({"records": [{"asset_id": "a", "state": "no_action", "updated_at": str(old) + "Z", "proofs": {"nas": {"sha256": "0" * 64}}}]}))
        self.monitor = root / "monitor.json"
        self.monitor.write_text(json.dumps({"manifest_path": str(self.manifest)}))
        self.days = root / "DAYS_REMAINING"
        self.days.write_text("10\n")
        self.state = root / "container.state"
        self.state.write_text("running\n")
        self.args = Namespace(
            mount=self.mount,
            container_label="runtime.test",
            container_state=self.state,
            docker_bin="/usr/local/bin/docker",
            docker_context="desktop-linux",
            container_name="icloudpd",
            days=self.days,
            cookie_warning_days=3,
            no_progress_seconds=24 * 60 * 60,
            monitor_config=(("main", self.monitor),),
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_progress_uses_success_state_and_ignores_failure_timestamp_churn(self):
        with mock.patch.object(HEALTH.os.path, "ismount", return_value=True), mock.patch.object(
            HEALTH, "_launchd_runtime_observation", return_value={"label": "runtime.test", "state": "running", "active_count": 1}
        ), mock.patch.object(
            HEALTH, "_docker_container_observation", return_value={"state": "running", "health": "healthy"}
        ):
            issues, observations, progress = HEALTH._issues(self.args, {})
        self.assertIn("no_progress_main", {item["id"] for item in issues})
        self.assertEqual(observations["progress"][0]["status"], "stale")
        self.manifest.write_text(json.dumps({"records": [{"asset_id": "a", "state": "no_action", "updated_at": "newerZ", "failures": [{"recorded_at": "new"}], "proofs": {"nas": {"sha256": "0" * 64}}}]}))
        with mock.patch.object(HEALTH.os.path, "ismount", return_value=True), mock.patch.object(
            HEALTH, "_launchd_runtime_observation", return_value={"label": "runtime.test", "state": "running", "active_count": 1}
        ), mock.patch.object(
            HEALTH, "_docker_container_observation", return_value={"state": "running", "health": "healthy"}
        ):
            issues_after, _, _ = HEALTH._issues(self.args, {"progress": progress})
        self.assertIn("no_progress_main", {item["id"] for item in issues_after})

    def test_unavailable_docker_state_is_explicitly_unavailable(self):
        self.state.unlink()
        with mock.patch.object(HEALTH.os.path, "ismount", return_value=True), mock.patch.object(
            HEALTH, "_launchd_runtime_observation", return_value={"label": "runtime.test", "state": "running", "active_count": 1}
        ), mock.patch.object(
            HEALTH, "_docker_container_observation", return_value={"state": "unavailable", "reason": "docker_daemon_unavailable"}
        ):
            issues, observations, _ = HEALTH._issues(self.args, {})
        self.assertIn("container_runtime_not_running", {item["id"] for item in issues})
        self.assertEqual(observations["container"]["container_state"], "unavailable")

    def test_exited_docker_container_is_alerted_even_when_colima_launchd_is_loaded(self):
        with mock.patch.object(HEALTH.os.path, "ismount", return_value=True), mock.patch.object(
            HEALTH, "_launchd_runtime_observation", return_value={"label": "runtime.test", "state": "running", "active_count": 1}
        ), mock.patch.object(
            HEALTH, "_docker_container_observation", return_value={"state": "exited", "health": None, "exit_code": 1}
        ):
            issues, observations, _ = HEALTH._issues(self.args, {})
        self.assertIn("container_exited", {item["id"] for item in issues})
        self.assertEqual(observations["container"]["container_state"], "exited")

    def test_docker_inspection_uses_only_read_only_inspect_command(self):
        class Result:
            returncode = 0
            stdout = '{"Status":"running","Health":{"Status":"healthy"},"ExitCode":0}'
            stderr = ""

        with mock.patch.object(HEALTH.subprocess, "run", return_value=Result()) as run:
            observation = HEALTH._docker_container_observation("/usr/local/bin/docker", "desktop-linux", "icloudpd")
        self.assertEqual(observation["state"], "running")
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["/usr/local/bin/docker", "--context", "desktop-linux", "container"])
        self.assertEqual(command[4], "inspect")
        self.assertNotIn("start", command)
        self.assertNotIn("stop", command)

    def test_telegram_false_ok_is_failure(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"ok": false}'

        with mock.patch.object(HEALTH.urllib.request, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(RuntimeError, "rejected"):
                HEALTH._send(("https://example.invalid/botTOKEN/sendMessage", "CHAT"), "test")


if __name__ == "__main__":
    unittest.main()
