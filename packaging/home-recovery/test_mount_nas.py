import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("mount_nas.py")
SPEC = importlib.util.spec_from_file_location("mount_nas", MODULE_PATH)
assert SPEC and SPEC.loader
MOUNT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOUNT)


class MountNasTests(unittest.TestCase):
    def test_parse_defaults_to_bounded_mount_timeout(self):
        args = MOUNT.parse_args([])
        self.assertEqual(args.mount_timeout_seconds, 15)

    def test_legacy_timeout_flag_controls_same_call(self):
        args = MOUNT.parse_args(["--open-timeout-seconds", "3"])
        self.assertEqual(args.mount_timeout_seconds, 3)

    def test_expected_source_requires_host_and_share(self):
        mount = Path("/Volumes/home")
        with mock.patch.object(MOUNT.os.path, "ismount", return_value=True), mock.patch.object(
            MOUNT, "_mount_source", return_value="//zeus._smb._tcp.local/home on /Volumes/home"
        ):
            self.assertEqual(MOUNT._is_expected_mount(mount), (True, "//zeus._smb._tcp.local/home on /Volumes/home"))
        with mock.patch.object(MOUNT.os.path, "ismount", return_value=True), mock.patch.object(
            MOUNT, "_mount_source", return_value="//other.example/home"
        ):
            self.assertEqual(MOUNT._is_expected_mount(mount), (False, "//other.example/home"))

    def test_timeout_receipt_is_bounded_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "mount-health.json"
            args = Namespace(
                mount=Path("/Volumes/home"),
                url=MOUNT.DEFAULT_URL,
                output=output,
                mount_timeout_seconds=1,
                wait_seconds=0,
            )
            with (
                mock.patch.object(MOUNT, "_is_expected_mount", return_value=(False, None)),
                mock.patch.object(MOUNT.os.path, "ismount", return_value=False),
                mock.patch.object(MOUNT.subprocess, "run", side_effect=MOUNT.subprocess.TimeoutExpired("osascript", 1)),
            ):
                rc = MOUNT.run(args)
            receipt = json.loads(output.read_text())
            self.assertEqual(rc, 1)
            self.assertEqual(receipt["status"], "mount_timed_out")
            self.assertNotIn("password", receipt)


if __name__ == "__main__":
    unittest.main()
