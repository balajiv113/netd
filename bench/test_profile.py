import base64
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

import run


class ProfileCpuTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.proc = mock.Mock()
        self.proc.poll.return_value = None
        self.proc.wait.return_value = -signal.SIGINT
        self.patches = [
            mock.patch.dict(os.environ, {"NETD_PROFILE": "1"}),
            mock.patch.object(run, "W", self.work),
            mock.patch.object(run.time, "sleep"),
            mock.patch.object(run.subprocess, "Popen", return_value=self.proc),
            mock.patch.object(run.subprocess, "run", side_effect=self.report),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        (self.work / "netd-up1.perf.data").write_bytes(b"data")
        self.report_text = "# Samples: 979  of event 'cpu-clock'\n"

    def report(self, command, stdout, **kwargs):
        stdout.write(self.report_text)

    def test_sent_sigint_and_success_are_accepted(self):
        for status in (-signal.SIGINT, 0):
            with self.subTest(status=status):
                self.proc.wait.return_value = status
                with run.profile_cpu("netd", "up1", 123):
                    pass
                self.proc.send_signal.assert_called_with(signal.SIGINT)

    def test_early_exit_is_rejected(self):
        self.proc.poll.side_effect = [None, 0]
        with self.assertRaisesRegex(RuntimeError, "during benchmark"):
            with run.profile_cpu("netd", "up1", 123):
                pass
        self.proc.send_signal.assert_not_called()

    def test_startup_exit_is_rejected(self):
        self.proc.poll.return_value = -signal.SIGINT
        with self.assertRaisesRegex(RuntimeError, "during startup"):
            with run.profile_cpu("netd", "up1", 123):
                pass

    def test_record_failure_is_rejected(self):
        self.proc.wait.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "exited with 1"):
            with run.profile_cpu("netd", "up1", 123):
                pass

    def test_timeout_kills_recorder(self):
        self.proc.wait.side_effect = [subprocess.TimeoutExpired("perf", 15), -signal.SIGKILL]
        with self.assertRaisesRegex(RuntimeError, "did not stop"):
            with run.profile_cpu("netd", "up1", 123):
                pass
        self.proc.kill.assert_called_once()

    def test_missing_data_is_rejected(self):
        (self.work / "netd-up1.perf.data").unlink()
        with self.assertRaisesRegex(RuntimeError, "no data"):
            with run.profile_cpu("netd", "up1", 123):
                pass

    def test_report_without_samples_is_rejected(self):
        self.report_text = "# Samples: 0  of event 'cpu-clock'\n"
        with self.assertRaisesRegex(RuntimeError, "no samples"):
            with run.profile_cpu("netd", "up1", 123):
                pass

    def test_report_failure_is_rejected(self):
        run.subprocess.run.side_effect = subprocess.CalledProcessError(1, "perf")
        with self.assertRaises(subprocess.CalledProcessError):
            with run.profile_cpu("netd", "up1", 123):
                pass


class GuestProfileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.patches = [mock.patch.object(run, "W", self.work), mock.patch.object(run.time, "sleep")]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.guest = mock.Mock()
        self.guest.run.return_value = (0, "# Samples: 42 of event 'cpu-clock'\n", "")
        self.statuses = iter([{"exited": False}, {"exited": False},
                              {"exited": True, "signal": signal.SIGINT,
                               "err-data": base64.b64encode(b"recorded").decode()}])
        self.guest.cmd.side_effect = self.cmd

    def cmd(self, name, args):
        if name == "guest-exec":
            return {"pid": 42}
        if name == "guest-exec-status":
            return next(self.statuses)
        if name == "guest-file-open":
            return 7
        if name == "guest-file-read":
            return {"buf-b64": base64.b64encode(b"data").decode(), "eof": True}
        if name == "guest-file-close":
            return {}
        self.fail(f"unexpected command: {name}")

    def test_guest_sigint_and_data_copy(self):
        with run.profile_guest(self.guest, "netd", "up1", "/perf"):
            pass
        self.assertEqual((self.work / "netd-up1-guest.perf.data").read_bytes(), b"data")
        self.assertEqual((self.work / "netd-up1-guest-perf-record.log").read_bytes(), b"recorded")
        self.guest.run.assert_any_call(["kill", "-INT", "42"])
        self.guest.cmd.assert_any_call("guest-file-close", {"handle": 7})

    def test_guest_early_exit_is_rejected(self):
        self.statuses = iter([{"exited": False}, {"exited": True, "exitcode": 0}])
        with self.assertRaisesRegex(RuntimeError, "during benchmark"):
            with run.profile_guest(self.guest, "netd", "up1", "/perf"):
                pass

    def test_guest_failure_is_rejected(self):
        self.statuses = iter([{"exited": False}, {"exited": False}, {"exited": True, "exitcode": 1}])
        with self.assertRaisesRegex(RuntimeError, "guest perf failed"):
            with run.profile_guest(self.guest, "netd", "up1", "/perf"):
                pass

    def test_guest_empty_report_is_rejected(self):
        self.guest.run.return_value = (0, "# Samples: 0 of event 'cpu-clock'\n", "")
        with self.assertRaisesRegex(RuntimeError, "no samples"):
            with run.profile_guest(self.guest, "netd", "up1", "/perf"):
                pass


if __name__ == "__main__":
    unittest.main()
