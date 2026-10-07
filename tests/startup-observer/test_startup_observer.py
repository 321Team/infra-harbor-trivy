import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "scripts/verify/observe-harbor-startup.py"
spec = importlib.util.spec_from_file_location("observer", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def rows():
    return [{"id": "%064x" % i, "name": "/" + name, "status": "running",
             "health": "healthy", "started_at": "2026-10-07T14:21:59.123456789Z", "exit_code": 0}
            for i, name in enumerate(m.NAMES, 1)]


def frame(index=0):
    return {"kind": "sample", "index": index, "observed_at_kst": "2026-10-08T03:00:00+09:00",
            "docker": {"rc": 0, "begin_ns": index * 10, "end_ns": index * 10 + 1, "value": rows()},
            "listener": {"rc": 0, "begin_ns": index * 10 + 2, "end_ns": index * 10 + 3, "value": True}}


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "capture.jsonl"

    def capture(self, frames=None):
        frames = [frame()] if frames is None else frames
        with patch.object(m.socket, "gethostname", return_value="harbor01"), \
             patch.object(m, "sample", side_effect=frames), patch.object(m.time, "sleep"):
            self.rc = m.collect(self.path, len(frames), 5, "harbor01")
        return m.summarize(self.path)

    def mutate(self, func):
        records = [json.loads(line) for line in self.path.read_text().splitlines()]
        func(records)
        self.path.write_text("".join(json.dumps(r) + "\n" for r in records))

    def test_success_is_never_autostart_or_ingestion_pass(self):
        result = self.capture()
        self.assertEqual(self.rc, 0)
        self.assertEqual(result["logger_healthy_and_ipv4_listener_sample_indices"], [0])
        self.assertEqual(result["AUTOSTART"], "NOT_EVALUATED")
        self.assertEqual(result["SYSLOG_INGESTION"], "NOT_TESTED")
        self.assertEqual(result["AC04"], "NOT_EVALUATED")

    def test_healthy_logger_with_exited_apps(self):
        f = frame()
        for r in f["docker"]["value"][1:]:
            r.update(status="exited", health=None, exit_code=128)
        result = self.capture([f])
        self.assertEqual(result["all_containers_running_sample_indices"], [])
        self.assertEqual(result["logger_healthy_and_ipv4_listener_sample_indices"], [0])

    def test_running_does_not_mean_healthy(self):
        f = frame()
        f["docker"]["value"][0]["health"] = "starting"
        result = self.capture([f])
        self.assertEqual(result["logger_healthy_and_ipv4_listener_sample_indices"], [])
        self.assertEqual(result["all_containers_running_sample_indices"], [0])

    def test_missing_listener(self):
        f = frame()
        f["listener"]["value"] = False
        self.assertEqual(self.capture([f])["logger_healthy_and_ipv4_listener_sample_indices"], [])

    def test_recreated_container_detected(self):
        second = frame(1)
        second["docker"]["value"][0]["id"] = "f" * 64
        self.assertTrue(self.capture([frame(), second])["identity_change_observed"])

    def test_daemon_unavailable_then_recovery_keeps_error(self):
        failed = frame()
        failed["docker"].pop("value")
        failed["docker"].update(rc=1, error="COMMAND_FAILED")
        result = self.capture([failed, frame(1)])
        self.assertEqual(self.rc, 2)
        self.assertEqual(result["capture"], "COMPLETE_WITH_ERRORS")
        self.assertEqual(result["error_sample_indices"], [0])
        self.assertEqual(result["AUTOSTART"], "NOT_EVALUATED")

    def test_exclusive_no_overwrite(self):
        self.capture()
        original = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            self.capture()
        self.assertEqual(self.path.read_bytes(), original)

    def test_interruption_no_footer(self):
        with patch.object(m.socket, "gethostname", return_value="harbor01"), \
             patch.object(m, "sample", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            m.collect(self.path, 1, 5, "harbor01")
        with self.assertRaises(ValueError):
            m.summarize(self.path)

    def test_host_mismatch_before_file_or_commands(self):
        with patch.object(m.socket, "gethostname", return_value="other"), patch.object(m, "sample") as s:
            with self.assertRaises(ValueError):
                m.collect(self.path, 1, 5, "harbor01")
            s.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_bounds_before_file(self):
        for count, interval in [(0, 5), (62, 5), (1, 0), (1, 11)]:
            with self.assertRaises(ValueError):
                m.collect(self.path, count, interval, "harbor01")
        self.assertFalse(self.path.exists())

    def test_selected_docker_fields_only(self):
        text = "\n".join(json.dumps(r) for r in rows())
        self.assertEqual(len(m.containers(text)), 10)
        self.assertNotIn(".Config", m.FORMAT)
        self.assertNotIn(".State.Health.Log", m.FORMAT)
        self.assertNotIn(".State.Error", m.FORMAT)

    def test_invalid_docker_output_not_echoed(self):
        secret = "SYNTHETIC_SECRET_CANARY"
        cases = [secret, json.dumps(rows()[0]), "\n".join(json.dumps(dict(r, secret=secret)) for r in rows())]
        for text in cases:
            run = lambda *a, **k: subprocess.CompletedProcess(a, 0, text)
            result = m.probe(m.DOCKER, m.containers, run)
            self.assertEqual(result["error"], "INVALID_SELECTED_FIELDS")
            self.assertNotIn(secret, json.dumps(result))

    def test_nonzero_does_not_parse_or_echo(self):
        def run(*a, **k):
            return subprocess.CompletedProcess(a, 1, "SYNTHETIC_SECRET_CANARY")
        result = m.probe(m.DOCKER, m.containers, run)
        self.assertEqual(result["rc"], 1)
        self.assertNotIn("value", result)
        self.assertNotIn("CANARY", json.dumps(result))

    def test_timeout_and_missing_binary(self):
        for error, expected in [(subprocess.TimeoutExpired("docker", 4), "TIMEOUT"),
                                (FileNotFoundError(), "COMMAND_UNAVAILABLE")]:
            with patch.object(m.subprocess, "run", side_effect=error) as run:
                self.assertEqual(m.probe(m.DOCKER, m.containers, run)["error"], expected)

    def test_listener_exact_ipv4_not_wildcard(self):
        self.assertTrue(m.listener("LISTEN 0 4096 127.0.0.1:1514 0.0.0.0:*\n"))
        self.assertFalse(m.listener(""))
        self.assertFalse(m.listener("LISTEN 0 4096 0.0.0.0:1514 0.0.0.0:*\n"))
        with self.assertRaises(ValueError):
            m.listener("SYNTHETIC_SECRET_CANARY")

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            m.decode('{"id":1,"id":2}')

    def test_missing_container_or_duplicate_identity_rejected(self):
        for rs in [rows()[:-1], [rows()[0]] * 10]:
            with self.assertRaises(ValueError):
                m.containers("\n".join(json.dumps(r) for r in rs))

    def test_trace_tampering_rejected(self):
        mutations = [lambda r: r.pop(),
                     lambda r: r[1].update(index=3),
                     lambda r: r[-1].update(samples_with_errors=1),
                     lambda r: r[1]["docker"].update(end_ns=-1),
                     lambda r: r[0].update(commands={}),
                     lambda r: r[1]["docker"].update(rc=1),
                     lambda r: r[1]["listener"].update(value="true"),
                     lambda r: r[1]["docker"].update(error="COMMAND_FAILED")]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                if self.path.exists():
                    self.path.unlink()
                self.capture()
                self.mutate(mutate)
                with self.assertRaises(ValueError):
                    m.summarize(self.path)

    def test_inspect_and_listener_are_only_host_commands(self):
        def fake(command, **kwargs):
            self.assertEqual(kwargs["timeout"], 4)
            self.assertFalse(kwargs.get("shell", False))
            self.assertEqual(kwargs["env"], m.COMMAND_ENV)
            self.assertNotIn("DOCKER_HOST", kwargs["env"])
            return subprocess.CompletedProcess(command, 0,
                   "\n".join(json.dumps(r) for r in rows()) if command == m.DOCKER else "")
        original_probe = m.probe
        with patch.object(m, "probe", side_effect=lambda c, p: original_probe(c, p, fake)) as probe:
            m.sample(0)
            self.assertEqual([call.args[0] for call in probe.call_args_list], [m.DOCKER, m.LISTENER])


if __name__ == "__main__":
    unittest.main()
