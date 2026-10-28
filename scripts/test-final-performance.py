#!/usr/bin/env python3
"""Portable contract checks; no proxy, network, Go or service is launched."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("final_performance", Path(__file__).with_name("acceptance-final-performance.py"))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class FinalPerformanceContract(unittest.TestCase):
    def test_unknown_or_duplicate_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for raw in (b'{"version":1,"version":2}', b'{"v":NaN}'):
                path.write_bytes(raw)
                with self.assertRaises((module.AcceptanceFailure, ValueError)):
                    module.strict_json(path)
            path.write_text(json.dumps({"version": 999, "source": "qingnode-automatic-probe"}))
            with self.assertRaises(module.AcceptanceFailure):
                module.summarize_report(path)

    def test_binary_hash_and_relative_path_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"no execution occurs")
            self.assertEqual(path, module.binary(path, module.sha(path)))
            for invalid, digest in (("relative", "a" * 64), (path, "b" * 64), (path, "A" * 64)):
                with self.assertRaises(module.AcceptanceFailure):
                    module.binary(invalid, digest)

    def test_skip_or_missing_target_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.jsonl"
            for events in ([], [{"Test": "exact", "Action": "skip"}], [{"Test": "other", "Action": "pass"}],
                           [{"Test": "exact", "Action": "pass"}, {"Action": "fail", "Package": "x"}]):
                path.write_text("\n".join(json.dumps(event) for event in events))
                with self.assertRaises(module.AcceptanceFailure):
                    module.inspect_test_log(path, "exact")
            events = [{"Test": "exact", "Action": "pass"}, {"Test": "exact/unsupported", "Action": "skip"}]
            path.write_text("\n".join(json.dumps(event) for event in events))
            self.assertEqual(1, len(module.inspect_test_log(path, "exact")))

    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            module.write_new(path, {"source": "original"})
            with self.assertRaises(FileExistsError):
                module.write_new(path, {"source": "replacement"})
            self.assertEqual({"source": "original"}, json.loads(path.read_bytes()))

    def test_report_projection_preserves_unknown_and_does_not_copy_extras(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            value = {"version": 1, "source": "qingnode-automatic-probe", "status": "completed",
                     "conditions": {"path": "client-proxy", "limits": {"max_payload_bytes": 1048576}},
                     "connection": {"status": "unknown", "elapsed_ms": None}, "statistics": {}, "samples": [],
                     "private_password": "not-copied"}
            path.write_text(json.dumps(value))
            result = module.summarize_report(path)
            self.assertEqual(None, result["connection"]["elapsed_ms"])
            self.assertNotIn("private_password", result)
            value["conditions"]["path"] = "server-outbound"
            path.write_text(json.dumps(value))
            with self.assertRaises(module.AcceptanceFailure):
                module.summarize_report(path)

    def test_payload_and_sample_bounds_are_not_waived(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for value in (3 << 20, None):
                report = {"version": 1, "source": "qingnode-automatic-probe", "conditions": {"path": "client-proxy", "limits": {}}}
                if value is not None:
                    report["conditions"]["limits"]["max_payload_bytes"] = value
                path.write_text(json.dumps(report))
                with self.assertRaises(module.AcceptanceFailure):
                    module.summarize_report(path)

    def test_command_timeout_hides_private_exception_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(module.subprocess, "run", side_effect=subprocess.TimeoutExpired("private-password", 1)):
                with self.assertRaises(module.AcceptanceFailure) as failure:
                    module.execute_case(Path("/go"), "fixture", "./internal/probe", "Expected", {}, Path(directory), 1)
            self.assertNotIn("private-password", str(failure.exception))

    def test_no_disposable_intent_cannot_start_subprocess(self):
        args = type("Args", (), {"disposable": False})()
        with mock.patch.object(module.subprocess, "run") as process:
            with self.assertRaises(module.AcceptanceFailure):
                module.run(args)
        process.assert_not_called()

    def test_netem_requires_both_root_and_explicit_vm_marker(self):
        args = type("Args", (), {"disposable": True, "with_netem": True})()
        with mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(module.os, "geteuid", return_value=0, create=True), mock.patch.dict(module.os.environ, {}, clear=True):
            with self.assertRaises(module.AcceptanceFailure):
                module.run(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
