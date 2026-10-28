#!/usr/bin/env python3
"""Portable contract checks only; never run acceptance or host commands."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("final_regression", Path(__file__).with_name("acceptance-final-regression.py"))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class RegressionContract(unittest.TestCase):
    def events(self, directory, values):
        path = Path(directory) / "events.jsonl"
        path.write_text("\n".join(json.dumps(value) for value in values))
        return path

    def test_missing_test_cannot_be_package_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.events(directory, [{"Package": "x", "Action": "pass"}])
            with self.assertRaises(module.common.AcceptanceFailure):
                module.inspect(path, ("Expected",))

    def test_expected_skipped_case_is_limited_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.events(directory, [{"Test": "Other", "Action": "pass"}, {"Test": "Expected", "Action": "skip"}])
            value = module.inspect(path, ("Expected",))
            self.assertEqual(["Expected"], value["skipped_tests"])

    def test_failure_cannot_be_hidden_by_another_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.events(directory, [{"Test": "Expected", "Action": "pass"}, {"Package": "x", "Action": "fail"}])
            with self.assertRaises(module.common.AcceptanceFailure):
                module.inspect(path, ("Expected",))

    def test_fixed_cases_cover_all_cross_batch_domains(self):
        labels = {row[0] for row in module.CASES}
        self.assertEqual(8, len(labels))
        self.assertEqual({"legacy-and-encrypted-migration", "live-maintenance-and-certificate-restore", "protocols-and-clients",
                          "controlled-nat-v4-v6", "egress-failure-and-recovery", "subscription-authorization", "monitor-stop-contract", "pool-and-credential-expiry"}, labels)
        self.assertTrue(all(row[3] <= 300 for row in module.CASES))

    def test_no_intent_or_marker_cannot_start_go(self):
        args = type("Args", (), {"disposable": False})()
        with mock.patch.object(module.subprocess, "run") as command:
            with self.assertRaises(module.common.AcceptanceFailure):
                module.run(args)
        command.assert_not_called()

    def test_real_legacy_gate_has_an_exact_required_name(self):
        case = module.LEGACY_CASE
        self.assertEqual("^TestLegacyV028RealBinaryMigrationAndBackup$", case[2])
        self.assertEqual(("TestLegacyV028RealBinaryMigrationAndBackup",), case[4])
        self.assertLessEqual(case[3], 300)

    def test_legacy_input_is_explicit_paired_and_digest_checked(self):
        for path, digest in (("/legacy", ""), ("", "a" * 64)):
            args = type("Args", (), {"legacy_bin": path, "legacy_sha256": digest})()
            with mock.patch.object(module.common, "binary") as check:
                with self.assertRaises(module.common.AcceptanceFailure):
                    module.legacy_binary(args)
                check.assert_not_called()
        args = type("Args", (), {"legacy_bin": "", "legacy_sha256": ""})()
        self.assertIsNone(module.legacy_binary(args))
        args = type("Args", (), {"legacy_bin": "/legacy", "legacy_sha256": "a" * 64})()
        with mock.patch.object(module.common, "binary", return_value=Path("/legacy")) as check:
            self.assertEqual(Path("/legacy"), module.legacy_binary(args))
            check.assert_called_once_with("/legacy", "a" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
