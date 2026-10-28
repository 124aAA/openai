#!/usr/bin/env python3
"""Portable safety checks for the opt-in actual-init fixture, not VM evidence."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).with_name("test-platform-aux.py")
SPEC = importlib.util.spec_from_file_location("platform_aux", PATH)
aux = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(aux)


class AuxiliaryFixtureContract(unittest.TestCase):
    def preview(self, name="qingnode-subscription", action="install", manager="systemd", definitions=None):
        return subprocess.CompletedProcess([], 0, json.dumps({"version": 1, "name": name, "manager": manager, "action": action,
                                           "installed": False, "pending": False, "definitions": definitions or [name + ".service"]}).encode(), b"")

    def root_fixture(self, temporary):
        root = Path(temporary) / "root"
        (root / "current").mkdir(parents=True)
        (root / "current/state.json").write_bytes(b'{"identity":"unchanged"}\n')
        return root

    def test_duplicate_service_properties_are_rejected(self):
        with self.assertRaises(aux.CheckFailure):
            aux.fields(b"MainPID=12\nMainPID=13\n")

    def test_unknown_manager_is_not_faked(self):
        with mock.patch.object(aux, "run", return_value=subprocess.CompletedProcess([], 0, b"Manager=unavailable\n", b"")):
            self.assertEqual(aux.service()["Manager"], "unavailable")

    def test_command_error_omits_private_output_and_arguments(self):
        response = subprocess.CompletedProcess([], 1, b"proxy_password=do-not-publish", b"dns_token=do-not-publish")
        with mock.patch.object(aux.subprocess, "run", return_value=response):
            with self.assertRaises(aux.CheckFailure) as failure:
                aux.run("qingnode", "subscription", "--secret", "do-not-publish")
        self.assertNotIn("do-not-publish", str(failure.exception))

    def test_command_timeout_does_not_expose_exception_payload(self):
        with mock.patch.object(aux.subprocess, "run", side_effect=subprocess.TimeoutExpired("private-token", 1)):
            with self.assertRaises(aux.CheckFailure) as failure:
                aux.run("qingnode", "status")
        self.assertNotIn("private-token", str(failure.exception))

    def test_disposable_environment_is_required_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence.json"
            with mock.patch.object(aux.sys, "platform", "linux"), mock.patch.object(aux.os, "geteuid", return_value=0, create=True), mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(SystemExit) as failure:
                    aux.main(["--disposable", "--work-dir", temporary, "--out", str(evidence)])
            self.assertEqual(failure.exception.code, 2)
            self.assertFalse(evidence.exists())

    def test_missing_explicit_disposable_switch_is_rejected(self):
        with self.assertRaises(SystemExit) as failure:
            aux.main(["--work-dir", "/tmp/private", "--out", "/tmp/report.json"])
        self.assertEqual(failure.exception.code, 2)

    def test_atomic_write_preserves_exact_definition_and_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "qingnode-monitor"
            contents = b"#!/sbin/openrc-run\n# Managed by QingNode\n"
            aux.atomic_bytes(target, contents, 0o755)
            self.assertEqual(target.read_bytes(), contents)
            self.assertEqual(list(Path(temporary).iterdir()), [target])
            if os.name == 'posix':
                self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_product_install_preview_is_readonly_and_has_typed_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            member = Path(temporary) / "qingnode-subscription.service"
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux, "run", return_value=self.preview()) as command:
                value = aux.service_transaction("install", "qingnode-subscription", "systemd", [member], preview=True, public_url=aux.PUBLIC)
            self.assertFalse(value["pending"])
            self.assertFalse(member.exists())
            self.assertEqual(command.call_args.args, ("qingnode", "service", "install", "--name", "qingnode-subscription", "--preview", "--public-url", aux.PUBLIC))

    def test_product_preview_rejects_wrong_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            member = Path(temporary) / "qingnode-subscription.service"
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux, "run", return_value=self.preview(name="qingnode-monitor")):
                with self.assertRaises(aux.CheckFailure):
                    aux.service_transaction("install", "qingnode-subscription", "systemd", [member], preview=True)

    def test_product_preview_rejects_journal_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            member = Path(temporary) / "qingnode-subscription.service"
            def mutating_preview(*unused):
                (root / ".auxiliary-qingnode-subscription.journal.json").write_bytes(b"unexpected write")
                return self.preview()
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux, "run", side_effect=mutating_preview):
                with self.assertRaises(aux.CheckFailure):
                    aux.service_transaction("install", "qingnode-subscription", "systemd", [member], preview=True)

    def test_product_preview_also_detects_new_conflict_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            member = Path(temporary) / "qingnode-subscription.service"
            def mutating_preview(*unused):
                (root / ".auxiliary-qingnode-subscription.conflict.json").write_bytes(b"unexpected witness")
                return self.preview()
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux, "run", side_effect=mutating_preview):
                with self.assertRaises(aux.CheckFailure):
                    aux.service_transaction("install", "qingnode-subscription", "systemd", [member], preview=True)

    def test_cli_group_signal_refuses_other_group_or_exited_process(self):
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        with mock.patch.object(aux.os, "getpgid", return_value=456, create=True), mock.patch.object(aux.os, "killpg", create=True) as kill:
            with self.assertRaises(aux.CheckFailure):
                aux.stop_fixture_cli_group(process, 9)
            kill.assert_not_called()
        process.poll.return_value = 0
        with mock.patch.object(aux.os, "getpgid", create=True) as group, mock.patch.object(aux.os, "killpg", create=True) as kill:
            self.assertFalse(aux.stop_fixture_cli_group(process, 9))
            group.assert_not_called()
            kill.assert_not_called()

    def test_real_interruption_requires_prepared_journal_and_only_signals_cli_group(self):
        for phase, succeeds in [("prepared", True), ("committed", False)]:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = self.root_fixture(temporary)
                member = Path(temporary) / "qingnode-subscription.service"
                member.write_bytes(b"owned definition")
                pending = root / ".auxiliary-qingnode-subscription.journal.json"
                process = mock.Mock(pid=301)
                process.poll.return_value = None
                account = mock.Mock(pw_uid=45)
                def spawn(*args, **kwargs):
                    self.assertTrue(kwargs["start_new_session"])
                    self.assertEqual(args[0], ["qingnode", "service", "remove", "--name", "qingnode-subscription", "--yes"])
                    # Simulates the real CLI writer, not a fixture-created record.
                    pending.write_bytes(json.dumps({"phase": phase, "action": "remove"}).encode())
                    return process
                def transaction(action, name, kind, paths, **kwargs):
                    self.assertTrue(pending.exists())
                    if kwargs.get("preview"):
                        return {"pending": True}
                    pending.unlink()
                private_stat = mock.Mock(st_mode=0o100600, st_uid=0, st_nlink=1, st_size=40)
                original_stat = Path.lstat
                def selective_stat(path, *args, **kwargs):
                    return private_stat if path == pending else original_stat(path, *args, **kwargs)
                with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux, "service", return_value={"ActiveState": "active", "UnitFileState": "enabled"}), \
                     mock.patch.object(aux, "active_pid", side_effect=lambda name, uid: 100 if name == "qingnode" else 200), \
                     mock.patch.object(aux.subprocess, "Popen", side_effect=spawn), mock.patch.object(aux.os, "getpgid", side_effect=lambda pid: 301 if pid == 301 else 999, create=True), \
                     mock.patch.object(aux.os, "killpg", create=True) as kill, mock.patch.object(aux.signal, "SIGSTOP", 19, create=True), mock.patch.object(aux.signal, "SIGKILL", 9, create=True), \
                     mock.patch.object(aux, "service_transaction", side_effect=transaction) as recovery, mock.patch.object(Path, "lstat", selective_stat), \
                     mock.patch.object(aux, "atomic_bytes") as write:
                    if succeeds:
                        result = aux.interrupt_subscription_remove("systemd", [member], account, 44)
                        self.assertEqual(result, "actual-prepared-cli-process-group-interrupted-and-product-recovered")
                        self.assertEqual(recovery.call_count, 2)
                    else:
                        with self.assertRaises(aux.CheckFailure):
                            aux.interrupt_subscription_remove("systemd", [member], account, 44)
                        recovery.assert_not_called()
                        self.assertTrue(pending.exists())
                    self.assertEqual(kill.call_args_list, [mock.call(301, 19), mock.call(301, aux.signal.SIGKILL)])
                    process.wait.assert_called_once_with(timeout=5)
                    write.assert_not_called()

    def test_recover_noop_accepts_empty_members_without_claiming_a_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            member = Path(temporary) / "qingnode-monitor.service"
            response = self.preview(name="qingnode-monitor", action="recover")
            payload = json.loads(response.stdout)
            payload["definitions"] = []
            response.stdout = json.dumps(payload).encode()
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux, "run", return_value=response):
                preview = aux.service_transaction("recover", "qingnode-monitor", "systemd", [member], preview=True)
            self.assertFalse(preview["pending"])
            self.assertEqual(preview["definitions"], [])

    def test_definition_permissions_are_strict_for_actual_vm_check(self):
        path = mock.Mock()
        path.is_symlink.return_value = False
        for kind, mode in [("systemd", 0o644), ("openrc", 0o755)]:
            path.stat.return_value = mock.Mock(st_uid=0, st_mode=mode)
            aux.assert_definition_permissions(path, kind)
        for uid, mode, symlink in [(1, 0o644, False), (0, 0o666, False), (0, 0o644, True)]:
            path.stat.return_value = mock.Mock(st_uid=uid, st_mode=mode)
            path.is_symlink.return_value = symlink
            with self.assertRaises(aux.CheckFailure):
                aux.assert_definition_permissions(path, "systemd")

    def test_install_conflict_is_inert_and_real_definition_comes_from_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            member = Path(temporary) / "qingnode-subscription.service"
            definition = b"# Managed by QingNode\n"
            def transaction(action, name, kind, paths, **options):
                if options.get("preview"):
                    self.assertFalse(member.exists())
                else:
                    member.write_bytes(definition)
            def conflict(*args, **options):
                self.assertIn("not managed by QingNode", member.read_text())
                self.assertEqual(args[:3], ("qingnode", "service", "install"))
                return subprocess.CompletedProcess([], 1, b"", b"")
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux, "service_transaction", side_effect=transaction) as transactions, \
                 mock.patch.object(aux, "run", side_effect=conflict), mock.patch.object(aux, "service", return_value={"ActiveState": "inactive", "UnitFileState": "disabled"}), \
                 mock.patch.object(aux, "assert_definition_permissions") as actual_vm_permissions:
                owned = aux.install_with_conflict_check("qingnode-subscription", "systemd", [member], public_url=aux.PUBLIC)
            self.assertEqual(owned, {member: definition})
            self.assertEqual(transactions.call_count, 2)
            actual_vm_permissions.assert_called_once_with(member, "systemd")

    def test_modified_remove_uses_cli_and_restores_only_its_fault_injection(self):
        with tempfile.TemporaryDirectory() as temporary:
            member = Path(temporary) / "qingnode-monitor"
            original = b"#!/sbin/openrc-run\n# Managed by QingNode\n"
            member.write_bytes(original)
            with mock.patch.object(aux, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"")) as command:
                aux.reject_modified_remove("qingnode-monitor", member, original, "openrc")
            self.assertEqual(member.read_bytes(), original)
            self.assertEqual(command.call_args.args, ("qingnode", "service", "remove", "--name", "qingnode-monitor", "--yes"))
            with mock.patch.object(aux, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
                with self.assertRaises(aux.CheckFailure):
                    aux.reject_modified_remove("qingnode-monitor", member, original, "openrc")
            self.assertEqual(member.read_bytes(), original)

    def test_explicit_pending_recovery_never_manufactures_a_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            evidence = Path(temporary) / "recovery.json"
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux.sys, "platform", "linux"), \
                 mock.patch.object(aux.os, "geteuid", return_value=0, create=True), mock.patch.object(aux, "private_dir", side_effect=Path), \
                 mock.patch.dict(os.environ, {"QINGNODE_VM_DISPOSABLE": "1"}), mock.patch.object(aux, "service", return_value={"Manager": "systemd"}):
                with self.assertRaises(aux.CheckFailure):
                    aux.main(["--disposable", "--work-dir", temporary, "--out", str(evidence), "--recover-pending-only", "qingnode-monitor"])
            self.assertFalse((root / ".auxiliary-qingnode-monitor.journal.json").exists())
            self.assertFalse(evidence.exists())

    def test_pending_recovery_report_stays_separate_from_full_lifecycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_fixture(temporary)
            pending = root / ".auxiliary-qingnode-monitor.journal.json"
            pending.write_bytes(b"unit-test-only pending fixture")
            evidence = Path(temporary) / "recovery.json"
            def transaction(action, name, kind, paths, **options):
                self.assertEqual((action, name, kind), ("recover", "qingnode-monitor", "systemd"))
                if options.get("preview"):
                    return {"pending": True}
                pending.unlink()
            with mock.patch.object(aux, "ROOT", root), mock.patch.object(aux.sys, "platform", "linux"), \
                 mock.patch.object(aux.os, "geteuid", return_value=0, create=True), mock.patch.object(aux, "private_dir", side_effect=Path), \
                 mock.patch.dict(os.environ, {"QINGNODE_VM_DISPOSABLE": "1"}), mock.patch.object(aux, "service", return_value={"Manager": "systemd"}), \
                 mock.patch.object(aux, "service_transaction", side_effect=transaction):
                result = aux.main(["--disposable", "--work-dir", temporary, "--out", str(evidence), "--recover-pending-only", "qingnode-monitor"])
            self.assertEqual(result, 0)
            report = json.loads(evidence.read_bytes())
            self.assertIn("not the full auxiliary lifecycle", report["scope"])
            self.assertEqual(report["checks"], ["explicit-product-cli-pending-recovery-state-preserved"])


if __name__ == "__main__":
    unittest.main()
