#!/usr/bin/env python3
"""Pure helper tests; these do not count as firewalld or SELinux VM evidence."""
import importlib.util
from pathlib import Path
import stat
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("platform_firewall_acceptance", Path(__file__).with_name("test-platform-firewall.py"))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def fixture():
    token = "0123456789abcdef"
    return {"version": 1, "owner": acceptance.MARKER, "token": token, "zone": "public", "port": 34567,
            "xml_path": "/etc/firewalld/services/qingnode-test-" + token + ".xml",
            "rule": 'rule family="ipv4" source address="192.0.2.250/32" port port="34567" protocol="tcp" reject',
            "before": [["foreign-before"], ["foreign-before"]], "active_zones": "public\n  interfaces: eth0"}


class RuleHelpers(unittest.TestCase):
    def test_commands_change_only_exact_rule_in_exact_store(self):
        rule = fixture()["rule"]
        self.assertEqual(acceptance.fw_args("public", False, "--add-rich-rule=" + rule),
                         ("firewall-cmd", "--zone=public", "--add-rich-rule=" + rule))
        self.assertEqual(acceptance.fw_args("public", True, "--remove-rich-rule=" + rule),
                         ("firewall-cmd", "--permanent", "--zone=public", "--remove-rich-rule=" + rule))

    def test_zone_cannot_inject_options(self):
        for zone in ("--reload", "public\n--reload", "public;sh", "", "x" * 65):
            # A leading double hyphen is syntactically legal as a zone name,
            # but remains inside the single --zone= argument.
            if zone == "--reload":
                self.assertEqual(acceptance.fw_args(zone, False)[1], "--zone=--reload")
                continue
            with self.subTest(zone=zone), self.assertRaises(acceptance.Failure):
                acceptance.fw_args(zone, False)

    def test_tcp_udp_and_both_families_are_separate(self):
        result = acceptance.expected_rules([
            {"listen": "0.0.0.0", "port": 34567, "protocol": "ss2022"},
            {"listen": "::", "port": 34568, "protocol": "ss2022"}])
        self.assertEqual(len(result), 6)
        self.assertIn('rule family="ipv6" port port="34568" protocol="udp" accept', result)
        self.assertIn('rule family="ipv4" port port="34567" protocol="tcp" accept', result)
        self.assertNotIn('rule family="ipv6" port port="34567" protocol="tcp" accept', result)

    def test_expected_matrix_rejects_unrelated_node(self):
        for address, protocol in (("127.0.0.1", "ss2022"), ("::1", "ss2022"), ("0.0.0.0", "trojan")):
            with self.subTest(address=address, protocol=protocol), self.assertRaises(acceptance.Failure):
                acceptance.expected_rules([{"listen": address, "port": 34567, "protocol": protocol}])

    def test_write_requires_actual_readback(self):
        rule = fixture()["rule"]
        with patch.object(acceptance, "run") as run, patch.object(acceptance, "lists", return_value=[[], []]):
            with self.assertRaisesRegex(acceptance.Failure, "readback_mismatch"):
                acceptance.change("public", False, rule, True)
            run.assert_called_once_with("firewall-cmd", "--zone=public", "--add-rich-rule=" + rule)

    def test_remove_does_not_modify_permanent_when_runtime_selected(self):
        rule = fixture()["rule"]
        with patch.object(acceptance, "run") as run, patch.object(acceptance, "lists", return_value=[[], [rule]]):
            acceptance.change("public", False, rule, False)
            run.assert_called_once_with("firewall-cmd", "--zone=public", "--remove-rich-rule=" + rule)


class RecoveryOwnership(unittest.TestCase):
    def test_exact_journal_is_accepted(self):
        self.assertEqual(acceptance.validate_journal(fixture())["zone"], "public")

    def test_future_format_and_foreign_asset_are_refused(self):
        for field, value in (("version", 2), ("owner", "external"), ("token", "../x"),
                             ("xml_path", "/etc/firewalld/services/ssh.xml"),
                             ("rule", "rule service name=ssh accept"), ("port", True)):
            candidate = fixture()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(acceptance.Failure):
                acceptance.validate_journal(candidate)

    def test_foreign_added_rule_is_reported_instead_of_removed(self):
        data = fixture()
        fake_path = types.SimpleNamespace(
            lstat=lambda: types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1),
            read_bytes=lambda: acceptance.sentinel_xml(data["token"]))
        expected = sorted(data["before"][0] + [data["rule"]])
        with patch.object(acceptance, "Path", return_value=fake_path), \
                patch.object(acceptance, "require_environment", return_value=(data["zone"], data["active_zones"])), \
                patch.object(acceptance, "lists", return_value=[expected + ["administrator-new-rule"], expected]), \
                patch.object(acceptance, "change") as change:
            with self.assertRaisesRegex(acceptance.Failure, "not_preserved"):
                acceptance.preserved(data)
            change.assert_not_called()

    def test_host_enforcing_and_service_running_are_not_inferred_from_tools(self):
        for values in (("Permissive",), ("Enforcing", "not running")):
            with self.subTest(values=values), patch.object(acceptance, "run", side_effect=values):
                with self.assertRaises(acceptance.Failure):
                    acceptance.require_environment()


if __name__ == "__main__":
    unittest.main()
