#!/usr/bin/env python3
"""Fixture safety contracts; these do not replace managed-service TLS traffic."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("platform_tls", Path(__file__).with_name("test-platform-tls.py"))
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)


def client():
    return {"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1080}],
            "outbounds": [{"type": "hysteria2", "tag": "selected", "server": "127.0.0.1", "server_port": tls.HY2_PORT,
                           "tls": {"enabled": True, "server_name": "localhost"}}],
            "route": {"final": "selected"}}


class ClientTrustTests(unittest.TestCase):
    def test_absent_security_module_is_unknown_but_enforcing_read_error_fails(self):
        domain = mock.Mock()
        domain.read_text.side_effect = OSError(22, "module unavailable")
        self.assertEqual("unavailable:errno=22", tls.service_security_context(domain, "unavailable"))
        with self.assertRaisesRegex(tls.Failure, "enforcing_service_context_unreadable"):
            tls.service_security_context(domain, "Enforcing")

    def test_private_ca_is_added_only_to_client_without_insecure(self):
        original = client()
        configured = tls.trusted_client(original, "private test CA")
        self.assertNotIn("certificate", original["outbounds"][0]["tls"])
        self.assertEqual(["private test CA"], configured["outbounds"][0]["tls"]["certificate"])
        self.assertNotIn("insecure", configured["outbounds"][0]["tls"])
        self.assertEqual("selected", configured["route"]["final"])

    def test_direct_multiple_outbounds_detour_or_route_escape_are_rejected(self):
        for kind in ("direct", "multiple", "detour", "route", "rule"):
            with self.subTest(kind=kind):
                config = client()
                if kind == "direct": config["outbounds"][0]["type"] = "direct"
                elif kind == "multiple": config["outbounds"].append({"type": "direct"})
                elif kind == "detour": config["outbounds"][0]["detour"] = "another"
                elif kind == "route": config["route"]["final"] = "another"
                else: config["route"]["rules"] = [{"outbound": "another"}]
                with self.assertRaises(tls.Failure): tls.trusted_client(config, "CA")

    def test_wrong_endpoint_public_listener_name_and_insecure_are_rejected(self):
        for kind in ("server", "port", "listener", "sni", "insecure"):
            with self.subTest(kind=kind):
                config = client()
                if kind == "server": config["outbounds"][0]["server"] = "example.com"
                elif kind == "port": config["outbounds"][0]["server_port"] = 8443
                elif kind == "listener": config["inbounds"][0]["listen"] = "0.0.0.0"
                elif kind == "sni": config["outbounds"][0]["tls"]["server_name"] = "wrong.invalid"
                else: config["outbounds"][0]["tls"]["insecure"] = True
                with self.assertRaises(tls.Failure): tls.trusted_client(config, "CA")

    def test_export_for_unselected_identity_is_rejected_before_cli_runs(self):
        calls = mock.Mock()
        platform = SimpleNamespace(flow=SimpleNamespace(command=calls))
        with tls.export_trust(platform, "owned-node", "CA", Path.cwd()):
            with self.assertRaises(tls.Failure):
                platform.flow.command("qingnode", "export", "--id", "foreign", "--out", "foreign.json")
        calls.assert_not_called()
        self.assertIs(platform.flow.command, calls)

    def test_certificate_cleanup_requires_the_complete_confirmed_resource(self):
        expected = {"id": "owned", "certificate": {"key_pem": "fixture private material"}}
        self.assertTrue(tls.owned_resource({"certificates": [expected]}, expected))
        self.assertFalse(tls.owned_resource({"certificates": [{"id": "owned", "certificate": {"key_pem": "changed"}}]}, expected))
        self.assertFalse(tls.owned_resource({"certificates": [{"id": "foreign"}]}, expected))


if __name__ == "__main__":
    unittest.main()
