#!/usr/bin/env python3
"""Portable contracts only; these mocks are not actual CLI acceptance."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('machine_interface',Path(__file__).with_name('test-machine-interface.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class MachineInterfaceContracts(unittest.TestCase):
    def test_invalid_future_duplicate_nonfinite_and_extra_json_rejected(self):
        for raw in (b'{}',b'{"version":2}',b'{"version":1,"version":1}',b'{"version":1,"sample":NaN}',b'{"version":1} {}',b'x'*(4<<20)+b'x'):
            with self.subTest(raw=raw[:32]):
                with self.assertRaises((RuntimeError,ValueError)):m.document(raw)
        self.assertEqual({'version':1,'missing':None},m.document(b'{"version":1,"missing":null}'))

    def test_requires_explicit_linux_and_new_output(self):
        with mock.patch.object(m.sys,'platform','win32'):
            with self.assertRaises(SystemExit):m.main(['--disposable','--bin','/abs/program','--sha256','a'*64,'--out','/abs/report'])
        with self.assertRaises(SystemExit):m.main([])

    def test_wrong_binary_digest_never_executes_suite(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);binary=root/'binary';binary.write_bytes(b'fixture')
            with mock.patch.object(m.sys,'platform','linux'),mock.patch.object(m,'run_suite')as suite:
                with self.assertRaises(ValueError):m.main(['--disposable','--bin',str(binary),'--sha256','a'*64,'--out',str(root/'report')])
                suite.assert_not_called()

    def test_existing_report_not_overwritten_or_executed(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);binary=root/'binary';binary.write_bytes(b'fixture');output=root/'report';output.write_bytes(b'preserve')
            digest=hashlib.sha256(binary.read_bytes()).hexdigest()
            with mock.patch.object(m.sys,'platform','linux'),mock.patch.object(m,'run_suite')as suite:
                with self.assertRaises(SystemExit):m.main(['--disposable','--bin',str(binary),'--sha256',digest,'--out',str(output)])
                suite.assert_not_called()
            self.assertEqual(b'preserve',output.read_bytes())

    def test_report_does_not_claim_service_protocol_public_gui_or_copy_raw_data(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);binary=root/'binary';binary.write_bytes(b'fixture');output=root/'report'
            digest=hashlib.sha256(binary.read_bytes()).hexdigest()
            with mock.patch.object(m.sys,'platform','linux'),mock.patch.object(m,'run_suite',return_value=['contract-only-no-actual-execution']),mock.patch.object(m.sys,'stdout',io.StringIO()):
                m.main(['--disposable','--bin',str(binary),'--sha256',digest,'--out',str(output)])
            result=json.loads(output.read_bytes())
            self.assertEqual('not-tested',result['proxy_authentication'])
            self.assertEqual('unknown',result['public_ingress'])
            self.assertEqual('not-tested',result['client_GUI'])
            self.assertFalse(result['production_state_or_services_changed'])
            self.assertFalse(result['raw_output_or_private_fixture_included'])
            self.assertNotIn('stdout',result)
            self.assertNotIn('state',result)


if __name__=='__main__':unittest.main()
