#!/usr/bin/env python3
"""Portable guards for the separate actual-Linux-PTY acceptance entry."""
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('terminal_workflow',Path(__file__).with_name('test-terminal-workflow.py'))
workflow=importlib.util.module_from_spec(spec);spec.loader.exec_module(workflow)

class TerminalContract(unittest.TestCase):
    def test_public_output_guard_detects_real_width_controls_and_secret_regressions(self):
        workflow.check_public_output('中😀a\r\nplain\r\n',5,['private-fixture-value'])
        for text,width in [('中文😀',5),('label\u202evalue',80),('label\u2066value',80),
                           ('label\x1b[31mvalue',80),('private-fixture-value',80)]:
            with self.subTest(category=repr(text)):
                with self.assertRaises(RuntimeError):
                    workflow.check_public_output(text,width,['private-fixture-value'])
    def test_prompt_wait_cannot_reuse_consumed_output(self):
        session=workflow.Session.__new__(workflow.Session)
        marker='节点名称'.encode()
        session.output=bytearray(marker)
        session.search_from=0
        session.read('节点名称',timeout=0)
        self.assertEqual(len(marker),session.search_from)
        with self.assertRaises(RuntimeError):session.read('节点名称',timeout=0)
        session.output.extend(marker)
        session.read('节点名称',timeout=0)
        self.assertEqual(2*len(marker),session.search_from)
    def test_requires_explicit_linux_pty_and_all_inputs(self):
        with mock.patch.object(workflow.sys,'platform','win32'):
            with self.assertRaises(SystemExit): workflow.main(['--disposable','--bin','/abs/cli','--sha256','a'*64,'--out','/abs/result'])
        with self.assertRaises(SystemExit): workflow.main([])
    def test_refuses_wrong_binary_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'cli';path.write_bytes(b'fixed fixture')
            with self.assertRaises(ValueError): workflow.checked_binary(path,'a'*64)
            self.assertEqual(path,workflow.checked_binary(path,hashlib.sha256(path.read_bytes()).hexdigest()))
    def test_refuses_links_and_relative_paths(self):
        with self.assertRaises(ValueError): workflow.checked_binary(Path('relative'),'a'*64)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'cli';path.write_bytes(b'x')
            with mock.patch.object(Path,'is_symlink',return_value=True):
                with self.assertRaises(ValueError):workflow.checked_binary(path,hashlib.sha256(b'x').hexdigest())
    def test_report_has_no_terminal_capture_and_says_phone_unverified(self):
        # Exercise only report writing; no mock result is accepted as PTY proof.
        with tempfile.TemporaryDirectory() as temp:
            binary=Path(temp)/'cli';binary.write_bytes(b'x');out=Path(temp)/'report.json'
            with mock.patch.object(workflow.sys,'platform','linux'),mock.patch.object(workflow,'pty',object()),mock.patch.object(workflow.sys,'stdout',io.StringIO()),mock.patch.object(workflow,'run_suite',return_value=['contract-only-no-real-PTY']) as suite:
                workflow.main(['--disposable','--bin',str(binary),'--sha256',hashlib.sha256(b'x').hexdigest(),'--out',str(out)])
            value=json.loads(out.read_bytes());self.assertFalse(value['raw_terminal_capture_included']);self.assertEqual('not-tested',value['physical_phone_ssh']);suite.assert_called_once()
            with mock.patch.object(workflow.sys,'platform','linux'),mock.patch.object(workflow,'pty',object()),mock.patch.object(workflow,'run_suite') as suite:
                with self.assertRaises(SystemExit):workflow.main(['--disposable','--bin',str(binary),'--sha256',hashlib.sha256(b'x').hexdigest(),'--out',str(out)])
                suite.assert_not_called()

if __name__=='__main__':unittest.main()
