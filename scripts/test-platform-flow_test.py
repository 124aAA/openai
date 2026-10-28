#!/usr/bin/env python3
"""Helper contracts only; real PID and traffic acceptance remains a VM gate."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location("platform_flow",Path(__file__).with_name("test-platform-flow.py"))
flow=importlib.util.module_from_spec(spec);spec.loader.exec_module(flow)


class NativeObserverTests(unittest.TestCase):
    def tearDown(self):flow.SERVICE_KIND=None

    def test_systemd_observer_queries_store_once_then_only_native_controller(self):
        def command(*args,**unused):
            if args==("qingnode","status"):
                return SimpleNamespace(stdout="Manager=systemd\nActiveState=active\nMainPID=123\nUnitFileState=enabled\n",returncode=0)
            self.assertEqual(args[:3],("systemctl","show","qingnode.service"))
            return SimpleNamespace(stdout="ActiveState=active\nMainPID=123\nUnitFileState=enabled\n",returncode=0)
        with mock.patch.object(flow.flow,"command",side_effect=command) as calls:
            self.assertEqual(flow.properties()["Manager"],"systemd")
            for _ in range(3):self.assertEqual(flow.properties()["MainPID"],"123")
            self.assertEqual(sum(call.args[0]=="qingnode" for call in calls.call_args_list),1)

    def test_openrc_observer_uses_child_pid_and_native_runlevels(self):
        flow.SERVICE_KIND="openrc"
        outputs={
            ("rc-service","qingnode","status"):" * status: started\n",
            ("rc-service","qingnode","qingnode_pid"):"456\n",
            ("rc-update","-q","show"):"external | default\nqingnode | default custom.level\n"}
        with mock.patch.object(flow.flow,"command",side_effect=lambda *args,**kw:SimpleNamespace(stdout=outputs[args],returncode=0)):
            self.assertEqual(flow.properties(),{"Manager":"openrc","ActiveState":"active","MainPID":"456","UnitFileState":"enabled"})

    def test_unknown_openrc_is_not_stopped(self):
        flow.SERVICE_KIND="openrc"
        with mock.patch.object(flow.flow,"command",return_value=SimpleNamespace(stdout="controller unavailable",returncode=1)):
            with self.assertRaisesRegex(RuntimeError,"unknown"):flow.properties()

    def test_missing_systemd_property_is_rejected(self):
        flow.SERVICE_KIND="systemd"
        with mock.patch.object(flow.flow,"command",return_value=SimpleNamespace(stdout="MainPID=123\n",returncode=0)):
            with self.assertRaisesRegex(RuntimeError,"incomplete"):flow.properties()


if __name__=="__main__":unittest.main()
