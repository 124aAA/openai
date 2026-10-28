#!/usr/bin/env python3
"""Check that the TCP acceptance observer rejects interrupted/corrupted streams.

These local socket tests validate the observer; they do not count as systemd or
proxy-protocol acceptance. The real-host entry is test-maintenance-flow.py.
"""
import importlib.util
import contextlib
import pathlib
import socket
import threading
import unittest

SPEC = importlib.util.spec_from_file_location(
    "maintenance_flow", pathlib.Path(__file__).with_name("test-maintenance-flow.py"))
FLOW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLOW)


class ObserverTests(unittest.TestCase):
    def test_fragmented_data_and_early_eof(self):
        reader, writer = socket.socketpair()
        with reader, writer:
            reader.settimeout(2)
            writer.sendall(b"first")
            fragmented = threading.Timer(0.02, lambda: writer.sendall(b"second"))
            fragmented.start()
            self.assertEqual(FLOW.read_exact(reader, 11), b"firstsecond")
            fragmented.join(timeout=2)
            writer.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(RuntimeError, "reconnecting is not allowed"):
                FLOW.read_exact(reader, 1)

    def test_healthy_stream_then_interruption_is_detected(self):
        reader, writer = socket.socketpair()
        reader.settimeout(2)
        writer.settimeout(2)
        close_echo = threading.Event()

        def echo():
            with writer:
                try:
                    while not close_echo.is_set():
                        data = writer.recv(32768)
                        if not data:
                            return
                        writer.sendall(data)
                except OSError:
                    pass

        thread = threading.Thread(target=echo, daemon=True)
        thread.start()
        flow = FLOW.ActiveFlow(reader)
        flow.thread.start()
        try:
            flow.advance(0, 5)
            previous = flow.frames
            close_echo.set()
            with contextlib.suppress(OSError):
                writer.shutdown(socket.SHUT_RDWR)
            with self.assertRaises((RuntimeError, OSError)):
                flow.advance(previous, 50)
        finally:
            flow.close()
            thread.join(timeout=3)

    def test_corrupted_payload_cannot_pass(self):
        reader, writer = socket.socketpair()
        reader.settimeout(2)
        writer.settimeout(2)

        def corrupt_echo():
            with writer:
                data = FLOW.read_exact(writer, 8200)
                writer.sendall(b"X" + data[1:])

        thread = threading.Thread(target=corrupt_echo, daemon=True)
        thread.start()
        flow = FLOW.ActiveFlow(reader)
        flow.thread.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "payload changed"):
                flow.advance(0)
        finally:
            flow.close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
