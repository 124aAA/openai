#!/usr/bin/env python3
"""Observe real systemd MainPID and one unbroken SS2022 TCP stream on a disposable host."""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import socket
import struct
import subprocess
import threading
import time

ROOT = pathlib.Path("/var/lib/qingnode")


def command(*args, success=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=90, check=False)
    if success and result.returncode:
        raise RuntimeError(f"command failed: {args[0]} {args[1]}\n{result.stdout}")
    return result


def identity():
    pid = int(command("systemctl", "show", "qingnode.service", "--property=MainPID", "--value").stdout.strip())
    if pid <= 0:
        raise RuntimeError("qingnode.service has no MainPID")
    # A reused process number must not look like the original process.
    stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
    start = stat.rsplit(")", 1)[1].split()[19]
    return pid, start


def enabled_state():
    result = command("systemctl", "is-enabled", "qingnode.service", success=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("cannot observe service autostart state")
    return result.stdout.strip()


def state():
    return json.loads((ROOT / "current/state.json").read_text())


def disk_digest():
    current = ROOT / "current"
    files = ("state.json", "server.json", "core-version", "parent", "runtime-identity")
    hashes = tuple(hashlib.sha256((current / name).read_bytes()).hexdigest()
                   if (current / name).exists() else None for name in files)
    generations = tuple(sorted(path.name for path in (ROOT / "generations").iterdir()))
    journals = tuple(hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                     if (ROOT / name).exists() else None for name in ("transaction.json", "uninstall.json"))
    return os.readlink(current), hashes, generations, journals


def read_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise RuntimeError("active TCP connection closed; reconnecting is not allowed")
        data.extend(part)
    return bytes(data)


def socks_connect(port, destination):
    connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    connection.sendall(b"\x05\x01\x00")
    if read_exact(connection, 2) != b"\x05\x00":
        connection.close()
        raise RuntimeError("SOCKS authentication negotiation failed")
    connection.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(destination[0]) + struct.pack("!H", destination[1]))
    reply = read_exact(connection, 4)
    if reply[:3] != b"\x05\x00\x00":
        connection.close()
        raise RuntimeError("SOCKS connection failed")
    if reply[3] == 1:
        size = 4
    elif reply[3] == 4:
        size = 16
    elif reply[3] == 3:
        size = read_exact(connection, 1)[0]
    else:
        connection.close()
        raise RuntimeError("unknown SOCKS address family")
    read_exact(connection, size + 2)
    return connection


class ActiveFlow:
    def __init__(self, connection):
        self.connection = connection
        self.stop = threading.Event()
        self.frames = 0
        self.errors = []
        self.thread = threading.Thread(target=self.transfer, daemon=True)

    def transfer(self):
        try:
            while not self.stop.is_set():
                payload = struct.pack("!Q", self.frames) + bytes(8192)
                self.connection.sendall(payload)
                if read_exact(self.connection, len(payload)) != payload:
                    raise RuntimeError("TCP payload changed during maintenance")
                self.frames += 1
                self.stop.wait(0.01)
        except Exception as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def advance(self, previous, count=3):
        deadline = time.monotonic() + 8
        while self.frames < previous + count:
            if self.errors:
                raise self.errors[0]
            if time.monotonic() >= deadline:
                raise RuntimeError("active TCP stream stopped advancing")
            time.sleep(0.02)

    def close(self):
        self.stop.set()
        self.connection.close()
        self.thread.join(timeout=6)


@contextlib.contextmanager
def running_flow(workdir, node_id):
    config_path = workdir / "maintenance-client.json"
    command("qingnode", "export", "--id", node_id, "--format", "sing-box", "--out", str(config_path))
    config = json.loads(config_path.read_text())
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config["inbounds"][0]["listen_port"] = port
    config_path.write_text(json.dumps(config))
    core = ROOT / "cores" / state()["core_version"] / "sing-box"
    command(str(core), "check", "-c", str(config_path))
    echo = socket.socket()
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)
    echo.settimeout(8)

    def echo_bytes():
        try:
            client, _ = echo.accept()
            with client:
                client.settimeout(10)
                while True:
                    data = client.recv(32768)
                    if not data:
                        break
                    client.sendall(data)
        except (OSError, TimeoutError):
            # The traffic reader observes timeout/EOF and fails the test itself.
            pass

    thread = threading.Thread(target=echo_bytes, daemon=True)
    thread.start()
    flow = None
    with (workdir / "maintenance-client.log").open("w") as log:
        process = subprocess.Popen([str(core), "run", "-c", str(config_path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 8
            while True:
                if process.poll() is not None:
                    raise RuntimeError("official sing-box test client exited")
                try:
                    connection = socks_connect(port, echo.getsockname())
                    break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            flow = ActiveFlow(connection)
            flow.thread.start()
            flow.advance(0)
            yield flow
        finally:
            if flow:
                flow.close()
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=8)
            echo.close()
            thread.join(timeout=6)


def unchanged(flow, label, action):
    original = identity()
    autostart = enabled_state()
    samples, errors = [], []
    stop = threading.Event()

    def observe():
        while not stop.is_set():
            try:
                samples.append(identity())
            except Exception as error:
                errors.append(error)
            stop.wait(0.05)

    watcher = threading.Thread(target=observe, daemon=True)
    watcher.start()
    frames = flow.frames
    try:
        action()
        flow.advance(frames)
        samples.append(identity())
        if errors or any(sample != original for sample in samples):
            raise RuntimeError(f"{label}: MainPID/process identity changed during metadata maintenance")
        if enabled_state() != autostart:
            raise RuntimeError(f"{label}: autostart changed")
        print(f"PASS {label}: MainPID={original[0]}, active TCP frames={frames}->{flow.frames}, PID samples={len(samples)}", flush=True)
    finally:
        stop.set()
        watcher.join(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--work-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or pathlib.Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("requires root and real systemd; a simulated service is not accepted")
    if not args.work_dir.is_absolute() or not args.work_dir.is_dir():
        parser.error("--work-dir must be an existing private absolute directory")
    original = state()
    ss = next(n for n in original["nodes"] if n["name"] == "acceptance-ss" and n["protocol"] == "ss2022")
    reality = next(n for n in original["nodes"] if n["name"] == "acceptance-reality" and n["protocol"] == "reality")
    ss_id, reality_id = ss["id"], reality["id"]
    batch = args.work_dir / "maintenance-batch.json"
    batch.write_text(json.dumps({"version": 1, "edits": [
        {"id": ss_id, "name": "acceptance-ss-batch"},
        {"id": reality_id, "name": "acceptance-reality-batch", "fingerprint": "firefox"}]}))
    invalid = args.work_dir / "maintenance-invalid.json"
    invalid.write_text(json.dumps({"version": 1, "edits": [
        {"id": ss_id, "name": "must-not-be-committed"}, {"id": reality_id, "port": 0}]}))
    with running_flow(args.work_dir, ss_id) as flow:
        unchanged(flow, "rename", lambda: command("qingnode", "edit", "--id", ss_id, "--name", "acceptance-ss-metadata"))
        unchanged(flow, "client-address", lambda: command("qingnode", "edit", "--id", ss_id, "--server", "localhost"))
        # The established client remains on its existing endpoint. These edits
        # change only future client exports and must preserve this exact stream.
        connection_port = ss.get("connect_port", ss["port"])
        alternate_port = 30000 if connection_port != 30000 else 30001
        unchanged(flow, "connection-port", lambda: command("qingnode", "endpoint", "edit", "--id", ss_id,
                                                          "--connect-port", str(alternate_port)))
        unchanged(flow, "additional-endpoint", lambda: command("qingnode", "endpoint", "add", "--id", ss_id,
                                                               "--endpoint", "acceptance-v6", "--server", "::1", "--connect-port", str(alternate_port)))
        unchanged(flow, "remove-additional-endpoint", lambda: command("qingnode", "endpoint", "remove", "--id", ss_id,
                                                                      "--endpoint", "acceptance-v6"))
        unchanged(flow, "restore-connection-port", lambda: command("qingnode", "endpoint", "edit", "--id", ss_id,
                                                                  "--connect-port", str(connection_port)))
        before = disk_digest()
        unchanged(flow, "repeat-apply", lambda: command("qingnode", "edit", "--id", ss_id, "--server", "localhost"))
        if disk_digest() != before:
            raise RuntimeError("repeat apply created or changed a generation")
        unchanged(flow, "explicit-repeat-apply", lambda: command("qingnode", "apply"))
        if disk_digest() != before:
            raise RuntimeError("explicit repeat apply created or changed a generation")
        unchanged(flow, "batch-preview", lambda: command("qingnode", "batch", "--file", str(batch), "--preview"))
        if disk_digest() != before:
            raise RuntimeError("preview changed state or derived files")
        unchanged(flow, "batch-metadata-and-fingerprint", lambda: command("qingnode", "batch", "--file", str(batch)))
        before_invalid = disk_digest()
        result = command("qingnode", "batch", "--file", str(invalid), success=False)
        if result.returncode == 0 or disk_digest() != before_invalid:
            raise RuntimeError("invalid batch was accepted or partially changed state")
        unchanged(flow, "metadata-rollback", lambda: command("qingnode", "rollback"))
        damaged_generation = (ROOT / "current").resolve()
        (damaged_generation / "server.json").write_text("{damaged-maintenance-fixture")
        unchanged(flow, "derived-file-repair", lambda: command("qingnode", "edit", "--id", ss_id, "--server", "localhost"))
        command("qingnode", "check")
        if (ROOT / "current").resolve() == damaged_generation:
            raise RuntimeError("damaged server config was not repaired into a new generation")
        if (damaged_generation / "server.json").read_text() != "{damaged-maintenance-fixture":
            raise RuntimeError("repair discarded original damaged recovery material")
        unchanged(flow, "restore-client-address-and-name", lambda: command("qingnode", "edit", "--id", ss_id,
                                                                          "--server", ss["host"], "--name", ss["name"]))
        print(f"PASS one persistent TCP connection: {flow.frames} verified frames, no reconnect", flush=True)
    old_pid = identity()
    autostart = enabled_state()
    command("qingnode", "edit", "--id", ss_id, "--random-port")
    if identity() == old_pid or enabled_state() != autostart:
        raise RuntimeError("runtime port change did not replace MainPID or changed autostart")
    command("qingnode", "rollback")
    command("qingnode", "check")
    print("PASS runtime port change and runtime rollback: real service restarted and validated", flush=True)
    command("qingnode", "stop")
    autostart = enabled_state()
    command("qingnode", "edit", "--id", ss_id, "--name", "acceptance-ss-stopped")
    if command("systemctl", "is-active", "--quiet", "qingnode.service", success=False).returncode == 0:
        raise RuntimeError("metadata edit started a previously stopped service")
    if enabled_state() != autostart:
        raise RuntimeError("stopped metadata edit changed autostart")
    command("qingnode", "rollback")
    if command("systemctl", "is-active", "--quiet", "qingnode.service", success=False).returncode == 0:
        raise RuntimeError("metadata rollback started a previously stopped service")
    command("qingnode", "start")
    final = state()
    for old in original["nodes"]:
        new = next(n for n in final["nodes"] if n["id"] == old["id"])
        for key in ("protocol", "users", "reality", "shadowsocks", "certificate", "port", "host"):
            if new.get(key) != old.get(key):
                raise RuntimeError(f"maintenance changed preserved identity/configuration field: {key}")
    print("PASS stopped metadata edit/rollback, autostart and node identities preserved", flush=True)


if __name__ == "__main__":
    main()
