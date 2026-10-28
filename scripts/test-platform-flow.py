#!/usr/bin/env python3
"""Actual owned-service TCP/UDP acceptance; only on an explicit disposable host.

Reuses the existing stream observer and official core client. It implements only
the local SOCKS5 test framing, never an encrypted proxy protocol or service mock.
"""
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import socket
import struct
import subprocess
import stat
import sys
import threading
import time

SOURCE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("maintenance_flow", SOURCE / "test-maintenance-flow.py")
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


# Read the manager once before the observer starts. Repeated management CLI
# queries take the Store inspection lock and can collide with the write being
# measured; the native controller is the independent PID/autostart observer.
SERVICE_KIND = None


def parse_properties(raw):
    values = {}
    for line in raw.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in values:
                raise RuntimeError("duplicate native service property")
            values[key] = value
    return values


def properties():
    global SERVICE_KIND
    if SERVICE_KIND is None:
        values = parse_properties(flow.command("qingnode", "status").stdout)
        if values.get("Manager") not in ("systemd", "openrc"):
            raise RuntimeError("actual supported init controller is unavailable")
        SERVICE_KIND = values["Manager"]
        return values
    if SERVICE_KIND == "systemd":
        values = parse_properties(flow.command("systemctl", "show", "qingnode.service", "--no-pager",
                                              "--property=ActiveState,MainPID,UnitFileState").stdout)
        if not all(key in values for key in ("ActiveState", "MainPID", "UnitFileState")):
            raise RuntimeError("native systemd observation is incomplete")
        values["Manager"] = SERVICE_KIND
        return values
    result = flow.command("rc-service", "qingnode", "status", success=False)
    if result.returncode == 0 and "status: started" in result.stdout:
        active = "active"
        pid = flow.command("rc-service", "qingnode", "qingnode_pid").stdout.strip()
        if not pid.isdigit() or int(pid) <= 0:
            raise RuntimeError("native OpenRC child PID is unknown")
    elif any(text in result.stdout for text in ("status: stopped", "status: crashed", "status: inactive")):
        active, pid = "inactive", "0"
    else:
        raise RuntimeError("native OpenRC activity is unknown")
    levels = []
    for line in flow.command("rc-update", "-q", "show").stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == "qingnode":
            if len(parts) < 2 or parts[1] != "|" or levels:
                raise RuntimeError("native OpenRC runlevel observation is invalid")
            levels = parts[2:]
            if any(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", level) is None for level in levels):
                raise RuntimeError("native OpenRC runlevel name is invalid")
    return {"Manager": SERVICE_KIND, "ActiveState": active, "MainPID": pid,
            "UnitFileState": "enabled" if levels else "disabled"}


def identity():
    pid = int(properties().get("MainPID", "0"))
    if pid < 1:
        raise RuntimeError("actual managed service has no live PID")
    return pid, Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def enabled_state():
    return properties()["UnitFileState"]


def udp_transfer(work, node):
    config_path = work / "udp-client.json"
    flow.command("qingnode", "export", "--id", node, "--format", "sing-box", "--out", str(config_path))
    config = json.loads(config_path.read_text())
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config["inbounds"][0]["listen_port"] = port
    # The exported config has exactly the selected node, with no direct fallback.
    if len(config["outbounds"]) != 1 or config["outbounds"][0]["type"] == "direct":
        raise RuntimeError("test client would have an unauthorized direct route")
    config_path.write_text(json.dumps(config))
    core = flow.ROOT / "cores" / flow.state()["core_version"] / "sing-box"
    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target.bind(("127.0.0.1", 0))
    target.settimeout(5)
    received = []

    def echo():
        try:
            for _ in range(3):
                data, peer = target.recvfrom(2048)
                received.append(data)
                target.sendto(data, peer)
        except OSError:
            pass

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    with (work / "udp-client.log").open("w") as log:
        client = subprocess.Popen([str(core), "run", "-c", str(config_path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 8
            while True:
                if client.poll() is not None:
                    raise RuntimeError("official UDP test client exited")
                try:
                    control = socket.create_connection(("127.0.0.1", port), timeout=2)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.05)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
                control.sendall(b"\x05\x01\x00")
                if flow.read_exact(control, 2) != b"\x05\x00":
                    raise RuntimeError("SOCKS negotiation failed")
                control.sendall(b"\x05\x03\x00\x01" + bytes(6))
                header = flow.read_exact(control, 4)
                if header != b"\x05\x00\x00\x01":
                    raise RuntimeError("SOCKS UDP association failed")
                host = socket.inet_ntoa(flow.read_exact(control, 4))
                relay_port = struct.unpack("!H", flow.read_exact(control, 2))[0]
                if host == "0.0.0.0":
                    host = "127.0.0.1"
                channel.settimeout(3)
                for sequence in range(3):
                    payload = b"qingnode-platform-udp:" + struct.pack("!I", sequence)
                    packet = b"\0\0\0\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target.getsockname()[1]) + payload
                    channel.sendto(packet, (host, relay_port))
                    response, _ = channel.recvfrom(2048)
                    if response[:4] != b"\0\0\0\x01" or response[10:] != payload:
                        raise RuntimeError("UDP sequence or response mismatch")
                if len(received) != 3:
                    raise RuntimeError("controlled UDP target did not observe all requests")
                print("PASS actual selected proxy UDP: three ordered request/response samples", flush=True)
        finally:
            client.terminate()
            try:
                client.wait(timeout=8)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=8)
            target.close()
            thread.join(timeout=6)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--node", default="acceptance-ss")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("QINGNODE_VM_DISPOSABLE") != "1" or not args.work_dir.is_absolute() or not args.work_dir.is_dir():
        parser.error("requires root and a private existing absolute work directory")
    info = args.work_dir.lstat()
    if args.work_dir.resolve() != args.work_dir or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        parser.error("work directory must be root-owned, private and without symlinks")
    observed = properties()
    if observed.get("Manager") not in ("systemd", "openrc") or observed.get("ActiveState") != "active":
        parser.error("requires an actual active supported init controller")
    flow.identity, flow.enabled_state = identity, enabled_state
    node = next(n for n in flow.state()["nodes"] if n["name"] == args.node)
    pid = identity()[0]
    proc_status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    uid = proc_status["Uid"].split()
    if int(uid[1]) == 0:
        raise RuntimeError("proxy service unexpectedly runs as root")
    # Fixed, nonsecret fields from the exact PID later observed under traffic.
    # gcompat can execute a musl loader; recording exe and ambient capability
    # avoids equating a file's getcap output with the running process's rights.
    runtime = {"version": 1, "manager": observed["Manager"], "pid": pid,
               "executable": os.readlink(f"/proc/{pid}/exe"), "uid": [int(v) for v in uid],
               "capabilities": {key: proc_status[key].strip() for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb") if key in proc_status},
               "unprivileged_port_start": int(Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text()),
               "listen_port": node["port"], "tcp_udp_passed": False,
               "public_ingress": "unknown"}
    with flow.running_flow(args.work_dir, node["id"]) as stream:
        flow.unchanged(stream, "platform-rename", lambda: flow.command("qingnode", "edit", "--id", node["id"], "--name", args.node + "-renamed"))
        flow.unchanged(stream, "platform-repeat-apply", lambda: flow.command("qingnode", "apply"))
        flow.unchanged(stream, "platform-name-rollback", lambda: flow.command("qingnode", "rollback"))
    udp_transfer(args.work_dir, node["id"])
    runtime["tcp_udp_passed"] = True
    with (args.work_dir / "flow-runtime.json").open("x") as out:
        json.dump(runtime, out, indent=2)
        out.write("\n")
    print("PASS actual service PID, nonroot TCP stream and UDP; public ingress remains untested", flush=True)


if __name__ == "__main__":
    main()
