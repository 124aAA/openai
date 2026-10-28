#!/usr/bin/env python3
"""Actual managed-service TLS/HY2 acceptance, only on a disposable Linux VM.

Temporary resources are created through QingNode's existing transactions. The
original State must return byte-for-byte; private CA/client files remain in the
private fixture directory. No public CA, insecure TLS or host trust change.
"""
import argparse
import contextlib
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time

ROOT = Path("/var/lib/qingnode")
SCRIPTS = Path(__file__).resolve().parent
HY2_PORT = 444  # SS2022 already owns both TCP and UDP 443; preserve it.
DEADLINE = None


class Failure(RuntimeError):
    pass


def require_private_directory(path):
    if not path.is_absolute() or path.resolve() != path:
        raise Failure("work_directory_must_be_absolute_without_symlinks")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise Failure("work_directory_must_be_root_owned_and_private")


def private_json(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def command(*args, timeout=25):
    if DEADLINE is not None:
        timeout = min(timeout, DEADLINE - time.monotonic())
        if timeout <= 0:
            raise Failure("fixture_time_budget_exhausted")
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Failure("tool_unavailable_or_timeout:" + Path(args[0]).name) from exc
    if result.returncode or len(result.stdout) + len(result.stderr) > 1 << 20:
        # Raw CLI/core output can contain temporary authentication material.
        raise Failure("tool_failed:" + Path(args[0]).name + ":" + str(result.returncode))
    return result.stdout


def trusted_client(config, ca_pem):
    """Apply a fixture-only trust root, preserving the selected proxy path."""
    config = json.loads(json.dumps(config))
    outputs, inputs = config.get("outbounds", []), config.get("inbounds", [])
    if len(outputs) != 1 or outputs[0].get("type") != "hysteria2" or outputs[0].get("detour"):
        raise Failure("client_must_have_only_selected_hy2_without_fallback")
    route = config.get("route", {})
    if route.get("rules") or route.get("final") != outputs[0].get("tag") or not outputs[0].get("tag"):
        raise Failure("client_route_must_select_only_its_hy2_outbound")
    if outputs[0].get("server") != "127.0.0.1" or outputs[0].get("server_port") != HY2_PORT:
        raise Failure("client_endpoint_is_not_the_owned_hy2_listener")
    tls = outputs[0].get("tls", {})
    if tls.get("enabled") is not True or tls.get("server_name") != "localhost" or tls.get("insecure"):
        raise Failure("client_tls_must_verify_the_expected_name")
    if len(inputs) != 1 or inputs[0].get("listen") != "127.0.0.1":
        raise Failure("client_must_listen_only_on_loopback")
    tls["certificate"] = [ca_pem]
    outputs[0]["tls"] = tls
    return config


@contextlib.contextmanager
def export_trust(platform_flow, node_id, ca_pem, work):
    """Reuse the existing transport helpers; only private client output changes."""
    original = platform_flow.flow.command

    def exporting(*args, **kwargs):
        if args[:2] == ("qingnode", "export"):
            if "--id" not in args or args[args.index("--id") + 1] != node_id or "--out" not in args:
                raise Failure("transport_helper_exported_an_unselected_node")
            path = Path(args[args.index("--out") + 1])
            if not path.resolve().is_relative_to(work):
                raise Failure("client_export_escaped_private_fixture")
        result = original(*args, **kwargs)
        if args[:2] == ("qingnode", "export"):
            value = trusted_client(json.loads(path.read_text()), ca_pem)
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
        return result

    platform_flow.flow.command = exporting
    try:
        yield
    finally:
        platform_flow.flow.command = original


def read_state():
    return json.loads((ROOT / "current/state.json").read_bytes())


def owned_resource(state, resource):
    return next((item for item in state.get("certificates", []) if item.get("id") == resource["id"]), None) == resource


def service_security_context(domain, enforcement):
    try:
        return domain.read_text().strip("\x00\n")
    except OSError as error:
        # procfs can expose this path without an active security module.
        if enforcement == "Enforcing":
            raise Failure("enforcing_service_context_unreadable") from error
        return "unavailable:errno=" + str(error.errno)


def managed_process():
    values = {}
    for line in command("qingnode", "service", "status").decode().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in values:
                raise Failure("duplicate_managed_service_property")
            values[key] = value
    pid = int(values.get("MainPID", "0"))
    if values.get("ActiveState") != "active" or pid <= 0:
        raise Failure("managed_core_is_not_active")
    data = dict(line.split(":", 1) for line in Path("/proc", str(pid), "status").read_text().splitlines() if ":" in line)
    import pwd
    expected_uid = pwd.getpwnam("qingnode").pw_uid
    uids = [int(item) for item in data["Uid"].split()]
    if expected_uid == 0 or uids != [expected_uid] * 4:
        raise Failure("managed_core_is_not_running_as_its_nonroot_account")
    domain = Path("/proc", str(pid), "attr/current")
    enforcement = "unavailable"
    if shutil.which("getenforce"):
        enforcement = command("getenforce").decode().strip()
    security_context = service_security_context(domain, enforcement)
    return {"manager": values.get("Manager", "unknown"), "pid": pid, "uids": uids,
            "executable": os.readlink(Path("/proc", str(pid), "exe")),
            "security_context": security_context,
            "selinux_enforcement": enforcement}


def make_certificates(work):
    ca, ca_key = work / "ca.pem", work / "ca.key"
    cert, key = work / "leaf.pem", work / "leaf.key"
    csr, extensions = work / "leaf.csr", work / "leaf-extensions.cnf"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n", encoding="ascii")
    command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "1", "-subj", "/CN=QingNode disposable platform CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca))
    command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(csr))
    command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
            "-set_serial", str(secrets.randbits(120) + 1), "-days", "1", "-extfile", str(extensions), "-out", str(cert))
    command("openssl", "verify", "-CAfile", str(ca), "-verify_hostname", "localhost", str(cert))
    for path in (ca, ca_key, cert, key, csr, extensions):
        path.chmod(0o600)
    return ca, cert, key


@contextlib.contextmanager
def official_client(core, config, directory):
    directory.mkdir(mode=0o700)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = json.loads(json.dumps(config))
    config["inbounds"][0]["listen_port"] = port
    path = directory / "client.json"
    private_json(path, config)
    command(str(core), "check", "-c", str(path))
    with (directory / "client-private.log").open("xb") as output:
        process = subprocess.Popen([str(core), "run", "-c", str(path)], stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 7
            while True:
                if process.poll() is not None:
                    raise Failure("isolated_official_client_exited")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise Failure("isolated_client_listener_timeout")
                    time.sleep(.05)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def https_transfer(platform_flow, core, config, ca, cert, key, work):
    payload = b"qingnode-disposable-managed-hy2-https"
    observed = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append(self.path)
            self.send_response(200 if self.path == "/platform-tls" else 404)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .1}, daemon=True)
    thread.start()
    try:
        with official_client(core, config, work / "https-client") as port:
            connection = platform_flow.flow.socks_connect(port, server.server_address)
            trust = ssl.create_default_context(cafile=str(ca))
            with trust.wrap_socket(connection, server_hostname="localhost") as stream:
                stream.settimeout(4)
                stream.sendall(b"GET /platform-tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                response = bytearray()
                while True:
                    block = stream.recv(4096)
                    if not block:
                        break
                    response.extend(block)
                    if len(response) > 8192:
                        raise Failure("controlled_https_response_exceeded_budget")
            if not bytes(response).startswith(b"HTTP/1.0 200") or bytes(response).split(b"\r\n\r\n", 1)[-1] != payload:
                raise Failure("controlled_https_response_mismatch")
        if observed != ["/platform-tls"]:
            raise Failure("controlled_https_target_did_not_observe_selected_path")
        negative = json.loads(json.dumps(config))
        negative["outbounds"][0]["tls"]["server_name"] = "mismatched.invalid"
        with official_client(core, negative, work / "wrong-sni-client") as port:
            try:
                connection = platform_flow.flow.socks_connect(port, server.server_address)
                connection.settimeout(4)
                trust = ssl.create_default_context(cafile=str(ca))
                with trust.wrap_socket(connection, server_hostname="localhost") as stream:
                    stream.sendall(b"GET /platform-tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    if stream.recv(128):
                        raise Failure("wrong_proxy_certificate_name_was_accepted")
            except (OSError, RuntimeError) as exc:
                if isinstance(exc, Failure):
                    raise
            else:
                # A clean TLS response/EOF after handshake is not evidence that
                # the proxy's deliberately incorrect certificate name failed.
                raise Failure("wrong_proxy_certificate_name_was_accepted")
        if observed != ["/platform-tls"]:
            raise Failure("failed_proxy_tls_reached_https_target")
        return len(response)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main(argv=None):
    global DEADLINE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.environ.get("QINGNODE_VM_DISPOSABLE") != "1" or os.geteuid() != 0:
        parser.error("requires explicit disposable Linux VM, root and QINGNODE_VM_DISPOSABLE=1")
    require_private_directory(args.work_dir)
    if not args.out.is_absolute() or os.path.lexists(args.out):
        parser.error("--out requires a new absolute JSON report path")
    require_private_directory(args.out.parent)
    started = time.monotonic()
    DEADLINE = started + 180
    report = {"version": 1, "kind": "managed-service-private-ca-hy2", "result": "failed",
              "public_ca": "not-used", "public_reachability": "unknown", "tls_verification_bypassed": False,
              "certificate_read_source": "imported PEM in the actual service configuration",
              "actual_core_acme_renewal_write": "not-tested",
              "traffic_scope": "controlled loopback endpoints; encrypted overhead not measured", "checks": []}
    report["time_budget_seconds"] = {"test": 180, "cleanup": 60}
    original = (ROOT / "current/state.json").read_bytes()
    known_node = None
    resource = None
    work = args.work_dir / ("managed-tls-" + secrets.token_hex(6))
    work.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location("platform_flow", SCRIPTS / "test-platform-flow.py")
    platform_flow = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(platform_flow)
    def timeout(*_):
        raise Failure("fixture_time_budget_exhausted")
    previous_alarm = signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, 180)
    try:
        report["step"] = "local-port-and-initial-process"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", HY2_PORT))
        before = read_state()
        managed_process()
        report["step"] = "private-ca-and-leaf"
        ca, cert, key = make_certificates(work)
        resource = {"id": secrets.token_hex(8), "name": "disposable-platform-tls",
                    "certificate": {"mode": "pem", "server_name": "localhost",
                                    "certificate_pem": cert.read_text() + ca.read_text(), "key_pem": key.read_text()}}
        if any(item.get("id") == resource["id"] for item in before.get("certificates", [])):
            raise Failure("temporary_certificate_id_collision")
        request = work / "certificate-request.json"
        private_json(request, {"version": 1, "resource": resource})
        report["step"] = "managed-certificate-import"
        command("qingnode", "certificate", "import", "--file", str(request))
        name = "platform-hy2-" + secrets.token_hex(5)
        report["step"] = "managed-hy2-create"
        command("qingnode", "add", "--protocol", "hysteria2", "--name", name,
                "--server", "127.0.0.1", "--listen", "127.0.0.1", "--port", str(HY2_PORT),
                "--certificate-id", resource["id"], "--quiet")
        state = read_state()
        candidates = [item for item in state["nodes"] if item.get("name") == name and item.get("certificate_id") == resource["id"]]
        if len(candidates) != 1:
            raise Failure("temporary_managed_node_identity_unknown")
        known_node = candidates[0]
        process = managed_process()
        report["managed_core"] = process
        report["managed_hy2_listener"] = {"address": "127.0.0.1", "port": HY2_PORT, "carrier": "udp"}
        core = ROOT / "cores" / state["core_version"] / "sing-box"
        report["step"] = "managed-hy2-tcp-udp"
        with export_trust(platform_flow, known_node["id"], ca.read_text(), work):
            stream_work = work / "tcp-client"
            stream_work.mkdir(mode=0o700)
            with platform_flow.flow.running_flow(stream_work, known_node["id"]) as stream:
                stream.advance(stream.frames)
            report["checks"].append("actual-managed-hy2-authenticated-tcp")
            udp_work = work / "udp-client"
            udp_work.mkdir(mode=0o700)
            platform_flow.udp_transfer(udp_work, known_node["id"])
            report["checks"].append("actual-managed-hy2-three-sequenced-udp-responses")
        exported = work / "https-export.json"
        command("qingnode", "export", "--id", known_node["id"], "--format", "sing-box", "--out", str(exported))
        config = trusted_client(json.loads(exported.read_text()), ca.read_text())
        report["step"] = "verified-https-and-wrong-name"
        report["https_response_bytes"] = https_transfer(platform_flow, core, config, ca, cert, key, work)
        report["checks"].extend(["actual-managed-hy2-verified-https", "wrong-proxy-certificate-name-rejected-without-target-request"])
        if managed_process()["pid"] != process["pid"]:
            raise Failure("managed_core_restarted_during_transport_test")
        report["result"] = "passed"
    except Failure as exc:
        report["error_category"] = str(exc)
    except Exception as exc:
        report["error_category"] = "fixture_exception:" + type(exc).__name__
        if isinstance(exc, OSError):
            report["error_errno"] = exc.errno
    finally:
        DEADLINE = time.monotonic() + 60
        signal.setitimer(signal.ITIMER_REAL, 60)
        cleanup = []
        try:
            state = read_state()
            if known_node is not None:
                current = next((item for item in state["nodes"] if item.get("id") == known_node["id"]), None)
                if current != known_node:
                    raise Failure("temporary_node_changed_refusing_cleanup")
                command("qingnode", "delete", "--id", known_node["id"], "--yes")
            state = read_state()
            if resource is not None and any(item.get("id") == resource["id"] for item in state.get("certificates", [])):
                if not owned_resource(state, resource):
                    raise Failure("temporary_certificate_changed_refusing_cleanup")
                command("qingnode", "certificate", "remove", "--id", resource["id"], "--yes")
        except Exception as exc:
            cleanup.append(str(exc) if isinstance(exc, Failure) else "cleanup_exception:" + type(exc).__name__)
        restored = (ROOT / "current/state.json").read_bytes() == original
        report["state_byte_identical_after_cleanup"] = restored
        report["cleanup_errors"] = cleanup
        report["private_fixture_retained"] = True
        report["duration_seconds"] = round(time.monotonic() - started, 3)
        if cleanup or not restored:
            report["result"] = "failed"
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_alarm)
        DEADLINE = None
        private_json(args.out, report)
        print("managed private-CA HY2 platform transport: " + report["result"], flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
