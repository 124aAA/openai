#!/usr/bin/env python3
"""Opt-in lifecycle checks for QingNode's auxiliary services on a disposable VM.

Uses the actual init controller and real service accounts. The subscription
fixture has no devices or tokens, and its HTTPS origin is deliberately synthetic;
this checks local deployment and permissions, not public HTTPS or client UI.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time

try:
    import pwd
except ImportError:  # Permit read-only fixture contract tests on Windows.
    pwd = None

ROOT = Path("/var/lib/qingnode")
SUB = Path("/var/lib/qingnode-subscription")
PUBLIC = "https://subscription.invalid"
NAMES = ("qingnode-subscription", "qingnode-monitor")


class CheckFailure(RuntimeError):
    """Only fixed, nonsecret messages may cross the evidence boundary."""


def run(*args, expected=0, timeout=45):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout,
                                env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckFailure("command unavailable or timed out: " + args[0]) from exc
    if len(result.stdout) + len(result.stderr) > 256 * 1024:
        raise CheckFailure("command output exceeded fixture budget")
    if expected is not None and result.returncode != expected:
        # Never publish a command's stdout/stderr: it may contain private State.
        operation = " ".join(args[:3] if args[:2] == ("qingnode", "service") else args[:2])
        raise CheckFailure("command failed: " + operation + " (exit=" + str(result.returncode) + ")")
    return result


def fields(raw):
    result = {}
    for line in raw.decode().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in result:
                raise CheckFailure("duplicate service property")
            result[key] = value
    return result


def service(name="qingnode"):
    return fields(run("qingnode", "service", "status", "--name", name).stdout)


def active_pid(name, wanted_uid):
    state = service(name)
    pid = int(state.get("MainPID", "0"))
    if state.get("ActiveState") != "active" or pid < 1:
        raise CheckFailure("managed service has no active child PID")
    values = Path("/proc", str(pid), "status").read_text().split("Uid:", 1)[1].splitlines()[0].split()
    if len(values) != 4 or any(int(value) != wanted_uid for value in values):
        raise CheckFailure("service does not run as its dedicated UID")
    return pid


def private_dir(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise CheckFailure("fixture path must be an absolute real directory")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise CheckFailure("fixture directory must be root-owned and private")
    return path


def atomic_bytes(path, data, mode):
    temporary = path.with_name(path.name + ".platform-candidate-" + secrets.token_hex(4))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def as_user(account, program):
    """Fork and really drop all groups/UIDs; root os.access is not evidence."""
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            program()
        except BaseException:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if status != 0:
        raise CheckFailure("actual service UID permission check failed")


def assert_loopback_listener(pid, port):
    inodes = set()
    for fd in Path("/proc", str(pid), "fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])
    found = []
    for family in ("tcp", "tcp6"):
        for line in Path("/proc", str(pid), "net", family).read_text().splitlines()[1:]:
            items = line.split()
            if items[3] == "0A" and items[9] in inodes:
                found.append((family, items[1]))
    if found != [("tcp", "0100007F:%04X" % port)]:
        raise CheckFailure("subscription listener is not exclusively the expected loopback socket")


def wait_until(predicate, seconds, cause):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.25)
    raise CheckFailure(cause)


def definition_fingerprint(paths):
    """Only deployment files; periodic monitor output is deliberately excluded."""
    result = []
    for path in paths:
        if path.is_symlink():
            raise CheckFailure("fixture refuses a symlink service definition")
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise CheckFailure("service definition is not a regular file")
            result.append((path.name, hashlib.sha256(path.read_bytes()).hexdigest(),
                           stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid))
        except FileNotFoundError:
            result.append((path.name, None))
    return result


def deployment_fingerprint(name, paths):
    evidence = {ROOT / (".auxiliary-" + name + suffix) for suffix in (".journal.json", ".installed.json", ".conflict.json")}
    evidence.update(ROOT.glob(".auxiliary-" + name + ".recovery-*.json"))
    return definition_fingerprint([*paths, *sorted(evidence)])


def assert_definition_permissions(member, kind):
    info = member.stat()
    if member.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != (0o644 if kind == "systemd" else 0o755):
        raise CheckFailure("product auxiliary definition has unexpected ownership or permissions")


def service_transaction(action, name, kind, paths, *, preview=False, public_url=None):
    if action not in ("install", "remove", "recover") or name not in NAMES:
        raise CheckFailure("unknown auxiliary deployment transaction")
    before = deployment_fingerprint(name, paths)
    state_before = (ROOT / "current/state.json").read_bytes()
    args = ["qingnode", "service", action, "--name", name, "--preview" if preview else "--yes"]
    if public_url is not None:
        if action != "install" or name != NAMES[0]:
            raise CheckFailure("public origin is accepted only during subscription install")
        args += ["--public-url", public_url]
    result = run(*args)
    if preview:
        try:
            value = json.loads(result.stdout)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CheckFailure("auxiliary preview did not return valid JSON") from exc
        definitions = value.get("definitions")
        expected_names = {path.name for path in paths}
        valid_members = (isinstance(definitions, list) and all(isinstance(member, str) for member in definitions)
                         and len(set(definitions)) == len(definitions) and set(definitions) <= expected_names)
        if action != "recover":
            valid_members = valid_members and set(definitions) == expected_names
        if (type(value.get("version")) is not int or value.get("version") != 1 or value.get("name") != name or value.get("manager") != kind
                or value.get("action") not in ({action} if action != "recover" else {"recover", "recover-noop", "recover noop"})
                or type(value.get("pending")) is not bool or not valid_members):
            raise CheckFailure("auxiliary preview does not describe the selected deployment")
        if before != deployment_fingerprint(name, paths) or state_before != (ROOT / "current/state.json").read_bytes():
            raise CheckFailure("auxiliary preview changed deployment or State")
        return value
    return result


def install_with_conflict_check(name, kind, paths, *, public_url=None):
    """Create an inert external conflict, never a runnable replacement unit."""
    service_transaction("install", name, kind, paths, preview=True, public_url=public_url)
    before_conflict = deployment_fingerprint(name, paths)
    path = paths[0]
    external = b"# External disposable conflict fixture; not managed by QingNode\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(external)
    try:
        command = ["qingnode", "service", "install", "--name", name, "--yes"]
        if public_url:
            command += ["--public-url", public_url]
        rejected = run(*command, expected=None).returncode != 0
        if not rejected or path.read_bytes() != external or any(p.exists() for p in paths[1:]):
            raise CheckFailure("installation accepted or damaged an external definition")
    finally:
        # Delete only the exact inert file this fault probe created.
        if path.is_symlink() or path.read_bytes() != external:
            raise CheckFailure("external conflict fixture changed; refusing cleanup")
        path.unlink()
    if deployment_fingerprint(name, paths) != before_conflict:
        raise CheckFailure("refused installation changed managed recovery materials")
    service_transaction("install", name, kind, paths, public_url=public_url)
    for member in paths:
        assert_definition_permissions(member, kind)
    state = service(name)
    if state.get("ActiveState") != "inactive" or state.get("UnitFileState") != "disabled":
        raise CheckFailure("new auxiliary deployment did not remain stopped and disabled")
    return {path: path.read_bytes() for path in paths}


def reject_modified_remove(name, path, contents, kind, expected_pid=None, expected_uid=None):
    injected = contents + b"\n# external edit fixture\n"
    atomic_bytes(path, injected, 0o644 if kind == "systemd" else 0o755)
    try:
        result = run("qingnode", "service", "remove", "--name", name, "--yes", expected=None)
        if result.returncode == 0 or path.read_bytes() != injected:
            raise CheckFailure("remove accepted or damaged an externally modified deployment")
        if expected_pid is not None:
            # The modified definition intentionally makes product control refuse
            # ownership. Read /proc directly instead of asking it to take over.
            values = Path("/proc", str(expected_pid), "status").read_text().split("Uid:", 1)[1].splitlines()[0].split()
            if any(int(value) != expected_uid for value in values):
                raise CheckFailure("refused remove disturbed the running auxiliary child")
    finally:
        if path.is_symlink() or path.read_bytes() != injected:
            raise CheckFailure("external edit changed; refusing fixture restore")
        atomic_bytes(path, contents, 0o644 if kind == "systemd" else 0o755)


def stop_fixture_cli_group(process, sig):
    """Signal only the fresh session this fixture created, never an init child."""
    if process.poll() is not None:
        return False
    try:
        if os.getpgid(process.pid) != process.pid:
            raise CheckFailure("fixture CLI is not in its own process group")
        os.killpg(process.pid, sig)
        return True
    except ProcessLookupError:
        return False


def interrupt_subscription_remove(kind, paths, account, core_uid):
    """Interrupt a real prepared transaction; never manufacture recovery input."""
    name = NAMES[0]
    pending = ROOT / (".auxiliary-" + name + ".journal.json")
    if pending.exists() or pending.is_symlink():
        raise CheckFailure("interrupt probe requires no prior auxiliary journal")
    state_before = (ROOT / "current/state.json").read_bytes()
    stable_paths = [*paths, ROOT / (".auxiliary-" + name + ".installed.json")]
    definitions_before = definition_fingerprint(stable_paths)
    native_before = service(name)
    subscription_pid = active_pid(name, account.pw_uid)
    subscription_group = os.getpgid(subscription_pid)
    core_pid = active_pid("qingnode", core_uid)
    if native_before.get("UnitFileState") != "enabled":
        raise CheckFailure("interrupt probe requires an explicitly enabled subscription")
    process = subprocess.Popen(["qingnode", "service", "remove", "--name", name, "--yes"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True,
                               env={**os.environ, "LC_ALL": "C"})
    captured = False
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and process.poll() is None:
            if pending.exists():
                if subscription_group == process.pid:
                    raise CheckFailure("init-managed subscription unexpectedly shares fixture CLI group")
                if not stop_fixture_cli_group(process, signal.SIGSTOP):
                    break
                info = pending.lstat()
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != 0 or info.st_nlink != 1 or info.st_size > 2 * 1024 * 1024):
                    raise CheckFailure("interrupted transaction journal is not a private managed file")
                try:
                    journal = json.loads(pending.read_bytes())
                except (OSError, ValueError) as exc:
                    raise CheckFailure("real interrupted journal is unreadable") from exc
                captured = journal.get("phase") == "prepared" and journal.get("action") == "remove"
                break
            time.sleep(.0005)
    finally:
        stop_fixture_cli_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise CheckFailure("interrupted fixture CLI process group did not exit") from exc
    if not captured or not pending.exists():
        raise CheckFailure("actual prepared auxiliary transaction was not captured; no recovery proof claimed")
    preview = service_transaction("recover", name, kind, paths, preview=True)
    if preview.get("pending") is not True:
        raise CheckFailure("actual interrupted transaction was not shown by recovery preview")
    service_transaction("recover", name, kind, paths)
    after = service(name)
    if (pending.exists() or after.get("ActiveState") != "active"
            or after.get("UnitFileState") != native_before.get("UnitFileState")
            or definitions_before != definition_fingerprint(stable_paths)
            or state_before != (ROOT / "current/state.json").read_bytes()
            or active_pid("qingnode", core_uid) != core_pid):
        raise CheckFailure("actual interrupted recovery did not preserve service state, definition or proxy")
    active_pid(name, account.pw_uid)
    return "actual-prepared-cli-process-group-interrupted-and-product-recovered"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True,
                        help="new JSON evidence file outside the private fixture")
    parser.add_argument("--node", default="acceptance-ss")
    parser.add_argument("--recover-pending-only", choices=NAMES,
                        help="explicit separate recovery proof; requires a real pending transaction from an interrupted prior CLI")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("QINGNODE_VM_DISPOSABLE") != "1":
        parser.error("requires Linux root and QINGNODE_VM_DISPOSABLE=1 on a disposable VM")
    work = private_dir(args.work_dir)
    if not args.out.is_absolute() or args.out.exists() or args.out.is_symlink() or not args.out.parent.is_dir():
        parser.error("--out must name a new absolute JSON file in an existing evidence directory")
    report = {"version": 1, "scope": "disposable-vm-actual-init", "result": "failed",
              "checks": [], "public_https": "not-tested", "tls_protocol_transfer": "not-tested",
              "reboot_autostart": "not-tested", "fixture_origin": PUBLIC,
              "deployment_transactions": "product-cli", "interrupted_transaction_recovery": "not-tested-no-pending-transaction"}
    owned = {}
    installed = []
    subscription_ready = False
    monitor_ready = False
    stopped_core = False
    created_user = False
    state_path = ROOT / "current/state.json"
    state_before = state_path.read_bytes()
    state_hash = hashlib.sha256(state_before).hexdigest()
    sub_account = None
    kind = service().get("Manager")
    if kind not in ("systemd", "openrc"):
        raise CheckFailure("actual supported init controller is unavailable")
    report["manager"] = kind
    directory = Path("/etc/systemd/system" if kind == "systemd" else "/etc/init.d")
    definitions = [directory / (name + ".service" if kind == "systemd" else name) for name in NAMES]
    timer = directory / "qingnode-monitor.timer" if kind == "systemd" else None
    members = {NAMES[0]: [definitions[0]], NAMES[1]: [definitions[1]] + ([timer] if timer else [])}
    if args.recover_pending_only:
        name = args.recover_pending_only
        pending = ROOT / (".auxiliary-" + name + ".journal.json")
        if not pending.is_file() or pending.is_symlink():
            raise CheckFailure("explicit recovery proof requires a real existing pending auxiliary transaction")
        value = service_transaction("recover", name, kind, members[name], preview=True)
        if value.get("pending") is not True:
            raise CheckFailure("recovery preview did not identify a pending transaction")
        service_transaction("recover", name, kind, members[name])
        if pending.exists() or state_path.read_bytes() != state_before:
            raise CheckFailure("explicit auxiliary recovery left pending transaction or changed State")
        report.update(result="passed", interrupted_transaction_recovery="actual-pending-transaction-recovered",
                      scope="separate-explicit-pending-recovery; not the full auxiliary lifecycle", checks=["explicit-product-cli-pending-recovery-state-preserved"])
        data = json.dumps(report, indent=2).encode() + b"\n"
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        return 0
    reserved = [SUB, ROOT / "subscription-publisher.json", ROOT / "monitor", *definitions]
    reserved += [ROOT / (".auxiliary-" + name + suffix) for name in NAMES for suffix in (".journal.json", ".installed.json")]
    if timer:
        reserved.append(timer)
    if any(path.exists() or path.is_symlink() for path in reserved):
        raise CheckFailure("refusing an existing auxiliary deployment or configuration")
    try:
        with socket.socket() as port:
            port.bind(("127.0.0.1", 8389))
        proxy = pwd.getpwnam("qingnode")
        if proxy.pw_uid == 0:
            raise CheckFailure("proxy account is root")
        original_core_pid = active_pid("qingnode", proxy.pw_uid)
        cert_probe = ROOT / "acme" / (".platform-permission-" + secrets.token_hex(8))

        def certificate_permissions():
            cert_probe.mkdir(mode=0o700)
            try:
                cert, key = cert_probe / "cert.pem", cert_probe / "key.pem"
                result = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                                         "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                                         "-keyout", str(key), "-out", str(cert)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                if result.returncode:
                    raise CheckFailure("certificate fixture creation failed")
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key)
                for path in (cert, key):
                    path.unlink()
            finally:
                cert_probe.rmdir()

        as_user(proxy, certificate_permissions)
        report["checks"].append("proxy-nonroot-certificate-storage-uid-read-write")
        try:
            sub_account = pwd.getpwnam("qingnode-sub")
        except KeyError:
            if kind == "openrc":
                run("addgroup", "-S", "qingnode-sub")
                run("adduser", "-S", "-D", "-H", "-s", "/sbin/nologin", "-G", "qingnode-sub", "qingnode-sub")
            else:
                shell = "/usr/sbin/nologin" if Path("/usr/sbin/nologin").exists() else "/sbin/nologin"
                run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", shell, "qingnode-sub")
            created_user = True
            sub_account = pwd.getpwnam("qingnode-sub")
        if sub_account.pw_uid in (0, proxy.pw_uid):
            raise CheckFailure("subscription must have an independent nonroot UID")
        run("qingnode", "subscription", "init", "--dir", str(SUB), "--gid", str(sub_account.pw_gid), "--formats", "sing-box")
        subscription_ready = True
        run("qingnode", "subscription", "publish")

        def subscription_permissions():
            (SUB / "snapshot.json").read_bytes()
            try:
                state_path.read_bytes()
            except PermissionError:
                return
            raise CheckFailure("subscription account can read root State")

        as_user(sub_account, subscription_permissions)
        report["checks"].append("subscription-snapshot-readable-state-denied-under-real-uid")
        owned.update(install_with_conflict_check(NAMES[0], kind, members[NAMES[0]], public_url=PUBLIC))
        installed.append(NAMES[0])
        report["checks"].append("subscription-product-install-preview-conflict-refusal-stopped-disabled")
        def sub_control(action, expected=0):
            return run("qingnode", "service", action, "--name", NAMES[0], "--public-url", PUBLIC, expected=expected)
        sub_control("enable")
        sub_control("start")
        sub_pid = active_pid(NAMES[0], sub_account.pw_uid)
        assert_loopback_listener(sub_pid, 8389)
        for token in (None, "0" * 64):
            connection = http.client.HTTPConnection("127.0.0.1", 8389, timeout=3)
            try:
                connection.request("GET", "/s/sing-box", headers={} if token is None else {"Authorization": "Bearer " + token})
                response = connection.getresponse()
                if response.status != 404 or response.getheader("Cache-Control") != "private, no-store, max-age=0":
                    raise CheckFailure("unauthorized subscription request was accepted or cacheable")
                if len(response.read(1025)) > 1024:
                    raise CheckFailure("unauthorized response exceeded budget")
            finally:
                connection.close()
        path = definitions[0]
        reject_modified_remove(NAMES[0], path, owned[path], kind, sub_pid, sub_account.pw_uid)
        if active_pid(NAMES[0], sub_account.pw_uid) != sub_pid:
            raise CheckFailure("refused modified remove disturbed the subscription child")
        report["checks"].append("subscription-actual-nonroot-loopback-auth-rejection-and-ownership")
        report["checks"].append("subscription-product-remove-refuses-external-edit")
        recovery = service_transaction("recover", NAMES[0], kind, members[NAMES[0]], preview=True)
        if recovery.get("pending") is not False:
            raise CheckFailure("healthy deployment unexpectedly has pending recovery")
        service_transaction("recover", NAMES[0], kind, members[NAMES[0]])
        if active_pid(NAMES[0], sub_account.pw_uid) != sub_pid:
            raise CheckFailure("no-op recover restarted the subscription child")
        report["checks"].append("explicit-recover-no-pending-is-noop")
        report["interrupted_transaction_recovery"] = interrupt_subscription_remove(kind, members[NAMES[0]], sub_account, proxy.pw_uid)
        report["checks"].append("actual-interrupted-subscription-remove-explicit-recovery")

        state = json.loads(state_before)
        node = next((node for node in state["nodes"] if args.node in (node["id"], node["name"])), None)
        if node is None:
            raise CheckFailure("fixture node does not exist")
        config = {"version": 1, "enabled": True, "interval_seconds": 15, "timeout_ms": 3000,
                  "concurrency": 1, "max_bytes": 1024, "jobs": [{"id": "platform-observation", "node_id": node["id"],
                  "enabled": True, "signals": ["process"]}], "recovery": {"mode": "observe"},
                  "notifications": {"enabled": False}}
        config_path = work / "platform-monitor.json"
        atomic_bytes(config_path, json.dumps(config).encode(), 0o600)
        run("qingnode", "monitor", "configure", "--file", str(config_path), "--yes")
        monitor_ready = True
        owned.update(install_with_conflict_check(NAMES[1], kind, members[NAMES[1]]))
        installed.append(NAMES[1])
        report["checks"].append("monitor-product-install-preview-conflict-refusal-stopped-disabled")
        run("qingnode", "service", "enable", "--name", NAMES[1])
        run("qingnode", "service", "start", "--name", NAMES[1])
        if kind == "systemd":
            run("systemctl", "is-enabled", "--quiet", "qingnode-monitor.timer")
            run("systemctl", "is-active", "--quiet", "qingnode-monitor.timer")
        else:
            active_pid(NAMES[1], 0)
        status_path = ROOT / "monitor/status.json"
        def snapshot():
            try:
                return json.loads(status_path.read_bytes())
            except (FileNotFoundError, json.JSONDecodeError):
                return {}
        wait_until(lambda: bool(snapshot().get("finished_at")), 15, "monitor initial actual service round did not complete")
        monitor_definition = timer if timer else definitions[1]
        monitor_pid = active_pid(NAMES[1], 0) if kind == "openrc" else None
        reject_modified_remove(NAMES[1], monitor_definition, owned[monitor_definition], kind, monitor_pid, 0)
        if any(path.read_bytes() != owned[path] for path in members[NAMES[1]]):
            raise CheckFailure("refused monitor remove changed another member of the deployment")
        if kind == "systemd":
            run("systemctl", "is-active", "--quiet", "qingnode-monitor.timer")
        report["checks"].append("monitor-product-remove-refuses-external-edit-and-preserves-pair")
        for name in NAMES:
            run("qingnode", "service", "logs", "--name", name, "--lines", "5")
        report["checks"].append("product-auxiliary-native-logs-readable")
        if active_pid("qingnode", proxy.pw_uid) != original_core_pid:
            raise CheckFailure("auxiliary deployment restarted the unrelated proxy core")
        before_stop = snapshot()["finished_at"]
        run("qingnode", "stop")
        stopped_core = True
        def observed_stop():
            status = snapshot()
            return status.get("finished_at") != before_stop and any(job.get("observation", {}).get("manual_stopped") for job in status.get("jobs", []))
        wait_until(observed_stop, 90 if kind == "systemd" else 25, "actual periodic scheduler did not observe manually stopped core")
        if service().get("ActiveState") != "inactive" or snapshot().get("actions"):
            raise CheckFailure("observation monitor restarted manually stopped core or attempted recovery")
        report["checks"].append("actual-periodic-observation-respects-manual-stop")
        run("qingnode", "start")
        stopped_core = False
        active_pid("qingnode", proxy.pw_uid)
        if hashlib.sha256(state_path.read_bytes()).hexdigest() != state_hash:
            raise CheckFailure("auxiliary lifecycle changed proxy State")
        report["checks"].append("proxy-state-byte-identical")
        report["result"] = "passed"
    except CheckFailure as exc:
        report["error"] = str(exc)
    except Exception:
        report["error"] = "unexpected fixture failure; private VM materials retained for diagnosis"
    finally:
        cleanup_errors = []
        if monitor_ready:
            try:
                run("qingnode", "monitor", "disable", "--yes")
            except CheckFailure:
                cleanup_errors.append("monitor-plan-disable-failed")
        for name in reversed(installed):
            try:
                if any(path.read_bytes() != owned[path] for path in members[name]):
                    raise CheckFailure("definition changed outside fixture")
                service_transaction("remove", name, kind, members[name], preview=True)
                service_transaction("remove", name, kind, members[name])
                if any(path.exists() or path.is_symlink() for path in members[name]):
                    raise CheckFailure("product auxiliary remove left managed definitions")
                report["checks"].append(name + "-product-remove-complete")
            except (CheckFailure, OSError):
                cleanup_errors.append(name + "-remove-failed")
        if stopped_core:
            try:
                run("qingnode", "start")
            except CheckFailure:
                cleanup_errors.append("proxy-start-restore-failed")
        try:
            if state_path.read_bytes() != state_before:
                cleanup_errors.append("proxy-state-changed-during-product-remove")
        except OSError:
            cleanup_errors.append("proxy-state-unavailable-after-product-remove")
        # Account and private publication/monitor material are retained as owned
        # fixture evidence until the parent acceptance performs its normal purge.
        report["fixture_account_created"] = created_user
        report["private_material_retained"] = bool(subscription_ready or monitor_ready)
        report["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            report["result"] = "failed"
        data = json.dumps(report, indent=2).encode() + b"\n"
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        print("platform auxiliary lifecycle: " + report["result"], flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
