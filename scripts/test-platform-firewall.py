#!/usr/bin/env python3
"""Real firewalld/SELinux acceptance, restricted to an explicit disposable VM.

exercise runs immediately before QingNode's final purge. verify-after-uninstall
runs after purge; cleanup then retracts only this script's exact sentinel assets.
This checks real runtime/permanent rules, not packet filtering on an external
path. Private recovery data belongs in --work-dir; reports contain no State.
"""
import argparse
from datetime import datetime, timezone
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys


FORMAT = 1
JOURNAL = "platform-firewall-private.json"
MARKER = "qingnode-platform-firewall-acceptance-v1"
PRODUCT_ASSETS = (Path("/etc/firewalld/services/qingnode-managed.xml"),
                  Path("/etc/firewalld/services/.qingnode-managed.json"))


class Failure(RuntimeError):
    pass


def stamp():
    return datetime.now(timezone.utc).isoformat()


def run(*args):
    """Keep raw tool output private, especially add output and authentication."""
    try:
        p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Failure("tool_unavailable_or_timeout:" + Path(args[0]).name) from e
    if p.returncode:
        raise Failure("tool_failed:" + Path(args[0]).name + ":exit=" + str(p.returncode))
    if len(p.stdout) > 1 << 20 or len(p.stderr) > 1 << 20:
        raise Failure("tool_output_limit:" + Path(args[0]).name)
    return p.stdout.decode("utf-8", errors="strict").strip()


def safe_directory(path, private):
    if not path.is_absolute() or path.resolve() != path:
        raise Failure("directory_must_be_absolute_without_symlinks")
    info = path.lstat()
    forbidden = 0o077 if private else 0o022
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & forbidden:
        raise Failure("directory_owner_or_permissions_invalid")


def read_private(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o077 or info.st_size > 1 << 20):
        raise Failure("private_recovery_file_invalid")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if temporary.exists():
            temporary.unlink()


def fw_args(zone, permanent, *args):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", zone):
        raise Failure("invalid_firewalld_zone")
    return ("firewall-cmd",) + (("--permanent",) if permanent else ()) + ("--zone=" + zone,) + args


def lists(zone):
    return [sorted(set(run(*fw_args(zone, permanent, "--list-rich-rules")).splitlines()))
            for permanent in (False, True)]


def change(zone, permanent, rule, add):
    # No reload, flush, zone change, interface assignment or runtime-to-permanent.
    verb = "--add-rich-rule=" if add else "--remove-rich-rule="
    run(*fw_args(zone, permanent, verb + rule))
    actual = lists(zone)[int(permanent)]
    if (rule in actual) != add:
        raise Failure("sentinel_rule_readback_mismatch")


def require_environment():
    if run("getenforce") != "Enforcing":
        raise Failure("selinux_is_not_enforcing")
    if run("firewall-cmd", "--state") != "running":
        raise Failure("firewalld_is_not_running")
    zone = run("firewall-cmd", "--get-default-zone")
    fw_args(zone, False)
    active = run("firewall-cmd", "--get-active-zones")
    if any(line and not line[0].isspace() and line.strip() != zone for line in active.splitlines()):
        raise Failure("nondefault_active_zone_requires_manual_test")
    return zone, active


def current_state():
    path = Path("/var/lib/qingnode/current/state.json")
    if path.stat().st_size > 8 << 20:
        raise Failure("state_exceeds_test_limit")
    return json.loads(path.read_text(encoding="utf-8"))


def expected_rules(nodes):
    result = set()
    for node in nodes:
        address = ipaddress.ip_address(node["listen"])
        families = ["ipv4"] if address.version == 4 else ["ipv4", "ipv6"]
        if not address.is_unspecified or node["protocol"] != "ss2022":
            raise Failure("unexpected_fixture_node")
        for family in families:
            for transport in ("tcp", "udp"):
                result.add('rule family="' + family + '" port port="' + str(node["port"])
                           + '" protocol="' + transport + '" accept')
    return sorted(result)


def free_port(family):
    # A reservation is released before Apply, whose real binding precheck is
    # authoritative if another process wins the race.
    try:
        with socket.socket(family, socket.SOCK_STREAM) as tcp:
            if family == socket.AF_INET6:
                tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            address = "0.0.0.0" if family == socket.AF_INET else "::"
            tcp.bind((address, 0))
            port = tcp.getsockname()[1]
            with socket.socket(family, socket.SOCK_DGRAM) as udp:
                if family == socket.AF_INET6:
                    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                udp.bind((address, port))
            return port
    except OSError as error:
        if family == socket.AF_INET6 and error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.EPROTONOSUPPORT):
            raise Failure("ipv6_listener_unavailable_not_validated") from error
        raise


def sentinel_xml(token):
    return ('<?xml version="1.0" encoding="utf-8"?>\n<service><short>' + MARKER
            + '</short><description>Disposable test sentinel ' + token + '</description></service>\n').encode()


def validate_journal(value):
    if (not isinstance(value, dict) or value.get("version") != FORMAT
            or value.get("owner") != MARKER or not re.fullmatch(r"[a-f0-9]{16}", value.get("token", ""))):
        raise Failure("unknown_private_recovery_format")
    token = value["token"]
    if value.get("xml_path") != "/etc/firewalld/services/qingnode-test-" + token + ".xml":
        raise Failure("sentinel_asset_path_not_owned")
    if value.get("rule") != 'rule family="ipv4" source address="192.0.2.250/32" port port="' + str(value.get("port")) + '" protocol="tcp" reject':
        raise Failure("sentinel_rule_not_owned")
    if type(value.get("port")) is not int or not 1024 <= value["port"] <= 65535:
        raise Failure("invalid_sentinel_port")
    fw_args(value["zone"], False)
    return value


def preserved(fixture, with_product=False):
    zone, active = require_environment()
    if zone != fixture["zone"] or active != fixture["active_zones"]:
        raise Failure("host_zone_policy_changed")
    path = Path(fixture["xml_path"])
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
        raise Failure("foreign_sentinel_file_changed")
    if path.read_bytes() != sentinel_xml(fixture["token"]):
        raise Failure("foreign_sentinel_content_changed")
    actual = lists(zone)
    wanted = []
    for before in fixture["before"]:
        wanted.append(sorted(set(before + [fixture["rule"]] + (fixture.get("product_rules", []) if with_product else []))))
    if actual != wanted:
        raise Failure("runtime_or_permanent_policy_not_preserved")


def exercise(args, report):
    zone, active = require_environment()
    journal = args.work_dir / JOURNAL
    if journal.exists() or any(path.exists() for path in PRODUCT_ASSETS):
        raise Failure("refusing_existing_fixture_or_project_firewall_assets")
    state = current_state()
    if state.get("firewall") or state.get("forwards") or state.get("egresses"):
        raise Failure("test_requires_manual_firewall_and_simple_loopback_fixture")
    for node in state["nodes"]:
        if node["enabled"] and not ipaddress.ip_address(node["listen"]).is_loopback:
            raise Failure("test_requires_existing_loopback_nodes")
    token = secrets.token_hex(8)
    port = free_port(socket.AF_INET)
    rule = 'rule family="ipv4" source address="192.0.2.250/32" port port="' + str(port) + '" protocol="tcp" reject'
    fixture = {"version": FORMAT, "owner": MARKER, "token": token, "zone": zone,
               "active_zones": active, "before": lists(zone), "port": port,
               "xml_path": "/etc/firewalld/services/qingnode-test-" + token + ".xml",
               "rule": rule, "node_names": [], "stage": "prepared", "created_at": stamp()}
    if any(rule in before for before in fixture["before"]):
        raise Failure("refusing_preexisting_sentinel_rule")
    write_json(journal, fixture)
    report["step"] = "foreign_sentinel"
    fd = os.open(fixture["xml_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(sentinel_xml(token))
        f.flush()
        os.fsync(f.fileno())
    for permanent in (False, True):
        change(zone, permanent, rule, True)
    fixture["stage"] = "sentinel_installed"
    write_json(journal, fixture)
    report["step"] = "actual_wildcard_nodes"
    for index, family, address in ((4, socket.AF_INET, "0.0.0.0"), (6, socket.AF_INET6, "::")):
        name = "platform-firewall-" + token + "-v" + str(index)
        fixture["node_names"].append(name)
        write_json(journal, fixture)
        run(args.qingnode, "add", "--protocol", "ss2022", "--name", name,
            "--server", "127.0.0.1", "--listen", address, "--port", str(free_port(family)), "--quiet")
    after = current_state()
    nodes = [node for node in after["nodes"] if node["name"] in fixture["node_names"]]
    if len(nodes) != 2:
        raise Failure("fixture_nodes_missing")
    fixture["product_rules"] = expected_rules(nodes)
    fixture["stage"] = "nodes_created"
    write_json(journal, fixture)
    report["step"] = "enable_readback"
    run(args.qingnode, "firewall", "enable", "--backend", "firewalld")
    preserved(fixture, with_product=True)
    receipt = read_private(PRODUCT_ASSETS[1])
    if (receipt.get("version") != 1 or receipt.get("pending") or receipt.get("zone") != zone
            or receipt.get("rules") != fixture["product_rules"]):
        raise Failure("product_receipt_mismatch")
    report["step"] = "disable_readback"
    run(args.qingnode, "firewall", "disable")
    preserved(fixture)
    if any(path.exists() for path in PRODUCT_ASSETS):
        raise Failure("disabled_project_assets_not_removed")
    report["step"] = "reenable_for_uninstall"
    run(args.qingnode, "firewall", "enable", "--backend", "firewalld")
    preserved(fixture, with_product=True)
    fixture["stage"] = "awaiting_uninstall"
    write_json(journal, fixture)
    report.update({"rule_readback": "passed", "disable_cleanup": "passed",
                   "uninstall_cleanup": "pending", "families": ["ipv4", "ipv6"],
                   "transports": ["tcp", "udp"], "managed_rule_count": len(fixture["product_rules"]),
                   "selinux": "Enforcing", "packet_filter_path": "unknown"})


def verify_after_uninstall(args, report):
    journal = args.work_dir / JOURNAL
    fixture = validate_journal(read_private(journal))
    if fixture.get("stage") != "awaiting_uninstall":
        raise Failure("fixture_not_ready_for_uninstall_verification")
    if any(path.exists() for path in PRODUCT_ASSETS) or Path("/var/lib/qingnode").exists():
        raise Failure("project_purge_not_complete")
    preserved(fixture)
    fixture["stage"] = "uninstall_verified"
    write_json(journal, fixture)
    report.update({"uninstall_cleanup": "passed", "foreign_assets_preserved": "passed",
                   "selinux": "Enforcing", "packet_filter_path": "unknown"})


def cleanup(args, report):
    journal = args.work_dir / JOURNAL
    fixture = validate_journal(read_private(journal))
    if fixture.get("stage") not in ("uninstall_verified", "cleanup_pending"):
        raise Failure("uninstall_must_be_verified_before_sentinel_cleanup")
    if fixture["stage"] == "uninstall_verified":
        preserved(fixture)
    fixture["stage"] = "cleanup_pending"
    write_json(journal, fixture)
    zone, active = require_environment()
    if zone != fixture["zone"] or active != fixture["active_zones"]:
        raise Failure("host_zone_policy_changed")
    for permanent in (False, True):
        actual = lists(zone)[int(permanent)]
        if fixture["rule"] in actual:
            change(zone, permanent, fixture["rule"], False)
    path = Path(fixture["xml_path"])
    if os.path.lexists(path):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or path.read_bytes() != sentinel_xml(fixture["token"])):
            raise Failure("sentinel_modified_refusing_cleanup")
        path.unlink()
    if lists(zone) != fixture["before"]:
        raise Failure("cleanup_did_not_restore_baseline_rules")
    fixture["stage"] = "cleaned"
    write_json(journal, fixture)
    report.update({"test_fixture_cleanup": "passed", "host_policy": "preserved",
                   "selinux": "Enforcing", "packet_filter_path": "unknown"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("exercise", "verify-after-uninstall", "cleanup"), required=True)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--qingnode", default="qingnode")
    args = parser.parse_args()
    if sys.platform != "linux" or not args.disposable or os.environ.get("QINGNODE_VM_DISPOSABLE") != "1" or os.geteuid() != 0:
        parser.error("requires explicit disposable Linux VM, root and QINGNODE_VM_DISPOSABLE=1")
    if not args.out.is_absolute() or os.path.lexists(args.out):
        parser.error("--out requires a new absolute report path")
    safe_directory(args.out.parent, False)
    report = {"version": FORMAT, "kind": "qingnode-platform-firewall-acceptance", "phase": args.phase,
              "started_at": stamp(), "measurement_location": "disposable VM server",
              "packet_filter_path": "unknown", "public_reachability": "unknown", "status": "failed"}
    result = 1
    try:
        safe_directory(args.work_dir, True)
        {"exercise": exercise, "verify-after-uninstall": verify_after_uninstall,
         "cleanup": cleanup}[args.phase](args, report)
        report["status"] = "passed"
        result = 0
    except (Failure, OSError, ValueError, KeyError) as e:
        # A bounded category, never raw captured command output, State or tokens.
        report["error_category"] = str(e) if isinstance(e, Failure) else type(e).__name__
    report["finished_at"] = stamp()
    write_json(args.out, report)
    print(json.dumps(report, sort_keys=True))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
