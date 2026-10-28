#!/usr/bin/env python3
"""Bounded final performance evidence using the existing probe engine and CLI.

Only explicitly selected local binaries are run. The real CLI fixture uses
controlled loopback HTTPS/sequence-UDP and an isolated official SS2022 server.
Optional HY2 netem reuses the existing disposable netns/cgroup acceptance.
No production State, service, system proxy, default route or sysctl is changed.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
MAX_FILE = 2 << 20
CLI_REPORTS = ("direct-control", "proxy-baseline", "proxy-repeat", "wrong-credential", "proxy-stopped")
NETEM_REPORTS = ("baseline", "delay-loss-rate", "udp-filtered", "memory-128MiB")


class AcceptanceFailure(RuntimeError):
    """Fixed messages only; never echo private command output."""


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def binary(path, digest):
    path = Path(path)
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_size > 256 << 20 or re.fullmatch("[0-9a-f]{64}", digest or "") is None):
        raise AcceptanceFailure("explicit regular binary and lowercase SHA256 required")
    if sha(path) != digest:
        raise AcceptanceFailure("selected binary SHA256 differs")
    return path


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as out:
        json.dump(value, out, indent=2, ensure_ascii=False)
        out.write("\n")


def strict_json(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise AcceptanceFailure("bounded regular evidence file required")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise AcceptanceFailure("duplicate evidence field")
            value[key] = item
        return value
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(AcceptanceFailure("nonfinite evidence")))


def summarize_report(path):
    """Projection only; the Go test calls ReadReport/ValidateReport first."""
    report = strict_json(path)
    if report.get("version") not in (1, 2) or report.get("source") != "qingnode-automatic-probe":
        raise AcceptanceFailure("unsupported standard probe report")
    condition = report.get("conditions", {})
    if condition.get("path") not in ("client-proxy", "controlled-link"):
        raise AcceptanceFailure("unexpected controlled measurement path")
    payload_limit = condition.get("limits", {}).get("max_payload_bytes")
    if type(payload_limit) is not int or not 1 <= payload_limit <= 2 << 20:
        raise AcceptanceFailure("controlled payload budget exceeds fixed fixture")
    if len(report.get("samples", [])) > 64:
        raise AcceptanceFailure("controlled sample count exceeds fixed fixture")
    return {key: report.get(key) for key in ("version", "started_at", "finished_at", "status", "conditions", "dns", "connection", "tls",
                                           "statistics", "udp", "metrics_before", "metrics_after", "traffic", "limitations")}


def inspect_test_log(path, expected):
    info = Path(path).stat()
    if info.st_size > 8 << 20:
        raise AcceptanceFailure("test output exceeded evidence budget")
    events = [json.loads(line) for line in Path(path).read_bytes().splitlines() if line]
    tested = [event for event in events if event.get("Test") == expected]
    status = [event.get("Action") for event in tested if event.get("Action") in ("pass", "skip", "fail")]
    if status != ["pass"] or any(event.get("Action") == "fail" for event in events):
        raise AcceptanceFailure("actual acceptance test did not pass")
    return [{"test": event["Test"], "reason": "explicit environment capability unavailable"}
            for event in events if event.get("Action") == "skip" and "Test" in event]


def execute_case(go, label, package, test, environment, output, timeout):
    log = output / (label + "-test.jsonl")
    command = [str(go), "test", "-count=1", "-json", "-run", "^" + test + "$", "-timeout=" + str(timeout) + "s", package]
    with log.open("xb") as stream:
        try:
            result = subprocess.run(command, cwd=REPO, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=timeout + 30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AcceptanceFailure("acceptance tool unavailable or total deadline exceeded") from exc
    if result.returncode:
        raise AcceptanceFailure("actual acceptance command returned nonzero; private evidence retained")
    return {"exit_code": result.returncode, "log_sha256": sha(log), "skips": inspect_test_log(log, test)}


def run(args):
    if sys.platform != "linux" or not args.disposable:
        raise AcceptanceFailure("explicit disposable Linux environment required")
    if args.with_netem and (os.geteuid() != 0 or os.environ.get("QINGNODE_VM_DISPOSABLE") != "1"):
        raise AcceptanceFailure("HY2 shaping requires root and explicit disposable VM marker")
    core, probe = binary(args.core, args.core_sha256), binary(args.probe, args.probe_sha256)
    output = Path(args.out)
    if not output.is_absolute() or output.is_symlink() or output.exists():
        raise AcceptanceFailure("new absolute output directory required")
    if not output.parent.is_dir() or output.parent.is_symlink() or output.parent.resolve() != output.parent:
        raise AcceptanceFailure("output parent must be an existing real directory")
    go = Path(args.go or shutil.which("go") or "")
    if not go.is_absolute() or not go.is_file():
        raise AcceptanceFailure("explicit or PATH-resolved Go tool required for acceptance fixtures")
    output.mkdir(mode=0o700)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summary = {"version": 1, "source": "qingnode-final-controlled-acceptance", "status": "running", "started_at": started,
               "scope": "controlled Linux loopback CLI and optional owned netns; not public ingress, desktop UI or ISP experience",
               "binaries": {"core_sha256": args.core_sha256, "qingprobe_sha256": args.probe_sha256}, "checks": {}, "reports": {},
               "not_measured": ["user ISP quality", "public ingress", "native mobile GUI", "proxy independent DNS/TCP/TLS phases", "wire bytes", "statistical significance"],
               "interpretation": {"benefit": "not established; no performance configuration is changed",
                                  "degradation": "only explicitly shaped delay/loss/rate direction is checked when requested",
                                  "sample_size": "eight idle/UDP observations and one download per report; p95 is descriptive only"}}
    summary["fixture_sources"] = {name: sha(REPO / name) for name in (
        "scripts/acceptance-final-performance.py", "internal/probe/final_acceptance_integration_test.go",
        "internal/node/performance_network_integration_test.go")}
    summary["host_context"] = {"started_load_average_1_5_15": list(os.getloadavg()),
                               "load_scope": "current Linux VM/host; unrelated workload was not controlled",
                               "test_load": "single bounded download plus concurrent HEAD samples; no production tuning"}
    environment = {**os.environ, "SING_BOX_BIN": str(core), "QINGPROBE_BIN": str(probe), "QINGNODE_FINAL_PERFORMANCE": "1",
                   "QINGNODE_FINAL_RESULTS": str(output / "cli"), "NO_COLOR": "1", "TERM": "dumb"}
    exit_code = 1
    try:
        summary["checks"]["portable-cli"] = execute_case(go, "portable-cli", "./internal/probe", "TestOfficialFinalCLIControlledPerformance", environment, output, 180)
        for name in CLI_REPORTS:
            path = output / "cli" / (name + ".json")
            summary["reports"]["cli/" + name] = {"sha256": sha(path), "measurement": summarize_report(path)}
        if args.with_netem:
            environment.update(QINGNODE_NETEM_TEST="1", QINGNODE_NETEM_RESULTS=str(output / "hy2-netem"))
            summary["checks"]["hy2-netem"] = execute_case(go, "hy2-netem", "./internal/node", "TestOfficialCoreHY2ControlledNetwork", environment, output, 300)
            for name in NETEM_REPORTS:
                path = output / "hy2-netem" / (name + ".json")
                if path.is_file():
                    summary["reports"]["hy2-netem/" + name] = {"sha256": sha(path), "measurement": summarize_report(path)}
            if len([key for key in summary["reports"] if key.startswith("hy2-netem/")]) != len(NETEM_REPORTS):
                raise AcceptanceFailure("controlled HY2 report set incomplete; capability gap retained")
        else:
            summary["not_measured"].append("HY2 delay/loss/rate and 128MiB controlled namespace fixture not requested")
        if any(check["skips"] for check in summary["checks"].values()):
            summary["status"] = "limited"
        else:
            summary["status"], exit_code = "completed", 0
    except (AcceptanceFailure, OSError, ValueError) as exc:
        # Exception type is enough for a public summary. Original logs remain in
        # the explicitly private output tree and are not copied to the report.
        summary["status"] = "failed"
        summary["failure_category"] = type(exc).__name__
    finally:
        summary["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        summary["host_context"]["finished_load_average_1_5_15"] = list(os.getloadavg())
        write_new(output / "SUMMARY.json", summary)
    print(json.dumps({"status": summary["status"], "report": str(output / "SUMMARY.json"), "scope": summary["scope"]}, ensure_ascii=False))
    return exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--probe-sha256", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--go", default="")
    parser.add_argument("--with-netem", action="store_true")
    try:
        return run(parser.parse_args(argv))
    except (AcceptanceFailure, OSError, ValueError):
        print("acceptance input invalid or unsupported; no production state was changed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
