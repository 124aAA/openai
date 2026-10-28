#!/usr/bin/env python3
"""Explicit disposable cross-batch regression; reuse existing test mechanisms.

This is not a production installer or a replacement for real init/mobile/public
acceptance. Fixed tests cover identity migration, actual official core data,
NAT, failover, subscription permissions and monitor contracts separately.
"""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("final_performance", Path(__file__).with_name("acceptance-final-performance.py"))
common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(common)
CASES = (
    ("legacy-and-encrypted-migration", "./internal/node", "^(TestMigration|TestStateVersion|TestLegacySnapshot|TestDeviceMigration|TestTopologySchema).*", 240,
     ("TestMigrationEncryptedRoundTripAndOldFormats", "TestDeviceMigrationPreservesAllLegacyFieldsAndRecoveryBytes"), "real files and encrypted recovery; no public CA inference"),
    ("live-maintenance-and-certificate-restore", "./internal/node", "^(TestOfficialCoreMetadataKeepsProcessAndTCPStream|TestOfficialCoreHY2ClientPerformanceKeepsProcessAndTCPStream|TestOfficialCoreCertificateMigrationPEMRestoresIdentityAndHY2)$", 120,
     ("TestOfficialCoreMetadataKeepsProcessAndTCPStream", "TestOfficialCoreHY2ClientPerformanceKeepsProcessAndTCPStream", "TestOfficialCoreCertificateMigrationPEMRestoresIdentityAndHY2"), "official core PID and active stream, failure rollback, private PEM restore; not real init"),
    ("protocols-and-clients", "./internal/node", "^(TestOfficialCoreEndToEnd|TestOfficialCoreTLSProtocolExpansionTCPUDPRevokeBackupAndCertificateMismatch|TestOfficialCoreSSAEADTUICProtocolExpansionTCPUDPRevokeAndRestore|TestMihomoTLSProtocolExpansionTCPUDPAndCertificateMismatch|TestMihomoSSAEADTUICProtocolExpansionTCPUDPRevokeAndRestore|TestDeviceOfficialFullConfigsTCPUDPAndNoDirectFallback)$", 240,
     ("TestOfficialCoreEndToEnd", "TestOfficialCoreTLSProtocolExpansionTCPUDPRevokeBackupAndCertificateMismatch", "TestOfficialCoreSSAEADTUICProtocolExpansionTCPUDPRevokeAndRestore", "TestMihomoTLSProtocolExpansionTCPUDPAndCertificateMismatch", "TestMihomoSSAEADTUICProtocolExpansionTCPUDPRevokeAndRestore", "TestDeviceOfficialFullConfigsTCPUDPAndNoDirectFallback"), "official sing-box/Mihomo TCP and UDP configurations; not a GUI import"),
    ("controlled-nat-v4-v6", "./internal/node", "^(TestOfficialCoreControlledNATEndpoints|TestOfficialCoreProtocolExpansionControlledNAT|TestOfficialCoreProtocolExpansionControlledNATIPv6)$", 300,
     ("TestOfficialCoreControlledNATEndpoints", "TestOfficialCoreProtocolExpansionControlledNAT", "TestOfficialCoreProtocolExpansionControlledNATIPv6"), "owned local forwarders/netns, explicit external ports and stopped-forwarder negatives; not cloud NAT"),
    ("egress-failure-and-recovery", "./internal/node", "^(TestOfficialCoreTopologyPureTCPUDPForwards|TestOfficialCoreTopologyEntryToRemoteProtocols|TestOfficialCoreFailoverThresholdsSourcesSessionsAndRecovery)$", 240,
     ("TestOfficialCoreTopologyPureTCPUDPForwards", "TestOfficialCoreTopologyEntryToRemoteProtocols", "TestOfficialCoreFailoverThresholdsSourcesSessionsAndRecovery"), "controlled target and exit failure evidence; existing sessions are not migrated"),
    ("subscription-authorization", "./internal/subscription", "^Test", 90, (), "controlled local HTTP and private snapshot authorization; public HTTPS remains separate"),
    ("monitor-stop-contract", "./internal/monitor", "^Test", 90,
     ("TestShortFlapAndSafetyStops", "TestSingleInstanceAndWatchCancellation"), "engine/controller contracts; actual init lifecycle is a separate gate"),
    ("pool-and-credential-expiry", "./internal/node", "^(TestOfficialAnyTLSIdlePoolOwnedSocketsAndResources|TestOfficialCredentialExpiryExistingTCPAndNewAuthentication)$", 120,
     ("TestOfficialAnyTLSIdlePoolOwnedSocketsAndResources", "TestOfficialCredentialExpiryExistingTCPAndNewAuthentication"),
     "actual owned core processes, AnyTLS sockets/resources and existing/new authentication after expiry; no production init"),
)
LEGACY_CASE = ("actual-v028-binary-migration", "./internal/node", "^TestLegacyV028RealBinaryMigrationAndBackup$", 180,
               ("TestLegacyV028RealBinaryMigrationAndBackup",), "fixed v0.2.8 executable creates real schema-1/URI/QNBK2; current manager preserves identity and old bytes")


def legacy_binary(args):
    path, digest = args.legacy_bin, args.legacy_sha256
    if bool(path) != bool(digest):
        raise common.AcceptanceFailure("legacy executable and digest must be supplied together")
    return common.binary(path, digest) if path else None


def inspect(path, required):
    if path.stat().st_size > 16 << 20:
        raise common.AcceptanceFailure("regression output exceeded bounded evidence size")
    events = [json.loads(line) for line in path.read_bytes().splitlines() if line]
    passed = {event["Test"] for event in events if event.get("Action") == "pass" and "Test" in event}
    skips = sorted({event["Test"] for event in events if event.get("Action") == "skip" and "Test" in event})
    failures = sorted({event.get("Test", event.get("Package", "unknown")) for event in events if event.get("Action") == "fail"})
    missing = sorted(set(required) - passed - set(skips))
    if not passed or failures or missing:
        raise common.AcceptanceFailure("regression failed or expected test was not executed")
    return {"passed_test_or_subcase_count": len(passed), "skipped_tests": skips, "missing_required_tests": missing,
            "failed_tests": failures, "log_sha256": common.sha(path)}


def run(args):
    if (sys.platform != "linux" or not args.disposable or os.geteuid() != 0
            or os.environ.get("QINGNODE_VM_DISPOSABLE") != "1"):
        raise common.AcceptanceFailure("explicit disposable root Linux environment required")
    core = common.binary(args.core, args.core_sha256)
    mihomo = common.binary(args.mihomo, args.mihomo_sha256)
    legacy = legacy_binary(args)
    output = Path(args.out)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.resolve() != output.parent:
        raise common.AcceptanceFailure("new absolute output directory below a real parent required")
    go = Path(args.go or shutil.which("go") or "")
    if not go.is_absolute() or not go.is_file():
        raise common.AcceptanceFailure("native Go acceptance tool required")
    output.mkdir(mode=0o700)
    report = {"version": 1, "source": "qingnode-cross-batch-regression", "status": "running",
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "core_sha256": args.core_sha256, "mihomo_sha256": args.mihomo_sha256,
              "legacy_binary_sha256": args.legacy_sha256 if legacy else None,
              "steps": {}, "not_verified": ["mobile SSH hardware", "desktop/mobile GUI", "public ingress", "public production CA", "native ARM", "real init lifecycle"]}
    environment = {**os.environ, "SING_BOX_BIN": str(core), "MIHOMO_BIN": str(mihomo),
                   "QINGNODE_NAT_DISPOSABLE": "1", "QINGNODE_PROTOCOL_NAT_TEST": "1", "QINGNODE_PROTOCOL_NAT_IPV6_TEST": "1",
                   "NO_COLOR": "1", "TERM": "dumb"}
    # Ambient opt-in variables cannot silently turn another step into this proof.
    for key in ("QINGNODE_LEGACY_V028_TEST", "QINGNODE_LEGACY_V028_BIN", "QINGNODE_LEGACY_V028_SHA256", "QINGNODE_ANYTLS_POOL_TEST", "QINGNODE_EXPIRY_CORE_TEST"):
        environment.pop(key, None)
    if not legacy:
        report["not_verified"].append("actual v0.2.8 executable migration: explicit legacy binary not supplied")
    code = 1
    try:
        cases = (LEGACY_CASE,) + CASES if legacy else CASES
        for label, package, pattern, timeout, required, scope in cases:
            report["current_step"] = label
            log = output / (label + ".jsonl")
            command = [str(go), "test", "-count=1", "-json", "-run", pattern, "-timeout=" + str(timeout) + "s", package]
            step_environment = environment
            if label == LEGACY_CASE[0]:
                step_environment = {**environment, "QINGNODE_LEGACY_V028_TEST": "1", "QINGNODE_LEGACY_V028_BIN": str(legacy),
                                    "QINGNODE_LEGACY_V028_SHA256": args.legacy_sha256}
            elif label == "pool-and-credential-expiry":
                step_environment = {**environment, "QINGNODE_ANYTLS_POOL_TEST": "1", "QINGNODE_EXPIRY_CORE_TEST": "1"}
            with log.open("xb") as stream:
                result = subprocess.run(command, cwd=REPO, env=step_environment, stdin=subprocess.DEVNULL,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=timeout + 30)
            if result.returncode:
                raise common.AcceptanceFailure("actual fixed regression command failed; private evidence retained")
            report["steps"][label] = {"scope": scope, "exit_code": result.returncode, **inspect(log, required)}
        report["status"] = "limited" if not legacy or any(step["skipped_tests"] for step in report["steps"].values()) else "completed"
        report["current_step"] = "complete"
        code = 0 if report["status"] == "completed" else 1
    except (common.AcceptanceFailure, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        report["status"], report["failure_category"] = "failed", type(exc).__name__
    finally:
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        common.write_new(output / "SUMMARY.json", report)
    print(json.dumps({"status": report["status"], "report": str(output / "SUMMARY.json"), "real_init_or_public_acceptance": False}))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    for name in ("core", "core-sha256", "mihomo", "mihomo-sha256", "out"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--go", default="")
    parser.add_argument("--legacy-bin", default="")
    parser.add_argument("--legacy-sha256", default="")
    try:
        return run(parser.parse_args(argv))
    except (common.AcceptanceFailure, OSError, ValueError):
        print("invalid or unsupported disposable regression input; no production state changed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
