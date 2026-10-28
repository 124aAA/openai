#!/usr/bin/env python3
"""Check actual archives offline; this does not publish, install or use GitHub."""
import importlib.util
import pathlib
import sys
import tarfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("release_guard", ROOT / "scripts/release.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def main():
    version = guard.version_from_source(ROOT)[1:]
    for arch in ("amd64", "arm64"):
        path = ROOT / "dist" / f"qingnode-{version}-linux-{arch}.tar.gz"
        guard.archive_info(path, arch, "v" + version)
        with tarfile.open(path) as archive:
            guard.require(b"\r" not in archive.extractfile("SHA256SUMS").read(), "manager checksum manifest must use LF on all build hosts")
        print("manager archive contract passed:", path.name)
    # Build review and publication now use the same strict helper contract:
    # exact members/checksums, permissions, ELF and PE64 target architecture.
    for target in guard.PROBE_TARGETS:
        path = ROOT / "artifacts/probe" / guard.probe_name(version, target)
        guard.probe_archive_info(path, target)
        print("portable helper archive contract passed:", path.name)
    # Probes can be staged here by the release workflow after build review.
    # Unknown files/directories remain forbidden; prepare requires all seven.
    allowed = {f"qingnode-{version}-linux-{arch}.tar.gz" for arch in ("amd64", "arm64")} | {"SHA256SUMS", "RELEASE.json"}
    allowed |= {guard.probe_name(version, target) for target in guard.PROBE_TARGETS}
    guard.require({p.name for p in (ROOT / "dist").iterdir()} <= allowed, "unknown artifact in the strict release directory")
    return 0


if __name__ == "__main__":
    sys.exit(main())
