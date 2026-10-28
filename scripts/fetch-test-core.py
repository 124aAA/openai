#!/usr/bin/env python3
"""Fetch pinned official test tools. Every archive is hashed before extraction."""
import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import platform
import tarfile
import urllib.parse
import urllib.request

SING_BOX_VERSION = "1.14.0"
SING_BOX_SUMS = {
    "amd64": "2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63",
    "arm64": "04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088",
}
MIHOMO_VERSION = "1.19.30"
MIHOMO_NAME = f"mihomo-linux-amd64-compatible-v{MIHOMO_VERSION}.gz"
MIHOMO_SHA256 = "db214c7a2517e63c150d123178d16d102e03a241ccdae4e5e07ffbe9cf56c6f9"
PEBBLE_VERSION = "2.10.1"
PEBBLE_SHA256 = "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed"
LEGACY_SOURCE = "70c0c277aa8703a4bd2cf8268b6bdad09ae13fc2"
LEGACY_ARCHIVE_SHA256 = "eba884e09ecd56409d9b0cb48d4c971ca520031007f7c7fd84ef804d6944efb6"
LEGACY_MANIFEST_SHA256 = "c17f4bd91f9b38b63c89a815c0a94ef4b0576104cc5b62a1c06f959664c78eaa"
LEGACY_BINARY_SHA256 = "ca87b8ad0f11796225676c3cb1d90eb530be861bc920ddbbaa397a6b05735d77"
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXECUTABLE = 256 * 1024 * 1024


def bounded_read(stream, limit):
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("official test tool exceeds the size limit")
    return data


def download(url, checksum):
    with urllib.request.urlopen(url, timeout=120) as response:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise ValueError("official download redirected outside HTTPS")
        data = bounded_read(response, MAX_ARCHIVE)
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("official test tool archive checksum mismatch")
    return data


def extract_amd64_tool(data, root, member_name, output_name):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 1000:
            raise ValueError("integration archive member limit exceeded")
        selected = [item for item in members if pathlib.PurePosixPath(item.name).name == member_name]
        if len(selected) != 1 or not selected[0].isfile() or not 0 < selected[0].size <= MAX_EXECUTABLE:
            raise ValueError("unexpected integration executable member")
        with archive.extractfile(selected[0]) as stream:
            binary = bounded_read(stream, MAX_EXECUTABLE)
    if len(binary) < 20 or not binary.startswith(b"\x7fELF\x02\x01") or int.from_bytes(binary[18:20], "little") != 62:
        raise ValueError("integration tool requires Linux amd64 ELF")
    destination = root / output_name
    destination.write_bytes(binary)
    destination.chmod(0o755)
    return destination, binary


def fetch_integration(root):
    pebble = download(f"https://github.com/letsencrypt/pebble/releases/download/v{PEBBLE_VERSION}/pebble-linux-amd64.tar.gz", PEBBLE_SHA256)
    pebble_bin, _ = extract_amd64_tool(pebble, root, "pebble", "pebble")
    base = "https://github.com/124aAA/openai/releases/download/v0.2.8/"
    manifest = json.loads(download(base + "RELEASE.json", LEGACY_MANIFEST_SHA256))
    if (manifest.get("version") != "v0.2.8" or manifest.get("commit") != LEGACY_SOURCE or
        manifest.get("archives", {}).get("qingnode-0.2.8-linux-amd64.tar.gz", {}).get("sha256") != LEGACY_ARCHIVE_SHA256):
        raise ValueError("official historical Release identity differs")
    legacy = download(base + "qingnode-0.2.8-linux-amd64.tar.gz", LEGACY_ARCHIVE_SHA256)
    legacy_bin, binary = extract_amd64_tool(legacy, root, "qingnode", "qingnode-v028")
    if hashlib.sha256(binary).hexdigest() != LEGACY_BINARY_SHA256:
        raise ValueError("official historical executable digest mismatch")
    return {"PEBBLE_BIN": pebble_bin, "QINGNODE_LEGACY_BIN": legacy_bin,
            "QINGNODE_LEGACY_V028_BIN": legacy_bin, "QINGNODE_LEGACY_V028_SHA256": LEGACY_BINARY_SHA256}


def fetch(root, arch, core_only=False, integration=False):
    if arch not in SING_BOX_SUMS:
        raise ValueError("official sing-box test requires Linux amd64 or arm64")
    if not core_only and arch != "amd64":
        raise ValueError("pinned Mihomo parser requires Linux amd64; use --core-only for sing-box alone")
    if integration and (arch != "amd64" or core_only):
        raise ValueError("full integration tools require Linux amd64 and Mihomo")
    root.mkdir(parents=True, exist_ok=True)
    name = f"sing-box-{SING_BOX_VERSION}-linux-{arch}.tar.gz"
    data = download(f"https://github.com/SagerNet/sing-box/releases/download/v{SING_BOX_VERSION}/{name}", SING_BOX_SUMS[arch])
    archive_path = root / name
    archive_path.write_bytes(data)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = [m for m in archive.getmembers() if pathlib.PurePosixPath(m.name).name == "sing-box"]
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= MAX_EXECUTABLE:
            raise ValueError("unexpected sing-box executable member")
        with archive.extractfile(members[0]) as source:
            executable = root / "sing-box"
            executable.write_bytes(bounded_read(source, MAX_EXECUTABLE))
    executable.chmod(0o755)
    environment = {"SING_BOX_BIN": executable, "SING_BOX_ARCHIVE": archive_path}
    if not core_only:
        data = download(f"https://github.com/MetaCubeX/mihomo/releases/download/v{MIHOMO_VERSION}/{MIHOMO_NAME}", MIHOMO_SHA256)
        (root / MIHOMO_NAME).write_bytes(data)
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
            data = bounded_read(source, MAX_EXECUTABLE)
        if not data.startswith(b"\x7fELF\x02\x01") or len(data) < 20 or int.from_bytes(data[18:20], "little") != 62:
            raise ValueError("unexpected Mihomo executable architecture")
        mihomo = root / "mihomo"
        mihomo.write_bytes(data)
        mihomo.chmod(0o755)
        environment["MIHOMO_BIN"] = mihomo
    if integration:
        environment.update(fetch_integration(root))
    return environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-only", action="store_true", help="explicitly omit Mihomo on an ARM64 developer host")
    parser.add_argument("--integration", action="store_true", help="also fetch pinned Pebble and the actual official v0.2.8 release for migration")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("official test tools run on Linux")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    environment = fetch(pathlib.Path("artifacts/test-core").resolve(), arch, args.core_only, args.integration)
    for key, value in environment.items():
        print(f"{key}={value}")
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as out:
            for key, value in environment.items():
                out.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
