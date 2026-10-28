#!/usr/bin/env python3
"""Bind verified artifacts to an exact Git commit, then publish without overwrites.

CI calls 'target' and 'prepare' with contents:read. Only the publish job has
contents:write. There is no CLI option to skip the successful current-run gate.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MAX_ASSET = 128 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024
GO_VERSION = "go1.27.1"
DOCS = {"ARCHITECTURE.md", "TEST_REPORT.md", "RELEASE_NOTES.md", "AUDIT_STAGE2.md",
        "GETTING_STARTED.md", "FAQ.md", "DEVELOPMENT.md", "CAPABILITIES.md",
        "BATCH_01.md", "NETWORK_TESTS.md", "BATCH_02.md", "NETWORK_PERFORMANCE.md", "BATCH_03.md",
        "ENDPOINTS.md", "BATCH04.md", "TOPOLOGY.md", "BATCH05.md", "SUBSCRIPTIONS.md", "BATCH06.md", "CERTIFICATES.md", "MIGRATION.md", "BATCH07.md", "MONITORING.md", "BATCH08.md", "PROTOCOLS.md", "BATCH09.md", "PLATFORMS.md", "BATCH10.md", "WORKFLOWS.md", "BATCH11.md"}
PACKAGE_FILES = {"qingnode", "install.sh", "README.md", "LICENSE", "THIRD_PARTY.md",
                 "SHA256SUMS"} | {"docs/" + name for name in DOCS}
PROBE_TARGETS = ("linux-amd64", "linux-arm64", "windows-amd64")
PROBE_DOCS = {"NETWORK_TESTS.md", "BATCH_02.md", "NETWORK_PERFORMANCE.md", "BATCH_03.md",
              "ENDPOINTS.md", "BATCH04.md", "TOPOLOGY.md", "BATCH05.md", "SUBSCRIPTIONS.md",
              "BATCH06.md", "CERTIFICATES.md", "MIGRATION.md", "BATCH07.md", "MONITORING.md",
              "BATCH08.md", "PROTOCOLS.md", "BATCH09.md", "PLATFORMS.md", "BATCH10.md",
              "WORKFLOWS.md", "BATCH11.md"}
GATE_STEPS = {
    "Validate release target", "Static analysis and Go tests",
    "Service-user permissions", "Installer transaction tests",
    "Release guard offline tests", "Maintenance stream observer regression", "Fetch pinned official test tools",
    "Official parser and transport tests", "Controlled topology and WireGuard namespace transport", "Build two Linux architectures",
    "Cross-batch migration and subscription acceptance",
    "Build portable network test tool", "Terminal and machine interface acceptance",
    "Real systemd lifecycle on disposable runner", "Bind release assets",
    "Upload verified candidate assets",
    "Upload portable network test artifacts",
}
spec = importlib.util.spec_from_file_location("test_tools", pathlib.Path(__file__).with_name("fetch-test-core.py"))
test_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test_tools)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded(stream, limit=MAX_ASSET):
    data = stream.read(limit + 1)
    require(len(data) <= limit, "response or artifact exceeds the size limit")
    return data


def read_file(path, limit=MAX_ASSET):
    require(path.is_file() and not path.is_symlink(), "missing or linked release artifact: " + path.name)
    with path.open("rb") as source:
        return bounded(source, limit)


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()


def version_from_source(root):
    installer = (root / "install.sh").read_text(encoding="utf-8")
    versions = re.findall(r"^REPO=.*?\bVERSION=(v[0-9]+\.[0-9]+\.[0-9]+) ", installer, re.M)
    require(len(versions) == 1, "installer must contain one exact release version")
    version = versions[0]
    cli = (root / "cmd/qingnode/main.go").read_text(encoding="utf-8")
    require(re.findall(r'^var version = "([^"]+)"$', cli, re.M) == [version[1:]],
            "installer and CLI versions disagree")
    probe = (root / "cmd/qingprobe/main.go").read_text(encoding="utf-8")
    require(re.findall(r'^var version = "([^"]+)"$', probe, re.M) == [version[1:]],
            "installer and portable probe versions disagree")
    return version


def identity(version, sha, repo):
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version), "invalid release version")
    require(re.fullmatch(r"[0-9a-f]{40}", sha), "release requires a full Git commit SHA")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo), "invalid GitHub repository")
    return {"schema": 2, "repository": repo, "version": version, "tag": version,
            "commit": sha, "revision": sha[:12]}


def check_checkout(root, sha):
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True)
    require(result.stdout.strip() == sha, "checkout differs from the triggering commit")


def parse_sums(data):
    result = {}
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        require(match is not None, "malformed checksum line")
        value, name = match.groups()
        require(name not in result, "duplicate checksum entry")
        result[name] = value
    return result


def archive_info(path, arch, version):
    data = read_file(path)
    contents = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            require(member.uid == 0 and member.gid == 0, "archive member owner must be root:root")
            if member.isdir():
                require(member.name == "docs", "unexpected archive directory")
                continue
            require(member.isfile() and member.name in PACKAGE_FILES, "unexpected archive member: " + member.name)
            require(member.name not in contents, "duplicate archive member")
            if member.name in ("qingnode", "install.sh"):
                require(member.mode == 0o755, "archive executable mode must be 0755: " + member.name)
            total += member.size
            require(0 <= member.size <= MAX_ASSET and total <= 256 * 1024 * 1024,
                    "archive expansion exceeds the size limit")
            with archive.extractfile(member) as source:
                contents[member.name] = bounded(source)
    require(set(contents) == PACKAGE_FILES, "archive is incomplete")
    binary = contents["qingnode"]
    require(binary.startswith(b"\x7fELF\x02\x01") and len(binary) >= 20, "expected a Linux ELF64 binary")
    require(int.from_bytes(binary[18:20], "little") == {"amd64": 62, "arm64": 183}[arch],
            "archive binary architecture mismatch")
    require(re.findall(rb"^REPO=.*?\bVERSION=(v[0-9]+\.[0-9]+\.[0-9]+) ", contents["install.sh"], re.M)
            == [version.encode()], "bundled installer version mismatch")
    sums = parse_sums(contents["SHA256SUMS"])
    require(set(sums) == PACKAGE_FILES - {"SHA256SUMS"}, "inner checksum contract mismatch")
    require(all(digest(contents[name]) == value for name, value in sums.items()), "inner checksum mismatch")
    return {"architecture": arch, "sha256": digest(data), "size": len(data)}


def probe_name(version, target):
    require(target in PROBE_TARGETS, "unsupported probe target")
    return f"qingprobe-{version.removeprefix('v')}-{target}" + (".zip" if target.startswith("windows-") else ".tar.gz")


def probe_archive_info(path, target):
    require(target in PROBE_TARGETS, "unsupported probe target")
    windows = target.startswith("windows-")
    binary_name = "qingprobe.exe" if windows else "qingprobe"
    allowed = {binary_name, "LICENSE", "THIRD_PARTY.md", "SHA256SUMS"} | {"docs/" + name for name in PROBE_DOCS}
    raw = read_file(path)
    contents = {}
    total = 0

    def add(name, size, source):
        nonlocal total
        require(name in allowed and name not in contents, "unknown or duplicate probe member")
        total += size
        require(0 <= size <= MAX_ASSET and total <= 256 * 1024 * 1024, "probe archive expansion exceeds limit")
        contents[name] = bounded(source)
        require(len(contents[name]) == size, "probe member size mismatch")

    if windows:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            require(len(archive.infolist()) <= len(allowed) + 1, "probe archive member count exceeded")
            for member in archive.infolist():
                require(not member.flag_bits & 1, "encrypted probe member refused")
                mode = member.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "linked or special probe member refused")
                if member.is_dir():
                    require(member.filename == "docs/", "unknown probe directory")
                    continue
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG), "probe file has directory permissions")
                with archive.open(member) as stream:
                    add(member.filename, member.file_size, stream)
    else:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            count = 0
            for member in archive:
                count += 1
                require(count <= len(allowed) + 1, "probe archive member count exceeded")
                require(member.uid == member.gid == 0, "probe archive owner must be root")
                if member.isdir():
                    require(member.name == "docs", "unknown probe directory")
                    continue
                require(member.isfile(), "linked or special probe member refused")
                require(member.mode == (0o755 if member.name == binary_name else 0o644), "probe member permission mismatch")
                with archive.extractfile(member) as stream:
                    add(member.name, member.size, stream)
    require(set(contents) == allowed, "probe archive is incomplete")
    require(b"\r" not in contents["SHA256SUMS"], "probe checksum manifest must use LF")
    sums = parse_sums(contents["SHA256SUMS"])
    require(set(sums) == allowed - {"SHA256SUMS"}, "probe inner checksum set mismatch")
    require(all(digest(contents[name]) == value for name, value in sums.items()), "probe inner checksum mismatch")
    binary = contents[binary_name]
    if windows:
        require(len(binary) >= 64 and binary.startswith(b"MZ"), "probe must be Windows PE64")
        offset = int.from_bytes(binary[60:64], "little")
        require(offset <= len(binary) - 26 and binary[offset:offset+4] == b"PE\0\0" and
                int.from_bytes(binary[offset+4:offset+6], "little") == 0x8664 and
                int.from_bytes(binary[offset+24:offset+26], "little") == 0x20b, "probe Windows architecture mismatch")
    else:
        require(len(binary) >= 20 and binary.startswith(b"\x7fELF\x02\x01") and
                int.from_bytes(binary[18:20], "little") == {"linux-amd64": 62, "linux-arm64": 183}[target],
                "probe Linux architecture mismatch")
    return {"component": "qingprobe", "target": target, "sha256": digest(raw), "size": len(raw)}


def expected_manifest(dist, version, sha, repo):
    manifest = identity(version, sha, repo)
    archives = {}
    for arch in ("amd64", "arm64"):
        name = f"qingnode-{version[1:]}-linux-{arch}.tar.gz"
        archives[name] = archive_info(dist / name, arch, version)
    for target in PROBE_TARGETS:
        name = probe_name(version, target)
        archives[name] = probe_archive_info(dist / name, target)
    manifest["archives"] = archives
    manifest["build"] = {"go_version": GO_VERSION, "goos": "linux", "cgo_enabled": False,
                         "trimpath": True, "buildvcs": False}
    manifest["official_test_tools"] = {
        "sing_box": {"version": test_tools.SING_BOX_VERSION, "archive_sha256": test_tools.SING_BOX_SUMS["amd64"],
                     "architecture": "amd64"},
        "mihomo": {"version": test_tools.MIHOMO_VERSION, "archive_sha256": test_tools.MIHOMO_SHA256,
                   "architecture": "amd64"},
        "pebble": {"version": test_tools.PEBBLE_VERSION, "archive_sha256": test_tools.PEBBLE_SHA256, "architecture": "amd64"},
        "qingnode_legacy": {"version": "0.2.8", "commit": test_tools.LEGACY_SOURCE,
                            "archive_sha256": test_tools.LEGACY_ARCHIVE_SHA256, "binary_sha256": test_tools.LEGACY_BINARY_SHA256},
    }
    return manifest


def prepare(dist, version, sha, repo):
    manifest = expected_manifest(dist, version, sha, repo)
    allowed = set(manifest["archives"]) | {"SHA256SUMS", "RELEASE.json"}
    require({p.name for p in dist.iterdir()} <= allowed, "unexpected file in release artifact directory")
    (dist / "RELEASE.json").write_bytes(canonical(manifest))
    sums = {name: entry["sha256"] for name, entry in manifest["archives"].items()}
    sums["RELEASE.json"] = digest(canonical(manifest))
    (dist / "SHA256SUMS").write_text("".join(f"{sums[name]}  {name}\n" for name in sorted(sums)), encoding="ascii", newline="\n")
    return manifest


def validate_local(dist, version, sha, repo):
    manifest = expected_manifest(dist, version, sha, repo)
    names = set(manifest["archives"]) | {"SHA256SUMS", "RELEASE.json"}
    require({p.name for p in dist.iterdir()} == names, "release must contain exactly seven verified assets")
    require(read_file(dist / "RELEASE.json", MAX_JSON) == canonical(manifest), "release manifest identity or digest mismatch")
    sums = parse_sums(read_file(dist / "SHA256SUMS", MAX_JSON))
    require(set(sums) == names - {"SHA256SUMS"}, "outer checksum contract mismatch")
    assets = {name: read_file(dist / name) for name in names}
    require(all(digest(assets[name]) == value for name, value in sums.items()), "outer checksum mismatch")
    return manifest, assets


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and not parsed.username and not parsed.password,
                "GitHub redirect must remain HTTPS")
        require(req.get_method() == "GET", "mutation redirects are not permitted")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if urllib.parse.urlsplit(req.full_url).netloc != parsed.netloc:
            redirected.remove_header("Authorization")
        return redirected


class GitHub:
    def __init__(self, repo, token):
        identity("v0.0.0", "0" * 40, repo)
        require(bool(token), "GITHUB_TOKEN is required")
        self.base = "https://api.github.com/repos/" + repo
        self.upload_base = "https://uploads.github.com/repos/" + repo
        self.token = token
        self.opener = urllib.request.build_opener(SafeRedirect())

    def request(self, method, path, value=None, binary=False, upload=None, missing=False):
        url = self.base + path
        headers = {"Accept": "application/octet-stream" if binary else "application/vnd.github+json",
                   "Authorization": "Bearer " + self.token, "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "QingNode-release-guard"}
        body = None
        if upload is not None:
            url = self.upload_base + path
            body = upload
            headers["Content-Type"] = "application/octet-stream"
        elif value is not None:
            body = canonical(value)
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=120) as response:
                data = bounded(response, MAX_ASSET if binary else MAX_JSON)
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise ValueError(f"GitHub {method} {path.split('?')[0]} failed (HTTP {error.code}); no asset was overwritten") from None
        except urllib.error.URLError:
            raise ValueError("GitHub request failed; retry the workflow after checking connectivity") from None
        return data if binary else json.loads(data) if data else None

    def get(self, path, missing=False):
        return self.request("GET", path, missing=missing)

    def pages(self, path, key=None):
        values = []
        for page in range(1, 101):
            join = "&" if "?" in path else "?"
            data = self.get(f"{path}{join}per_page=100&page={page}")
            batch = data[key] if key else data
            require(isinstance(batch, list), "malformed paginated GitHub response")
            values.extend(batch)
            if len(batch) < 100:
                return values
        raise ValueError("GitHub pagination limit reached")

    def tag_commit(self, version):
        data = self.get("/git/ref/tags/" + version, missing=True)
        if data is None:
            return None
        obj = data["object"]
        for _ in range(6):
            require(re.fullmatch(r"[0-9a-f]{40}", obj["sha"]), "invalid Git tag object SHA")
            if obj["type"] == "commit":
                return obj["sha"]
            require(obj["type"] == "tag", "release tag must point to a Git commit")
            obj = self.get("/git/tags/" + obj["sha"])["object"]
        raise ValueError("release tag nesting exceeds the limit")

    def release(self, version):
        matches = [r for r in self.pages("/releases") if r["tag_name"] == version]
        require(len(matches) <= 1, "multiple Releases use the same tag")
        return matches[0] if matches else None

    def assets(self, release_id):
        return self.pages(f"/releases/{release_id}/assets")

    def download_asset(self, asset_id):
        return self.request("GET", f"/releases/assets/{asset_id}", binary=True)

    def upload_asset(self, release_id, name, data):
        return self.request("POST", f"/releases/{release_id}/assets?name={urllib.parse.quote(name, safe='')}", upload=data)


def validate_target(api, version, sha, ref):
    identity(version, sha, "owner/repo")
    allowed = {"refs/heads/main", "refs/heads/release/" + version, "refs/tags/" + version}
    require(ref in allowed, "release target must be main, the matching release/version branch, or the exact version tag")
    data = api.get("/git/ref/" + ref.removeprefix("refs/"), missing=True)
    require(data is not None, "triggering ref no longer exists")
    if ref.startswith("refs/tags/"):
        require(api.tag_commit(version) == sha, "release tag points to another commit")
    else:
        require(data["object"]["type"] == "commit" and data["object"]["sha"] == sha,
                "branch head moved since this run started")
    tag_sha = api.tag_commit(version)
    require(tag_sha is None or tag_sha == sha, "existing version tag points to another commit")


def require_gates(api, sha, run_id, attempt):
    require(str(run_id).isdigit() and int(run_id) > 0 and str(attempt).isdigit() and int(attempt) > 0,
            "publish requires a current GitHub Actions run and attempt")
    run = api.get(f"/actions/runs/{run_id}")
    require(run["head_sha"] == sha and run["path"] == ".github/workflows/release.yml",
            "verification run does not belong to this source and release workflow")
    require(run["event"] in ("push", "workflow_dispatch") and run["run_attempt"] == int(attempt),
            "verification run event or attempt mismatch")
    jobs = api.pages(f"/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    verify = [job for job in jobs if job["name"] == "Verify release gates"]
    require(len(verify) == 1, "current attempt must contain exactly one release verification job")
    job = verify[0]
    require(job["head_sha"] == sha and job["status"] == "completed" and job["conclusion"] == "success",
            "release verification job has not passed")
    steps = {step["name"]: step for step in job["steps"]}
    require(GATE_STEPS <= set(steps), "required verification step is absent")
    require(all(steps[name]["status"] == "completed" and steps[name]["conclusion"] == "success" for name in GATE_STEPS),
            "a required verification step did not pass")
    return run["html_url"]


def validate_release_identity(release, version, sha, manifest):
    require(release["tag_name"] == version, "existing Release tag mismatch")
    target = release.get("target_commitish", "")
    if re.fullmatch(r"[0-9a-f]{40}", target):
        require(target == sha, "existing Release target commit mismatch")
    require(not release["prerelease"], "existing Release is a prerelease")
    if release["draft"]:
        marker = "<!-- qingnode-release:" + digest(canonical(manifest)) + " -->"
        require(marker in release.get("body", ""), "draft belongs to another source or artifact set")


def verify_remote_assets(api, release, assets, allow_missing=False):
    remote = api.assets(release["id"])
    names = [asset["name"] for asset in remote]
    require(len(names) == len(set(names)) and set(names) <= set(assets), "unexpected or duplicate Release asset")
    if not allow_missing:
        require(set(names) == set(assets), "existing formal Release is incomplete")
    for asset in remote:
        name = asset["name"]
        expected = assets[name]
        require(asset["state"] == "uploaded" and asset["size"] == len(expected), "Release asset size or upload state mismatch: " + name)
        if asset.get("digest") is not None:
            require(asset["digest"] == "sha256:" + digest(expected), "Release asset API digest mismatch: " + name)
        require(digest(api.download_asset(asset["id"])) == digest(expected), "Release asset downloaded digest mismatch: " + name)
    return set(names)


def publish(api, dist, version, sha, repo, ref, run_id, attempt, notes):
    manifest, assets = validate_local(dist, version, sha, repo)
    require(ref in ("refs/heads/main", "refs/tags/" + version), "candidate branches cannot publish")
    run_url = require_gates(api, sha, run_id, attempt)
    validate_target(api, version, sha, ref)
    release = api.release(version)
    if release is not None:
        require(api.tag_commit(version) == sha, "existing Release tag is absent or points to another commit")
        validate_release_identity(release, version, sha, manifest)
        existing = verify_remote_assets(api, release, assets, allow_missing=release["draft"])
        if not release["draft"]:
            validate_target(api, version, sha, ref)
            print("Existing formal Release has the exact commit and all seven verified assets; no changes made.")
            return release
    else:
        if api.tag_commit(version) is None:
            api.request("POST", "/git/refs", {"ref": "refs/tags/" + version, "sha": sha})
        require(api.tag_commit(version) == sha, "version tag changed before release creation")
        marker = "<!-- qingnode-release:" + digest(canonical(manifest)) + " -->"
        body = notes + "\n\nVerified source commit: `" + sha + "`\n\n" + marker
        body += "\n\n[Full verification run](" + run_url + ") (Go/race/vet, installer rollback, official sing-box + Mihomo parser, amd64 real systemd lifecycle)."
        body += "\n\nARM64 is cross-built and its archive is verified. Public-network clients, ACME and native ARM64 deployment require separate acceptance. See `RELEASE.json` for immutable source and artifact identity.\n"
        release = api.request("POST", "/releases", {"tag_name": version, "target_commitish": sha,
                              "name": "QingNode " + version, "body": body,
                              "draft": True, "prerelease": False, "make_latest": "false"})
        validate_release_identity(release, version, sha, manifest)
        existing = set()
    for name in sorted(set(assets) - existing):
        api.upload_asset(release["id"], name, assets[name])
    verify_remote_assets(api, release, assets)
    validate_target(api, version, sha, ref)
    require(api.tag_commit(version) == sha, "version tag changed before formal publication")
    release = api.request("PATCH", f"/releases/{release['id']}", {"draft": False, "prerelease": False, "make_latest": "true"})
    require(not release["draft"] and not release["prerelease"], "GitHub did not confirm formal publication")
    validate_release_identity(release, version, sha, manifest)
    verify_remote_assets(api, release, assets)
    validate_target(api, version, sha, ref)
    print("Formal release published with the exact commit and all seven verified assets.")
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("version", "target", "prepare", "publish"))
    parser.add_argument("--dist", default="dist")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    version = version_from_source(root)
    if args.command == "version":
        print(version)
        return
    sha = os.environ.get("GITHUB_SHA", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    identity(version, sha, repo)
    check_checkout(root, sha)
    dist = pathlib.Path(args.dist)
    if args.command == "prepare":
        go_version = subprocess.run(["go", "env", "GOVERSION"], check=True, capture_output=True, text=True).stdout.strip()
        require(go_version == GO_VERSION, "release requires the pinned Go toolchain")
        prepare(dist, version, sha, repo)
        validate_local(dist, version, sha, repo)
        print("Bound both Linux archives and checksums to " + sha)
        return
    require(os.environ.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch"), "unsupported release trigger")
    api = GitHub(repo, os.environ.get("GITHUB_TOKEN", ""))
    ref = os.environ.get("GITHUB_REF", "")
    if args.command == "target":
        validate_target(api, version, sha, ref)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write("version=" + version + "\n")
        print("Release target matches installer, CLI, ref and commit: " + version)
        return
    notes = (root / "docs/RELEASE_NOTES.md").read_text(encoding="utf-8")
    release = publish(api, dist, version, sha, repo, ref, os.environ.get("GITHUB_RUN_ID", ""),
                      os.environ.get("GITHUB_RUN_ATTEMPT", ""), notes)
    url = f"https://github.com/{repo}/releases/tag/{release['tag_name']}"
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(f"Verified formal release: [{version}]({url})\n\nSource commit: `{sha}`\n")
    print(url)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print("Release refused: " + str(error), file=sys.stderr)
        sys.exit(1)
