#!/usr/bin/env python3
"""Offline release failure simulations; never contacts GitHub or changes tags."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("release_guard", pathlib.Path(__file__).with_name("release.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
SHA = "a" * 40
VERSION = "v9.8.7"
REPO = "owner/repo"


def fixture_archive(path, arch, version=VERSION, modes=None, owner=(0, 0)):
    binary = bytearray(64)
    binary[:6] = b"\x7fELF\x02\x01"
    binary[18:20] = {"amd64": 62, "arm64": 183}[arch].to_bytes(2, "little")
    files = {name: ("fixture " + name + "\n").encode() for name in guard.PACKAGE_FILES - {"SHA256SUMS"}}
    files["qingnode"] = bytes(binary)
    files["install.sh"] = f"REPO='' VERSION={version} PORT=443\n".encode()
    files["SHA256SUMS"] = "".join(f"{guard.digest(data)}  {name}\n" for name, data in sorted(files.items())).encode()
    with tarfile.open(path, "w:gz") as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.uid, member.gid = owner
            member.mode = (modes or {}).get(name, 0o755 if name in ("qingnode", "install.sh") else 0o644)
            archive.addfile(member, io.BytesIO(data))


class FakeGitHub:
    def __init__(self, sha=SHA):
        self.sha = sha
        self.tag = None
        self.current_release = None
        self.files = {}
        self.mutations = []
        self.metadata_changes = {}
        self.run = {"head_sha": sha, "path": ".github/workflows/release.yml", "event": "push",
                    "run_attempt": 1, "html_url": "https://github.com/owner/repo/actions/runs/123"}
        self.job = {"name": "Verify release gates", "head_sha": sha, "status": "completed", "conclusion": "success",
                    "steps": [{"name": name, "status": "completed", "conclusion": "success"} for name in guard.GATE_STEPS]}

    def get(self, path, missing=False):
        if path.startswith("/git/ref/tags/"):
            return {"object": {"type": "commit", "sha": self.tag}} if self.tag else None
        if path.startswith("/git/ref/heads/"):
            return {"object": {"type": "commit", "sha": self.sha}}
        if path == "/actions/runs/123":
            return copy.deepcopy(self.run)
        raise AssertionError("unexpected offline GET " + path)

    def pages(self, path, key=None):
        if path == "/actions/runs/123/attempts/1/jobs":
            return [copy.deepcopy(self.job)]
        raise AssertionError("unexpected offline pagination " + path)

    def tag_commit(self, version):
        return self.tag

    def release(self, version):
        return copy.deepcopy(self.current_release)

    def assets(self, release_id):
        result = []
        for index, (name, data) in enumerate(sorted(self.files.items()), 1):
            item = {"name": name, "id": index, "state": "uploaded", "size": len(data), "digest": "sha256:" + guard.digest(data)}
            item.update(self.metadata_changes.get(name, {}))
            result.append(item)
        return result

    def download_asset(self, asset_id):
        return self.files[sorted(self.files)[asset_id - 1]]

    def upload_asset(self, release_id, name, data):
        if name in self.files:
            raise AssertionError("attempted to overwrite an asset")
        self.mutations.append(("upload", name))
        self.files[name] = data
        return {"name": name}

    def request(self, method, path, value=None, **kwargs):
        self.mutations.append((method, path))
        if method == "POST" and path == "/git/refs":
            if self.tag:
                raise AssertionError("attempted to overwrite a tag")
            self.tag = value["sha"]
            return {"object": {"type": "commit", "sha": self.tag}}
        if method == "POST" and path == "/releases":
            if self.current_release:
                raise AssertionError("attempted to replace a Release")
            if value["draft"] is not True or value["prerelease"] is not False:
                raise AssertionError("must first stage a tested, non-prerelease draft")
            self.current_release = dict(value, id=1)
            return copy.deepcopy(self.current_release)
        if method == "PATCH" and path == "/releases/1":
            if set(self.files) != self.expected_names:
                raise AssertionError("published before all four assets existed")
            self.current_release.update(value)
            return copy.deepcopy(self.current_release)
        raise AssertionError("unexpected offline mutation")


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dist = pathlib.Path(self.temp.name) / "dist"
        self.dist.mkdir()
        for arch in ("amd64", "arm64"):
            fixture_archive(self.dist / f"qingnode-{VERSION[1:]}-linux-{arch}.tar.gz", arch)
        self.manifest = guard.prepare(self.dist, VERSION, SHA, REPO)
        _, self.assets = guard.validate_local(self.dist, VERSION, SHA, REPO)
        self.api = FakeGitHub()
        self.api.expected_names = set(self.assets)

    def publish(self, ref="refs/heads/main", sha=SHA):
        return guard.publish(self.api, self.dist, VERSION, sha, REPO, ref, "123", "1", "Release notes")

    def existing(self, draft=False, missing=None):
        self.api.tag = SHA
        self.api.current_release = {"id": 1, "tag_name": VERSION, "target_commitish": SHA,
                                    "draft": draft, "prerelease": False,
                                    "body": "<!-- qingnode-release:" + guard.digest(guard.canonical(self.manifest)) + " -->"}
        self.api.files = {name: value for name, value in self.assets.items() if name != missing}

    def test_new_release_is_staged_checked_then_formal_latest(self):
        result = self.publish()
        self.assertEqual(self.api.tag, SHA)
        self.assertFalse(result["draft"])
        self.assertFalse(result["prerelease"])
        self.assertEqual(result["make_latest"], "true")
        self.assertEqual(self.api.mutations[0], ("POST", "/git/refs"))
        self.assertEqual(self.api.mutations[1], ("POST", "/releases"))
        self.assertEqual(self.api.mutations[-1], ("PATCH", "/releases/1"))
        self.assertEqual(self.api.files, self.assets)

    def test_existing_tag_same_commit_can_publish(self):
        self.api.tag = SHA
        self.publish()
        self.assertNotIn(("POST", "/git/refs"), self.api.mutations)

    def test_formal_release_is_strictly_idempotent(self):
        self.existing()
        self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_symbolic_target_commitish_uses_tag_and_manifest(self):
        self.existing()
        self.api.current_release["target_commitish"] = "main"
        self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_formal_release_missing_asset_is_refused_without_mutation(self):
        self.existing(missing="RELEASE.json")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_formal_release_extra_asset_is_refused(self):
        self.existing()
        self.api.files["unexpected.txt"] = b"untracked"
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_formal_release_changed_asset_is_refused_without_overwrite(self):
        self.existing()
        self.api.files["RELEASE.json"] = b"foreign source"
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_api_digest_mismatch_is_refused(self):
        self.existing()
        self.api.metadata_changes["RELEASE.json"] = {"digest": "sha256:" + "0" * 64}
        with self.assertRaisesRegex(ValueError, "API digest"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_downloaded_digest_checked_even_without_api_digest(self):
        self.existing()
        expected = self.api.files["RELEASE.json"]
        self.api.files["RELEASE.json"] = b"x" * len(expected)
        self.api.metadata_changes["RELEASE.json"] = {"digest": None}
        with self.assertRaisesRegex(ValueError, "downloaded digest"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_incomplete_upload_state_is_refused(self):
        self.existing()
        self.api.metadata_changes["RELEASE.json"] = {"state": "starter"}
        with self.assertRaisesRegex(ValueError, "upload state"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_draft_same_identity_resumes_only_missing_assets(self):
        self.existing(draft=True, missing="RELEASE.json")
        self.publish()
        self.assertEqual([op for op in self.api.mutations if op[0] == "upload"], [("upload", "RELEASE.json")])
        self.assertFalse(self.api.current_release["draft"])

    def test_foreign_draft_is_refused(self):
        self.existing(draft=True)
        self.api.current_release["body"] = "another attempt"
        with self.assertRaisesRegex(ValueError, "another source"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_draft_changed_existing_asset_is_refused(self):
        self.existing(draft=True, missing="SHA256SUMS")
        self.api.files["RELEASE.json"] = b"wrong existing asset"
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_prerelease_is_not_promoted_or_overwritten(self):
        self.existing()
        self.api.current_release["prerelease"] = True
        with self.assertRaisesRegex(ValueError, "prerelease"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_existing_tag_wrong_commit_is_refused(self):
        self.api.tag = "b" * 40
        with self.assertRaisesRegex(ValueError, "another commit"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_existing_release_target_sha_mismatch_is_refused(self):
        self.existing()
        self.api.current_release["target_commitish"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "target commit"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_moved_main_is_refused(self):
        self.api.sha = "b" * 40
        with self.assertRaisesRegex(ValueError, "branch head moved"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_main_moved_during_existing_release_validation_is_refused(self):
        self.existing()
        original = self.api.download_asset
        def moved(asset_id):
            data = original(asset_id)
            self.api.sha = "b" * 40
            return data
        self.api.download_asset = moved
        with self.assertRaisesRegex(ValueError, "branch head moved"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_tag_changed_during_draft_validation_cannot_be_published(self):
        self.existing(draft=True)
        original = self.api.download_asset
        def moved(asset_id):
            data = original(asset_id)
            self.api.tag = "b" * 40
            return data
        self.api.download_asset = moved
        with self.assertRaisesRegex(ValueError, "another commit"):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_candidate_branch_can_validate_but_cannot_publish(self):
        guard.validate_target(self.api, VERSION, SHA, "refs/heads/release/" + VERSION)
        with self.assertRaisesRegex(ValueError, "candidate"):
            self.publish("refs/heads/release/" + VERSION)
        self.assertEqual(self.api.mutations, [])

    def test_wrong_candidate_branch_or_tag_is_refused(self):
        for ref in ("refs/heads/release/v1.0.0", "refs/tags/v1.0.0", "refs/heads/develop"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                guard.validate_target(self.api, VERSION, SHA, ref)

    def test_exact_tag_trigger_can_publish(self):
        self.api.tag = SHA
        self.publish("refs/tags/" + VERSION)

    def test_all_required_gates_and_current_attempt_must_pass(self):
        for change in ("job_failed", "step_failed", "step_skipped", "step_missing", "different_sha", "different_workflow", "old_attempt"):
            with self.subTest(change=change):
                api = FakeGitHub()
                api.expected_names = set(self.assets)
                if change == "job_failed":
                    api.job["conclusion"] = "failure"
                elif change == "step_failed":
                    api.job["steps"][0]["conclusion"] = "failure"
                elif change == "step_skipped":
                    api.job["steps"][0]["conclusion"] = "skipped"
                elif change == "step_missing":
                    api.job["steps"].pop()
                elif change == "different_sha":
                    api.run["head_sha"] = "b" * 40
                elif change == "different_workflow":
                    api.run["path"] = ".github/workflows/ci.yml"
                else:
                    api.run["run_attempt"] = 2
                with self.assertRaises(ValueError):
                    guard.publish(api, self.dist, VERSION, SHA, REPO, "refs/heads/main", "123", "1", "notes")
                self.assertEqual(api.mutations, [])

    def test_changed_local_manifest_or_sums_is_refused(self):
        for name in ("RELEASE.json", "SHA256SUMS"):
            with self.subTest(name=name):
                original = (self.dist / name).read_bytes()
                (self.dist / name).write_bytes(b"tampered")
                with self.assertRaises(ValueError):
                    self.publish()
                (self.dist / name).write_bytes(original)
        self.assertEqual(self.api.mutations, [])

    def test_wrong_architecture_is_refused(self):
        fixture_archive(self.dist / f"qingnode-{VERSION[1:]}-linux-arm64.tar.gz", "amd64")
        with self.assertRaisesRegex(ValueError, "architecture"):
            guard.prepare(self.dist, VERSION, SHA, REPO)

    def test_wrong_bundled_version_is_refused(self):
        fixture_archive(self.dist / f"qingnode-{VERSION[1:]}-linux-amd64.tar.gz", "amd64", "v1.2.3")
        with self.assertRaisesRegex(ValueError, "bundled installer"):
            guard.prepare(self.dist, VERSION, SHA, REPO)

    def test_wrong_executable_mode_is_refused(self):
        path = self.dist / f"qingnode-{VERSION[1:]}-linux-amd64.tar.gz"
        for name in ("qingnode", "install.sh"):
            for mode in (0o644, 0o4755):
                with self.subTest(name=name, mode=mode):
                    fixture_archive(path, "amd64", modes={name: mode})
                    with self.assertRaisesRegex(ValueError, "mode must be 0755"):
                        guard.prepare(self.dist, VERSION, SHA, REPO)

    def test_non_root_archive_owner_is_refused(self):
        path = self.dist / f"qingnode-{VERSION[1:]}-linux-amd64.tar.gz"
        for owner in ((1000, 0), (0, 1000)):
            with self.subTest(owner=owner):
                fixture_archive(path, "amd64", owner=owner)
                with self.assertRaisesRegex(ValueError, "owner must be root:root"):
                    guard.prepare(self.dist, VERSION, SHA, REPO)

    def test_extra_local_artifact_is_refused(self):
        (self.dist / "extra.txt").write_text("extra")
        with self.assertRaisesRegex(ValueError, "exactly four"):
            guard.validate_local(self.dist, VERSION, SHA, REPO)

    def test_reproducible_manifest_is_bound_to_source(self):
        before = (self.dist / "RELEASE.json").read_bytes()
        guard.prepare(self.dist, VERSION, SHA, REPO)
        self.assertEqual(before, (self.dist / "RELEASE.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "manifest"):
            guard.validate_local(self.dist, VERSION, "b" * 40, REPO)

    def test_installer_and_cli_version_must_agree(self):
        root = pathlib.Path(self.temp.name)
        (root / "cmd/qingnode").mkdir(parents=True)
        (root / "install.sh").write_text("REPO='' VERSION=v1.2.3 PORT=443\n")
        (root / "cmd/qingnode/main.go").write_text('var version = "1.2.3"\n')
        self.assertEqual(guard.version_from_source(root), "v1.2.3")
        (root / "cmd/qingnode/main.go").write_text('var version = "1.2.4"\n')
        with self.assertRaisesRegex(ValueError, "versions disagree"):
            guard.version_from_source(root)

    def test_annotated_tag_resolves_exact_commit(self):
        api = guard.GitHub(REPO, "offline-token")
        objects = {"/git/ref/tags/" + VERSION: {"object": {"type": "tag", "sha": "c" * 40}},
                   "/git/tags/" + "c" * 40: {"object": {"type": "commit", "sha": SHA}}}
        api.get = lambda path, missing=False: objects[path]
        self.assertEqual(api.tag_commit(VERSION), SHA)

    def test_cross_host_redirect_strips_token_and_http_is_refused(self):
        request = guard.urllib.request.Request("https://api.github.com/example", headers={"Authorization": "Bearer secret"})
        redirect = guard.SafeRedirect().redirect_request(request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/file")
        self.assertIsNone(redirect.get_header("Authorization"))
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            guard.SafeRedirect().redirect_request(request, None, 302, "Found", {}, "http://example.test/file")


class ToolDownloadTests(unittest.TestCase):
    def response(self, data, url="https://github.com/test"):
        response = io.BytesIO(data)
        response.url = url
        return response

    def test_bad_official_digest_is_refused(self):
        with mock.patch.object(guard.test_tools.urllib.request, "urlopen", return_value=self.response(b"wrong")):
            with self.assertRaisesRegex(ValueError, "checksum"):
                guard.test_tools.download("https://github.com/test", "0" * 64)

    def test_matching_official_digest_is_accepted(self):
        data = b"verified fixture"
        with mock.patch.object(guard.test_tools.urllib.request, "urlopen", return_value=self.response(data)):
            self.assertEqual(guard.test_tools.download("https://github.com/test", hashlib.sha256(data).hexdigest()), data)

    def test_download_and_decompression_size_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            guard.test_tools.bounded_read(io.BytesIO(b"12345"), 4)
        with gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(b"12345"))) as source:
            with self.assertRaisesRegex(ValueError, "size limit"):
                guard.test_tools.bounded_read(source, 4)

    def test_mihomo_not_silently_skipped_on_arm64(self):
        with self.assertRaisesRegex(ValueError, "amd64"):
            guard.test_tools.fetch(pathlib.Path("unused"), "arm64")

    def test_non_https_redirect_is_refused(self):
        with mock.patch.object(guard.test_tools.urllib.request, "urlopen", return_value=self.response(b"data", "http://example.test")):
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                guard.test_tools.download("https://github.com/test", "0" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
