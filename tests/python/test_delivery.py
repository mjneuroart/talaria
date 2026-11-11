"""Tests for setup, delivery and link audit.

Run:  cd repo && python3 -m unittest discover -s tests/python -t . -v

No test here opens a socket. Every network entry point is replaced by a stub that fails the
test when it is reached without the user's explicit flag.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures"
sys.path.insert(0, str(REPO))

from talaria import env, icloud, library, setup  # noqa: E402
from talaria import inspect as audit  # noqa: E402

SIGNED_FIXTURE = FIXTURES / "signed" / "import-test.shortcut"
UNSIGNED_FIXTURE = FIXTURES / "unsigned" / "meeting-note.shortcut"
LINK = "https://www.icloud.com/shortcuts/" + "0123456789abcdef" * 2


def load_plugin():
    spec = importlib.util.spec_from_file_location("talaria_plugin_under_test", REPO / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def no_network(*args, **kwargs):
    raise AssertionError("a network call was attempted")


class IsolatedCase(unittest.TestCase):
    """Private library and delivery folders, and no compiler override, for each test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="talaria-delivery-")
        root = Path(self._tmp.name)
        patch = mock.patch.dict(os.environ, {
            "TALARIA_HOME": str(root / "home"),
            "TALARIA_DELIVER_DIR": str(root / "deliver"),
        })
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(self._tmp.cleanup)
        os.environ.pop(env.COMPILER_ENV, None)
        os.environ.pop(env.ALLOW_UNPINNED_ENV, None)

    def store(self, blob: bytes, name: str, signed: bool) -> str:
        """Put a file in the library the way build and sign do."""
        sha = hashlib.sha256(blob).hexdigest()
        artifact_id = ("s" + sha[:15]) if signed else sha[:16]
        library.artifact_path(artifact_id).write_bytes(blob)
        library.write_meta(artifact_id, {"artifact_id": artifact_id, "name": library.slugify(name),
                                         "display_name": name, "sha256": sha, "bytes": len(blob),
                                         "actions": 1, "signed": signed})
        return artifact_id


class TestSetup(IsolatedCase):
    def test_no_confirm_means_no_download(self):
        with mock.patch.object(setup, "_download", no_network), \
                mock.patch.object(env.shutil, "which", return_value=None):
            for value in (False, None, "true", 1):
                result = setup.install(value)
                self.assertTrue(result["refused"], result)
                self.assertFalse(result["downloaded"])
                self.assertFalse(env.managed_compiler().exists())

    def test_refusal_names_the_source_and_both_checksums(self):
        with mock.patch.object(env.shutil, "which", return_value=None), \
                mock.patch.object(setup, "platform_key", return_value="linux-x86_64"):
            reason = setup.install()["reason"]
        build = setup.BUILDS["linux-x86_64"]
        self.assertIn(build["url"], reason)
        self.assertIn(build["archive_sha256"], reason)
        self.assertIn(build["binary_sha256"], reason)
        self.assertIn("Nothing is uploaded", reason)

    def test_pinned_binary_is_the_one_the_engine_trusts(self):
        for build in setup.BUILDS.values():
            self.assertIn(build["binary_sha256"], env.PINNED)

    def test_only_github_hosts_are_accepted(self):
        self.assertTrue(setup.official_host("https://github.com/electrikmilk/cherri/releases/download/x"))
        self.assertTrue(setup.official_host("https://release-assets.githubusercontent.com/a"))
        for bad in ("http://github.com/x", "https://github.com.evil.example/x",
                    "https://evil.example/github.com", "https://githubusercontent.com.evil.example/x",
                    "file:///etc/passwd"):
            self.assertFalse(setup.official_host(bad), bad)

    def test_wrong_archive_writes_nothing(self):
        with mock.patch.object(setup, "_download", return_value=b"not the release"), \
                mock.patch.object(env.shutil, "which", return_value=None), \
                mock.patch.object(setup, "platform_key", return_value="linux-x86_64"):
            with self.assertRaises(setup.SetupError) as caught:
                setup.install(True)
        self.assertIn("checksum mismatch", str(caught.exception))
        self.assertFalse(env.managed_compiler().exists())

    def test_right_archive_wrong_member_writes_nothing(self):
        """An archive that passes the first checksum still has to hold the pinned binary."""
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("cherri", b"#!/bin/sh\necho not the compiler\n")
        blob = payload.getvalue()
        forged = dict(setup.BUILDS["linux-x86_64"], archive_sha256=hashlib.sha256(blob).hexdigest())
        with mock.patch.dict(setup.BUILDS, {"linux-x86_64": forged}), \
                mock.patch.object(setup, "_download", return_value=blob), \
                mock.patch.object(env.shutil, "which", return_value=None), \
                mock.patch.object(setup, "platform_key", return_value="linux-x86_64"):
            with self.assertRaises(setup.SetupError):
                setup.install(True)
        self.assertFalse(env.managed_compiler().exists())

    def test_unknown_platform_is_refused_with_a_way_out(self):
        with mock.patch.object(setup, "platform_key", return_value="plan9-mips"), \
                mock.patch.object(env.shutil, "which", return_value=None):
            with self.assertRaises(setup.SetupError) as caught:
                setup.install(True)
        self.assertIn(env.COMPILER_ENV, str(caught.exception))

    def test_installed_copy_is_found_before_path(self):
        target = env.managed_compiler()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"placeholder")
        with mock.patch.object(env.shutil, "which", return_value="/usr/bin/some-other-cherri"):
            self.assertEqual(env.compiler_path(), target)

    def test_unrecognised_binary_is_never_executed(self):
        target = env.managed_compiler()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"#!/bin/sh\ntouch \"$0.ran\"\n")
        os.chmod(target, 0o700)
        with mock.patch.object(env.subprocess, "run", no_network):
            status = env._compiler_status()
        self.assertTrue(status["present"])
        self.assertFalse(status["pinned"])
        self.assertIsNone(status["version"])
        self.assertIn("not executed", status["error"])
        self.assertFalse(Path(str(target) + ".ran").exists())


class TestDelivery(IsolatedCase):
    def test_publish_copies_the_exact_bytes_under_a_clean_name(self):
        blob = SIGNED_FIXTURE.read_bytes()
        artifact_id = self.store(blob, "Meeting Note  2", signed=True)
        out = library.publish(artifact_id)
        path = Path(out["path"])
        self.assertEqual(path.read_bytes(), blob)
        self.assertEqual(out["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(path.name, "meeting-note-2.shortcut")
        self.assertEqual(path.parent, library.deliver_dir())
        self.assertEqual(out["media_tag"], "MEDIA:" + out["path"])
        self.assertTrue(path.is_absolute())
        self.assertNotRegex(out["path"], r"\s")

    def test_publish_twice_replaces_the_file_and_leaves_no_temp(self):
        first = self.store(b"<?xml one", "same name", signed=False)
        second = self.store(b"<?xml two", "same name", signed=False)
        library.publish(first)
        out = library.publish(second)
        self.assertEqual(Path(out["path"]).read_bytes(), b"<?xml two")
        self.assertEqual([p.name for p in library.deliver_dir().iterdir()], ["same-name.shortcut"])

    def test_unknown_artifact_is_an_error_not_an_empty_file(self):
        with self.assertRaises(FileNotFoundError):
            library.publish("0" * 16)
        with self.assertRaises(ValueError):
            library.publish("../../etc/passwd")

    def test_tool_returns_the_media_line(self):
        plugin = load_plugin()
        artifact_id = self.store(SIGNED_FIXTURE.read_bytes(), "import test", signed=True)
        payload = json.loads(plugin.talaria_library({"action": "deliver", "artifact_id": artifact_id}))
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["signed"])
        self.assertTrue(payload["deliver"]["media_tag"].startswith("MEDIA:/"))
        self.assertTrue(Path(payload["deliver"]["path"]).is_file())
        self.assertNotIn("error", payload)
        self.assertNotIn("note", payload)

    def test_tool_warns_when_the_file_is_unsigned(self):
        plugin = load_plugin()
        artifact_id = self.store(UNSIGNED_FIXTURE.read_bytes(), "meeting note", signed=False)
        payload = json.loads(plugin.talaria_library({"action": "deliver", "artifact_id": artifact_id}))
        self.assertFalse(payload["signed"])
        self.assertIn("unsigned", payload["note"])

    def test_tool_refuses_an_unknown_id(self):
        plugin = load_plugin()
        payload = json.loads(plugin.talaria_library({"action": "deliver", "artifact_id": "f" * 16}))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "unknown_artifact")


class TestLinkAudit(IsolatedCase):
    def record(self, url, field="signedShortcut"):
        return json.dumps({"fields": {
            "name": {"value": "Shared thing"},
            "signingStatus": {"value": "APPROVED"},
            field: {"value": {"downloadURL": url, "size": 1}},
        }}).encode()

    def test_only_the_public_link_shape_is_accepted(self):
        self.assertTrue(icloud.is_link(LINK))
        self.assertTrue(icloud.is_link(LINK + "/"))
        for bad in ("http://www.icloud.com/shortcuts/" + "a" * 32,
                    "https://www.icloud.com.evil.example/shortcuts/" + "a" * 32,
                    "https://evil.example/?u=https://www.icloud.com/shortcuts/" + "a" * 32,
                    "https://www.icloud.com/shortcuts/" + "a" * 31,
                    "https://www.icloud.com/shortcuts/../" + "a" * 32,
                    "file:///etc/passwd", ""):
            self.assertFalse(icloud.is_link(bad), bad)
            with self.assertRaises(icloud.LinkError):
                icloud.record_id(bad)

    def test_a_record_pointing_elsewhere_downloads_nothing(self):
        calls = []

        def fake_get(url, limit):
            calls.append(url)
            return self.record("https://evil.example/${f}")

        with mock.patch.object(icloud, "_get", fake_get):
            with self.assertRaises(icloud.LinkError) as caught:
                icloud.fetch(LINK)
        self.assertIn("nothing was downloaded", str(caught.exception))
        self.assertEqual(len(calls), 1)
        self.assertTrue(icloud.record_host(calls[0]))

    def test_lookalike_content_hosts_are_refused(self):
        self.assertTrue(icloud.content_host("https://cvws.icloud-content.com/B/x"))
        for bad in ("https://icloud-content.com.evil.example/x", "http://cvws.icloud-content.com/x",
                    "https://evil-icloud-content.com/x"):
            self.assertFalse(icloud.content_host(bad), bad)

    def test_the_signed_file_is_fetched_and_audited(self):
        blob = SIGNED_FIXTURE.read_bytes()
        seen = []

        def fake_get(url, limit):
            seen.append(url)
            if icloud.record_host(url):
                return self.record("https://cvws.icloud-content.com/B/abc/${f}?o=1")
            return blob

        with mock.patch.object(icloud, "_get", fake_get):
            report = audit.inspect_link(LINK)
        self.assertEqual(len(seen), 2)
        self.assertIn("/signed.shortcut?", seen[1])
        self.assertNotIn("${f}", seen[1])
        self.assertEqual(report["origin"]["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(report["origin"]["asset"], "signedShortcut")
        self.assertEqual(report["container"]["magic"], "AEA1")
        self.assertEqual(report["workflow"]["action_count"], 1)
        self.assertIn(report["verdict"], ("no-findings", "review", "dangerous"))

    def test_tool_never_fetches_a_link_that_is_not_icloud(self):
        plugin = load_plugin()
        with mock.patch.object(icloud, "_get", no_network):
            for bad in ("https://example.com/x.shortcut", "http://169.254.169.254/latest/meta-data/",
                        "https://www.icloud.com/shortcuts/short"):
                payload = json.loads(plugin.talaria_inspect({"url": bad}))
                self.assertFalse(payload["ok"], payload)
                self.assertIn("not a public iCloud shortcut link", payload["message"])

    def test_tool_still_reads_a_local_path(self):
        plugin = load_plugin()
        with mock.patch.object(icloud, "_get", no_network):
            payload = json.loads(plugin.talaria_inspect({"path": str(SIGNED_FIXTURE)}))
        self.assertEqual(payload["container"]["magic"], "AEA1")


class TestApprovalHook(unittest.TestCase):
    def setUp(self):
        self.hook = load_plugin()._on_pre_tool_call

    def test_download_and_upload_are_escalated_to_a_human(self):
        setup_gate = self.hook("talaria_setup", {"confirm": True})
        self.assertEqual(setup_gate["action"], "approve")
        self.assertIn("Nothing is uploaded", setup_gate["message"])
        sign_gate = self.hook("talaria_sign", {"artifact_id": "a" * 16, "consent": True})
        self.assertEqual(sign_gate["action"], "approve")
        self.assertEqual(sign_gate["rule_key"], "talaria_sign:" + "a" * 16)

    def test_one_approval_never_covers_another_artifact(self):
        first = self.hook("talaria_sign", {"artifact_id": "a" * 16, "consent": True})
        second = self.hook("talaria_sign", {"artifact_id": "b" * 16, "consent": True})
        self.assertNotEqual(first["rule_key"], second["rule_key"])

    def test_calls_that_stay_local_are_not_interrupted(self):
        for tool, args in (("talaria_setup", {}), ("talaria_setup", {"confirm": "true"}),
                           ("talaria_sign", {"artifact_id": "a" * 16}), ("talaria_build", {"name": "x"}),
                           ("talaria_inspect", {"url": LINK}), ("terminal", {"command": "ls"})):
            self.assertIsNone(self.hook(tool, args), (tool, args))


class TestManifest(unittest.TestCase):
    def test_declared_tools_are_the_registered_tools(self):
        plugin = load_plugin()
        text = (REPO / "plugin.yaml").read_text(encoding="utf-8")
        block = text.split("provides_tools:", 1)[1].split("provides_hooks:", 1)[0]
        declared = [line.strip()[2:].strip() for line in block.splitlines() if line.strip().startswith("- ")]
        self.assertEqual(sorted(declared), sorted(plugin._HANDLERS))
        self.assertEqual(sorted(plugin.SCHEMAS), sorted(plugin._HANDLERS))
        for name, schema in plugin.SCHEMAS.items():
            self.assertEqual(schema["name"], name)
            self.assertIsInstance(schema["parameters"], dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
