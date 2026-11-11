"""Tests for the Talaria build/sign engine.

Run:  cd repo && python3 -m unittest discover -s tests/python -v
      cd repo && python3 -m pytest tests/python -q      (if pytest is installed)

No test here signs anything, opens a socket to the internet, or needs the reference C
decoder: the only signing assertions are refusals, and the isolation test asserts that a
connection attempt from INSIDE the sandbox fails.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures"
sys.path.insert(0, str(REPO))

from talaria import aea, compile as tal_compile, env, library, sandbox, sign  # noqa: E402

SIGNED_FIXTURE = FIXTURES / "signed" / "import-test.shortcut"

#: The build and sign paths need the Cherri compiler. Without it those tests skip rather
#: than fail: a reviewer's machine will not have it, and the decoder and audit tests above
#: do not need it.
COMPILER = env.compiler_path()
NEEDS_COMPILER = unittest.skipUnless(
    COMPILER is not None,
    "Cherri compiler not installed: put it on PATH or set TALARIA_CHERRI to its path",
)

#: 16 actions, compiled rc=0 (facts/CHERRI-RULES.md)
SOURCE_16 = """\
#include 'actions/calendar'
#include 'actions/documents'
#include 'actions/text'

const now = currentDate()
const stamp = formatDate(now, "Custom", "yyyy-MM-dd HH:mm")
const subject = prompt("Meeting name?", "Text", "Standup")
const body = prompt("What was decided?", "Text", "")

if !body {
  alert("Empty note discarded", "Talaria")
} else {
  @line = "{stamp} | {subject} | {body}"
  saveFile("talaria/notes.txt", @line, true)
  const confirmation = "Saved to talaria notes: {subject}"
  speak(confirmation)
  show(confirmation)
}
"""

#: compiles rc=0 and yields an EMPTY action list (measured)
SOURCE_ZERO_ACTIONS = "// only a comment\n/* and a block comment */\n"


class TalariaTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="talaria-test-")
        cls._old_home = os.environ.get("TALARIA_HOME")
        os.environ["TALARIA_HOME"] = cls._tmp.name
        cls._old_deliver = os.environ.get("TALARIA_DELIVER_DIR")
        os.environ["TALARIA_DELIVER_DIR"] = os.path.join(cls._tmp.name, "deliver")

    @classmethod
    def tearDownClass(cls):
        if cls._old_home is None:
            os.environ.pop("TALARIA_HOME", None)
        else:
            os.environ["TALARIA_HOME"] = cls._old_home
        if cls._old_deliver is None:
            os.environ.pop("TALARIA_DELIVER_DIR", None)
        else:
            os.environ["TALARIA_DELIVER_DIR"] = cls._old_deliver
        cls._tmp.cleanup()


class TestEnv(TalariaTestCase):
    def test_status_reports_every_surface_it_claims(self):
        st = env.status()
        self.assertEqual(set(st), {"compiler", "sandbox", "decoder", "signer"})
        self.assertEqual(set(st["compiler"]),
                         {"present", "path", "version", "sha256", "pinned", "error"})
        self.assertEqual(set(st["sandbox"]), {"available", "mode", "bwrap_path", "reason"})
        self.assertEqual(set(st["decoder"]), {"present", "mode", "error", "detail"})
        self.assertEqual(set(st["signer"]),
                         {"reachable", "checked", "host", "port", "url", "latency_ms", "error"})

    @NEEDS_COMPILER
    def test_compiler_is_found_and_pinned(self):
        st = env.status()["compiler"]
        self.assertTrue(st["present"], st)
        self.assertRegex(st["version"], r"^v?\d+\.\d+")
        self.assertEqual(len(st["sha256"]), 64)
        self.assertTrue(st["pinned"], f"compiler sha256 {st['sha256']} is not a pinned build")

    def test_status_makes_no_network_call_by_default(self):
        """The default path must be silent: `checked` false and no reachability claim."""
        signer = env.status()["signer"]
        self.assertFalse(signer["checked"])
        self.assertIsNone(signer["reachable"])
        self.assertIn("no network call", signer["error"])

    def test_decoder_is_pure_python(self):
        decoder = env.status()["decoder"]
        self.assertTrue(decoder["present"], decoder)
        self.assertEqual(decoder["mode"], "pure-python")

    @NEEDS_COMPILER
    def test_unpinned_compiler_is_refused(self):
        with mock.patch.dict(env.PINNED, clear=True):
            with self.assertRaises(env.CompilerNotPinned):
                env.assert_pinned_compiler(env.compiler_path())


class TestSandbox(TalariaTestCase):
    @NEEDS_COMPILER
    def test_runs_isolated(self):
        if not sandbox.available():
            self.skipTest("bwrap not available on this host")
        result = sandbox.run(["--version"], library.new_jobdir("sandbox-probe"), timeout=30)
        self.assertEqual(result["isolation"], "bwrap")
        self.assertFalse(result["no_isolation"])
        self.assertEqual(result["rc"], 0)
        self.assertIn("2.4.0", result["stdout"] + result["stderr"])
        self.assertIn("--unshare-all", result["argv"])
        self.assertIn("--remount-ro", result["argv"])
        self.assertIn("--clearenv", result["argv"])

    def test_refuses_to_run_without_bwrap(self):
        """No bubblewrap means no compile, not an unsandboxed compile."""
        jobdir = library.new_jobdir("no-bwrap")
        with mock.patch.object(sandbox.shutil, "which", return_value=None):
            with self.assertRaises(sandbox.SandboxUnavailable) as ctx:
                sandbox.run(["--version"], jobdir)
        self.assertIn("will not run the compiler", str(ctx.exception))
        self.assertFalse(hasattr(sandbox, "_direct_argv"), "the unsandboxed path must be gone")

    def test_network_is_unreachable_inside_sandbox(self):
        if not sandbox.available():
            self.skipTest("bwrap not available on this host")
        curl = shutil.which("curl")
        if not curl:
            self.skipTest("curl not installed")

        def fetch(allow_network: bool) -> dict:
            return sandbox.run(
                ["-sS", "--max-time", "5", "-o", "/dev/null",
                 "-w", "%{http_code}", "http://1.1.1.1:80/"],
                library.new_jobdir("net-probe"),
                executable=curl,
                allow_network=allow_network,
                timeout=40,
            )

        blocked = fetch(False)
        self.assertNotEqual(blocked["rc"], 0, blocked)
        self.assertNotIn("200", blocked["stdout"], blocked)

        allowed = fetch(True)
        self.assertIn("--share-net", allowed["argv"])
        self.assertEqual(allowed["rc"], 0, allowed)
        self.assertEqual(allowed["stdout"].strip(), "301")

    @NEEDS_COMPILER
    def test_write_outside_the_job_dir_is_refused(self):
        """A source that names its output elsewhere must not create a file there."""
        if not sandbox.available():
            self.skipTest("bwrap not available on this host")
        jobdir = Path(library.new_jobdir("escape-probe"))
        target = jobdir.parent / "escaped-should-not-exist"
        (jobdir / "escape.cherri").write_text(
            f'#define nameX{target}\nalert("x")\n', encoding="utf-8"
        )
        sandbox.run(["escape.cherri", "--skip-sign", "--no-ansi"], jobdir, timeout=30)
        self.assertFalse(target.exists(), f"{target} was created from inside the sandbox")


class TestCompile(TalariaTestCase):
    @NEEDS_COMPILER
    def test_sixteen_action_source_builds(self):
        built = tal_compile.build(SOURCE_16, "meeting note")
        self.assertGreaterEqual(built["actions"], 10, built)
        idents = [a["identifier"] for a in built["inventory"]]
        self.assertIn("is.workflow.actions.conditional", idents)
        self.assertTrue(all(i.startswith("is.workflow.actions.") for i in idents))

        blob = Path(built["path"]).read_bytes()
        self.assertTrue(blob.startswith(b"<?xml"))
        self.assertEqual(hashlib.sha256(blob).hexdigest(), built["sha256"])
        self.assertEqual(len(blob), built["bytes"])
        plist = plistlib.loads(blob)
        self.assertEqual(len(plist["WFWorkflowActions"]), built["actions"])

    @NEEDS_COMPILER
    def test_build_argv_never_signs(self):
        built = tal_compile.build(SOURCE_16, "argv probe")
        argv = built["diagnostics"]["argv"]
        self.assertIn("--skip-sign", argv)
        self.assertIn("--no-ansi", argv)
        for forbidden in ("--derive-uuids", "--hubsign", "--signing-server",
                          "--debug", "--open", "-o", "--install"):
            self.assertNotIn(forbidden, argv, argv)
        self.assertEqual(built["diagnostics"]["isolation"], "bwrap")

    @NEEDS_COMPILER
    def test_job_directory_is_cleaned_up(self):
        built = tal_compile.build(SOURCE_16, "cleanup probe")
        self.assertFalse(Path(built["diagnostics"].get("jobdir", "/nonexistent")).exists())

    @NEEDS_COMPILER
    def test_zero_action_output_fails_the_build(self):
        with self.assertRaises(tal_compile.BuildError) as ctx:
            tal_compile.build(SOURCE_ZERO_ACTIONS, "empty")
        self.assertIn("zero actions", str(ctx.exception))

    def test_unbalanced_source_is_rejected_before_compiling(self):
        with self.assertRaises(tal_compile.BuildError) as ctx:
            tal_compile.build('alert("a")\nif 1 == 1 {\n  alert("b")\n', "unbalanced")
        self.assertIn("unbalanced-brace", str(ctx.exception))

    def test_prefilter_rejects_host_touching_source(self):
        cases = (
            ('embedFile("/etc/hostname")\n', "embedFile"),
            ("#import 'Notes'\n", "#import"),
            ('#define name ../escaped\nalert("x")\n', "#define name"),
            ('#define nameXzzz\nalert("x")\n', "#define name"),
            ('#defineXname zzz2\nalert("x")\n', "#define name"),
            ("#include '../outside.cherri'\n", "#include"),
            ("#includeX'/etc/nope.cherri'\n", "#include"),
            ("#include 'stdfunc'\n", "#include"),
        )
        for src, rule in cases:
            with self.subTest(source=src):
                findings = tal_compile.prefilter(src)
                self.assertTrue(findings, src)
                self.assertIn(rule, [f["rule"] for f in findings], findings)
                with self.assertRaises(tal_compile.BuildError):
                    tal_compile.build(src, "blocked")

    def test_prefilter_allows_real_categories(self):
        self.assertEqual(tal_compile.prefilter("#include 'actions/calendar'\n"), [])
        self.assertEqual(tal_compile.prefilter('alert("hi")\n'), [])
        self.assertEqual(tal_compile.prefilter(SOURCE_16), [])

    def test_structural_problems_catch_an_unclosed_block(self):
        actions = [
            {"WFWorkflowActionIdentifier": "is.workflow.actions.alert"},
            {"WFWorkflowActionIdentifier": "is.workflow.actions.conditional",
             "WFWorkflowActionParameters": {"GroupingIdentifier": "G1", "WFControlFlowMode": 0}},
            {"WFWorkflowActionIdentifier": "is.workflow.actions.showresult"},
        ]
        problems = tal_compile.structural_problems(actions)
        self.assertTrue(any("never closed" in p for p in problems), problems)

    def test_structural_problems_catch_a_noop_only_shortcut(self):
        actions = [{"WFWorkflowActionIdentifier": "is.workflow.actions.nothing"}]
        self.assertTrue(tal_compile.structural_problems(actions))

    @NEEDS_COMPILER
    def test_structural_problems_accept_a_balanced_shortcut(self):
        built = tal_compile.build(SOURCE_16, "structure probe")
        self.assertEqual(built["inventory"] and tal_compile.structural_problems([]), [])

    @NEEDS_COMPILER
    def test_a_name_without_ascii_still_builds(self):
        built = tal_compile.build('alert("x")\n', "\u65e5\u672c\u8a9e")
        self.assertTrue(Path(built["path"]).is_file())
        self.assertEqual(built["artifact_id"], built["sha256"][:16])


@NEEDS_COMPILER
class TestSignRefusal(TalariaTestCase):
    def test_refuses_without_consent(self):
        built = tal_compile.build(SOURCE_16, "consent probe")
        before = sorted(p.name for p in library.artifacts_dir().iterdir())
        for falsey in (False, None, "true", 1, "yes"):
            result = sign.sign(built["artifact_id"], falsey)
            self.assertTrue(result["refused"], result)
            self.assertFalse(result["uploaded"])
            self.assertIsNone(result["signed_path"])
        after = sorted(p.name for p in library.artifacts_dir().iterdir())
        self.assertEqual(before, after)

    def test_missing_consent_argument_is_not_a_type_error(self):
        built = tal_compile.build(SOURCE_16, "consent default")
        result = sign.sign(built["artifact_id"])       # no consent argument at all
        self.assertTrue(result["refused"])
        self.assertIn("hubsign", result["reason"])

    def test_strict_wrapper_raises(self):
        built = tal_compile.build(SOURCE_16, "consent strict")
        with self.assertRaises(sign.SignRefused):
            sign.require_consent(built["artifact_id"])

    def test_refusal_states_what_leaves_the_machine(self):
        built = tal_compile.build(SOURCE_16, "consent text")
        text = sign.sign(built["artifact_id"])["reason"]
        self.assertIn("hubsign.routinehub.services/sign", text)
        self.assertIn("third party", text)
        self.assertIn("every action", text)
        # it must describe the payload that is really sent, not the source file
        self.assertIn("XML plist", text)

    def test_handler_refusal_matches_the_engine_text(self):
        """The string a user sees must be the string that is tested here."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("talaria_plugin", REPO / "__init__.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        import json

        built = tal_compile.build(SOURCE_16, "handler refusal")
        payload = json.loads(plugin.talaria_sign({"artifact_id": built["artifact_id"]}))
        self.assertEqual(payload["error"], "consent_required")
        self.assertEqual(payload["message"], sign.REFUSAL)


class TestAEA(TalariaTestCase):
    def test_header_parses_on_the_signed_fixture(self):
        self.assertTrue(SIGNED_FIXTURE.is_file(), SIGNED_FIXTURE)
        blob = SIGNED_FIXTURE.read_bytes()
        hdr = aea.parse_header(blob)
        self.assertEqual(hdr["magic"], "AEA1")
        self.assertEqual(len(hdr["chain_sizes"]), 3)
        self.assertEqual(hdr["chain_sizes"], [778, 746, 583])
        self.assertTrue(any("Apple" in i for i in hdr["issuers"]), hdr["issuers"])
        self.assertTrue(hdr["apple_issued"])
        self.assertEqual(hdr["total_len"], len(blob))

    def test_body_is_not_a_plist(self):
        blob = SIGNED_FIXTURE.read_bytes()
        raw = aea.body(blob)
        self.assertGreater(len(raw), 1000)
        with self.assertRaises(Exception):
            plistlib.loads(raw)          # measured: InvalidFile

    def test_rejects_non_aea_bytes(self):
        with self.assertRaises(aea.AEAError):
            aea.parse_header(b'<?xml version="1.0"?><plist/>')


if __name__ == "__main__":
    unittest.main(verbosity=2)
