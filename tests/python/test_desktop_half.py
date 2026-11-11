"""Tests for the desktop half (desktop/plugin.js) against the package identity.

Run:  cd repo && python3 -m unittest discover -s tests/python -t . -v

The desktop half is plain ESM loaded by the Hermes Desktop renderer. Two defects reached a
running app before these tests existed: the exported id did not follow the package rename, so
ctx.rest() called a backend prefix that was never mounted; and backend ISO timestamps were
handed to sdk.relativeTime, which takes epoch milliseconds and throws on anything else.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLUGIN_JS = REPO / "desktop" / "plugin.js"


def _manifest_name() -> str:
    for line in (REPO / "plugin.yaml").read_text(encoding="utf-8").splitlines():
        if line.startswith("name:"):
            return line.split(":", 1)[1].strip().strip("\"'")
    raise AssertionError("plugin.yaml has no name")


def _manifest_tools() -> list[str]:
    tools, inside = [], False
    for line in (REPO / "plugin.yaml").read_text(encoding="utf-8").splitlines():
        if line.startswith("provides_tools:"):
            inside = True
            continue
        if inside:
            item = re.match(r"\s+-\s+(\S+)", line)
            if not item:
                break
            tools.append(item.group(1))
    return tools


class DesktopIdentity(unittest.TestCase):
    def setUp(self) -> None:
        self.source = PLUGIN_JS.read_text(encoding="utf-8")
        self.name = _manifest_name()

    def test_exported_id_is_the_package_name(self) -> None:
        ids = re.findall(r"^  id: '([^']+)'", self.source, flags=re.M)
        self.assertEqual(ids, [self.name])

    def test_dashboard_manifest_carries_the_same_name(self) -> None:
        manifest = json.loads((REPO / "dashboard" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], self.name)

    def test_every_backend_path_named_in_the_source_uses_the_package_name(self) -> None:
        prefixes = set(re.findall(r"/api/plugins/([a-z0-9-]+)/", self.source))
        self.assertEqual(prefixes, {self.name})

    def test_tool_card_covers_every_declared_tool(self) -> None:
        block = re.search(r"const TOOLS = \[(.*?)\]", self.source, flags=re.S)
        self.assertIsNotNone(block)
        assert block is not None
        listed = re.findall(r"'([a-z_]+)'", block.group(1))
        self.assertEqual(sorted(listed), sorted(_manifest_tools()))


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class DesktopTime(unittest.TestCase):
    def _run(self, expression: str) -> str:
        body = re.search(r"function toMillis\(value\) \{.*?\n\}", PLUGIN_JS.read_text(encoding="utf-8"), flags=re.S)
        self.assertIsNotNone(body, "toMillis is missing from desktop/plugin.js")
        assert body is not None
        script = body.group(0) + "\nconsole.log(JSON.stringify(" + expression + "))"
        done = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def test_backend_iso_stamp_becomes_epoch_milliseconds(self) -> None:
        # The exact shape library.py writes: local time with a colon-less offset.
        self.assertEqual(self._run("toMillis('2026-11-11T14:12:36+0100')"), "1794402756000")

    def test_seconds_and_milliseconds_are_both_accepted(self) -> None:
        self.assertEqual(self._run("[toMillis(1794402756), toMillis(1794402756000)]"),
                         "[1794402756000,1794402756000]")

    def test_garbage_is_not_a_finite_number(self) -> None:
        self.assertEqual(self._run("[toMillis(''), toMillis(null), toMillis('nope')].map(Number.isFinite)"),
                         "[false,false,false]")


if __name__ == "__main__":
    unittest.main()
