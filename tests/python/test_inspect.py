"""Tests for the Talaria audit engine.

Run:  cd repo && python3 -m unittest discover -s tests/python -v

Fixtures are real artifacts: a signed shortcut produced without a Mac, a 16-action
shortcut, and a 3-action shortcut that reads the clipboard and posts it away. No test
needs a network, a binary, or the reference C decoder.
"""

from __future__ import annotations

import os
import plistlib
import struct
import unittest
from pathlib import Path

from talaria.inspect import SHORT_NAMES, InspectError, inspect

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures"
SIGNED = FIXTURES / "signed" / "import-test.shortcut"
MEETING = FIXTURES / "unsigned" / "meeting-note.shortcut"
SUSPECT = FIXTURES / "unsigned" / "suspect.shortcut"

PREFIX = "is.workflow.actions."


def craft(actions, name="Crafted", binary=False):
    """Build an unsigned .shortcut-shaped plist from (identifier, params) pairs."""
    payload = {
        "WFWorkflowActions": [
            {"WFWorkflowActionIdentifier": i, "WFWorkflowActionParameters": p} for i, p in actions
        ],
        "WFWorkflowClientVersion": "1146.14",
        "WFWorkflowTypes": ["Watch"],
    }
    if name is not None:
        payload["WFWorkflowName"] = name
    return plistlib.dumps(payload, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML)


def forged_aea(body_plist: bytes, chain: list[bytes]) -> bytes:
    """An AEA1 prologue with a chosen certificate chain and a bare plist body."""
    auth = plistlib.dumps({"SigningCertificateChain": chain})
    prologue = b"AEA1" + b"\x00\x00\x00" + b"\x00" + struct.pack("<I", len(auth))
    return prologue + auth + body_plist


class TestSignedContainer(unittest.TestCase):
    def setUp(self):
        self.report = inspect(SIGNED)

    def test_container_is_aea1_with_an_apple_chain(self):
        c = self.report["container"]
        self.assertEqual(c["magic"], "AEA1")
        self.assertTrue(c["signed"])
        self.assertEqual(c["chain_sizes"], [778, 746, 583])
        self.assertEqual(len(c["issuers"]), 3)
        self.assertTrue(any("Apple" in i for i in c["issuers"]), c["issuers"])

    def test_the_signature_is_not_claimed_as_verified(self):
        c = self.report["container"]
        self.assertFalse(c["signature_verified"])

    def test_body_was_decompressed_in_pure_python(self):
        c = self.report["container"]
        self.assertEqual(c["compressed"], "lzfse/lzvn")
        self.assertEqual(c["decompressed_bytes"], 1568)

    def test_actions_extracted_from_the_signed_body(self):
        w = self.report["workflow"]
        self.assertEqual(w["action_count"], 1)
        self.assertEqual(w["actions"][0]["identifier"], PREFIX + "alert")
        self.assertEqual(w["actions"][0]["short"], "Show Alert")
        self.assertEqual(self.report["verdict"], "no-findings")
        self.assertEqual(self.report["findings"], [])

    def test_path_and_bytes_agree(self):
        self.assertEqual(inspect(SIGNED.read_bytes()), self.report)


class TestUnsignedContainers(unittest.TestCase):
    def test_meeting_note_inventory(self):
        r = inspect(MEETING)
        self.assertEqual(r["container"]["magic"], "xml")
        self.assertFalse(r["container"]["signed"])
        self.assertEqual(r["workflow"]["action_count"], 16)
        ids = [a["identifier"] for a in r["workflow"]["actions"]]
        self.assertEqual(ids[0], PREFIX + "date")
        self.assertIn(PREFIX + "documentpicker.save", ids)

    def test_binary_plist_container_is_read(self):
        """bplist00 is the normal encoding of unsigned files; a 6-byte compare missed it."""
        blob = craft([(PREFIX + "alert", {"WFAlertActionMessage": "hi"})], binary=True)
        self.assertEqual(blob[:8], b"bplist00")
        report = inspect(blob)
        self.assertEqual(report["container"]["magic"], "bplist00")
        self.assertEqual(report["workflow"]["action_count"], 1)

    def test_tilde_paths_are_expanded(self):
        with self.assertRaises(InspectError) as ctx:
            inspect("~/definitely-not-here.shortcut")
        self.assertIn(os.path.expanduser("~"), str(ctx.exception))

    def test_actions_key_must_be_a_list(self):
        blob = plistlib.dumps({"WFWorkflowActions": 5})
        with self.assertRaises(InspectError) as ctx:
            inspect(blob)
        self.assertIn("not a list", str(ctx.exception))


class TestRiskRules(unittest.TestCase):
    def test_clipboard_then_post_is_dangerous(self):
        r = inspect(SUSPECT)
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("NET_WRITE", codes)
        self.assertTrue({"CLIPBOARD_READ", "CLIPBOARD_VARIABLE_READ"} & codes, codes)
        self.assertEqual(r["verdict"], "dangerous")
        net = [f for f in r["findings"] if f["code"] == "NET_WRITE"][0]
        self.assertIn("method=POST", net["evidence"])

    def test_get_only_is_a_read_not_a_write(self):
        r = inspect(craft([(PREFIX + "downloadurl", {"WFURL": "https://example.com/x.json"})]))
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("NET_READ", codes)
        self.assertNotIn("NET_WRITE", codes)

    def test_save_to_files_fires_on_the_meeting_note(self):
        r = inspect(MEETING)
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("SAVE_TO_FILES", codes)
        self.assertNotIn("NET_WRITE", codes)
        self.assertEqual(r["verdict"], "review")

    def test_url_scheme_launch_is_flagged_on_the_real_opener(self):
        """openURL compiles to `openurl` with WFInput, not to the passive `url` action."""
        r = inspect(craft([(PREFIX + "openurl", {"WFInput": "shortcuts://run-shortcut?name=X"})]))
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("URL_SCHEME_OPEN", codes)
        self.assertEqual(r["verdict"], "dangerous")

    def test_plain_web_url_is_not_flagged(self):
        r = inspect(craft([(PREFIX + "openurl", {"WFInput": "https://example.com"})]))
        self.assertEqual([f["code"] for f in r["findings"]], [])
        self.assertEqual(r["verdict"], "no-findings")

    def test_dynamic_url_is_reported_as_dynamic(self):
        r = inspect(craft([(PREFIX + "openurl", {"WFInput": {"Value": {"Type": "Variable"}}})]))
        self.assertIn("URL_OPEN_DYNAMIC", {f["code"] for f in r["findings"]})

    def test_self_call_is_not_a_recursion_flag(self):
        r = inspect(craft([(PREFIX + "runworkflow", {"WFWorkflow": {"isSelf": True}})]))
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("RUN_SELF", codes)
        self.assertNotIn("RUN_SHORTCUT_RECURSION", codes)

    def test_named_high_risk_actions_are_named(self):
        for ident, code in (
            (PREFIX + "runsshscript", "SSH_EXEC"),
            (PREFIX + "sendmessage", "SEND_MESSAGE"),
            (PREFIX + "file.delete", "FILE_DELETE"),
            (PREFIX + "openpasswords", "PASSWORD_ACCESS"),
        ):
            with self.subTest(identifier=ident):
                r = inspect(craft([(ident, {})]))
                self.assertIn(code, {f["code"] for f in r["findings"]})
                self.assertEqual(r["verdict"], "dangerous")

    def test_location_health_contacts_are_flagged(self):
        r = inspect(craft([
            (PREFIX + "getcurrentlocation", {}),
            (PREFIX + "healthquantitysample", {}),
            (PREFIX + "getcontacts", {}),
        ]))
        codes = {f["code"] for f in r["findings"]}
        for expected in ("LOCATION_ACCESS", "HEALTH_ACCESS", "CONTACTS_ACCESS"):
            self.assertIn(expected, codes)


class TestFailsClosed(unittest.TestCase):
    def test_an_unknown_action_is_reported_not_ignored(self):
        ident = "com.example.private.ExfiltrateEverythingIntent"
        r = inspect(craft([(ident, {"WFThing": 1})]))
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("UNASSESSED_ACTION", codes)
        self.assertEqual(r["verdict"], "review")
        self.assertEqual(r["workflow"]["unassessed"], 1)
        self.assertEqual(r["workflow"]["actions"][0]["short"], ident)

    def test_a_known_benign_action_is_not_flagged(self):
        r = inspect(craft([(PREFIX + "alert", {"WFAlertActionMessage": "hi"})]))
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["verdict"], "no-findings")
        self.assertEqual(r["workflow"]["assessed"], 1)
        self.assertEqual(r["workflow"]["unassessed"], 0)

    def test_zero_actions_is_review_not_clean(self):
        r = inspect(craft([]))
        self.assertIn("EMPTY_SHORTCUT", {f["code"] for f in r["findings"]})
        self.assertEqual(r["verdict"], "review")

    def test_a_forged_container_is_an_anomaly(self):
        """An AEA1 prologue with an empty chain is not something Apple produces."""
        body = craft([(PREFIX + "runsshscript", {})], name=None)
        r = inspect(forged_aea(body, []))
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("CONTAINER_ANOMALY", codes)
        self.assertEqual(r["verdict"], "dangerous")

    def test_a_bare_plist_inside_aea_is_an_anomaly(self):
        body = craft([(PREFIX + "alert", {"WFAlertActionMessage": "hi"})], name=None)
        # A 0-byte chain is impossible from Apple, and the body is a plain plist.
        r = inspect(forged_aea(body, []))
        self.assertIn("CONTAINER_ANOMALY", {f["code"] for f in r["findings"]})

    def test_rejects_non_shortcut_bytes(self):
        with self.assertRaises(InspectError):
            inspect(b"PK\x03\x04 not a shortcut")

    def test_short_names_are_real_identifiers(self):
        for ident in SHORT_NAMES:
            self.assertTrue(ident.startswith(PREFIX), ident)


if __name__ == "__main__":
    unittest.main()
