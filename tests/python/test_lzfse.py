"""Tests for the pure-Python LZFSE / LZVN decoder.

The vectors live in `tests/fixtures/lzfse-vectors.json` as base64 text, not as binary
files: the catalog refuses a payload a reviewer cannot read, and the plugin security scan
warns on any binary file in the tree. Each vector carries a recipe that rebuilds its
expected output in code, so every decoded byte is still compared.

Where the vectors come from: Apple's reference encoder (BSD-3, github.com/lzfse/lzfse)
was run locally on each input, and the reference decoder was run on the result. The
compressed bytes are what Apple's encoder wrote; the expected bytes are what Apple's
decoder returned. Nothing in this file shells out, installs, or downloads.
"""

from __future__ import annotations

import base64
import hashlib
import json
import plistlib
import random
import unittest
from pathlib import Path

from talaria import lzfse

VECTORS_PATH = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "lzfse-vectors.json"


def expected_bytes(recipe: dict) -> bytes:
    kind = recipe["kind"]
    if kind == "literal":
        return bytes.fromhex(recipe["value_hex"])
    if kind == "b64":
        return base64.b64decode(recipe["value"])
    if kind == "pattern":
        return recipe["unit"].encode() * recipe["repeat"]
    if kind == "crafted_plist":
        count = recipe["actions"]
        return plistlib.dumps({
            "WFWorkflowActions": [
                {
                    "WFWorkflowActionIdentifier": "is.workflow.actions.alert",
                    "WFWorkflowActionParameters": {"WFAlertActionMessage": f"step {i} of {count}"},
                }
                for i in range(count)
            ],
            "WFWorkflowClientVersion": "1146.14",
            "WFWorkflowTypes": ["Watch"],
        })
    if kind == "seeded_random":
        return random.Random(recipe["seed"]).randbytes(recipe["size"])
    raise AssertionError(f"unknown recipe {kind}")


def load_vectors() -> list[dict]:
    with open(VECTORS_PATH, encoding="utf-8") as handle:
        return json.load(handle)["vectors"]


class TestVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()

    def test_the_fixture_file_exists_and_is_text(self):
        self.assertTrue(VECTORS_PATH.is_file(), VECTORS_PATH)
        raw = VECTORS_PATH.read_bytes()
        self.assertFalse(raw.startswith(b"\x7fELF"))
        raw.decode("utf-8")                      # must be readable text

    def test_every_vector_decodes_byte_for_byte(self):
        for vector in self.vectors:
            with self.subTest(name=vector["name"]):
                encoded = base64.b64decode(vector["compressed_b64"])
                self.assertEqual(encoded[:4].decode("latin1"), vector["magic"])
                expected = expected_bytes(vector["expected"])
                self.assertEqual(len(expected), vector["raw_bytes"])
                self.assertEqual(hashlib.sha256(expected).hexdigest(), vector["raw_sha256"])
                self.assertEqual(lzfse.decompress(encoded), expected)

    def test_all_three_block_classes_are_covered(self):
        magics = {vector["magic"] for vector in self.vectors}
        self.assertEqual(magics, {"bvx-", "bvxn", "bvx2"},
                         "the set must exercise stored, LZVN and LZFSE v2 blocks")


class TestAppleContainer(unittest.TestCase):
    def test_a_real_signed_payload_is_lzvn(self):
        """The two signed files produced during development both hold an LZVN stream."""
        vector = next(v for v in load_vectors() if v["name"] == "apple-lzvn")
        encoded = base64.b64decode(vector["compressed_b64"])
        self.assertEqual(encoded[:4], b"bvxn")
        self.assertEqual(lzfse.find_stream(encoded), 0)
        out = lzfse.decompress(encoded)
        self.assertEqual(len(out), 1568)
        self.assertIn(b"bplist00", out)


class TestOpcodeTable(unittest.TestCase):
    def test_class_sizes_match_the_reference_jump_table(self):
        kinds = lzfse._LZVN_KIND
        self.assertEqual(len(kinds), 256)
        self.assertEqual(kinds.count("sml_d"), 120)
        self.assertEqual(kinds.count("lrg_d"), 20)
        self.assertEqual(kinds.count("pre_d"), 12)
        self.assertEqual(kinds.count("med_d"), 32)
        self.assertEqual(kinds.count("sml_l"), 15)
        self.assertEqual(kinds.count("sml_m"), 15)
        self.assertEqual(kinds.count("udef"), 37)
        self.assertEqual(kinds.count("eos"), 1)
        self.assertEqual(kinds.count("nop"), 2)

    def test_known_opcodes_land_in_the_right_class(self):
        expect = {
            0x06: "eos", 0x0E: "nop", 0x00: "sml_d", 0x07: "lrg_d", 0x46: "pre_d",
            0xA0: "med_d", 0xE0: "lrg_l", 0xE1: "sml_l", 0xF0: "lrg_m", 0xFF: "sml_m",
            0x70: "udef", 0xD0: "udef",
        }
        for opc, kind in expect.items():
            with self.subTest(opcode=hex(opc)):
                self.assertEqual(lzfse._LZVN_KIND[opc], kind)


class TestFailureIsLoud(unittest.TestCase):
    def test_empty_input_raises(self):
        with self.assertRaises(lzfse.LZFSEError):
            lzfse.decompress(b"")

    def test_not_a_stream_raises(self):
        with self.assertRaises(lzfse.LZFSEError) as ctx:
            lzfse.decompress(b"<?xml version='1.0'?><plist/>")
        self.assertIn("no LZFSE block magic", str(ctx.exception))

    def test_truncated_stream_raises(self):
        vector = next(v for v in load_vectors() if v["name"] == "apple-lzvn")
        encoded = base64.b64decode(vector["compressed_b64"])
        with self.assertRaises(lzfse.LZFSEError):
            lzfse.decompress(encoded[: len(encoded) // 3])

    def test_missing_end_of_stream_raises(self):
        vector = next(v for v in load_vectors() if v["name"] == "tiny")
        encoded = base64.b64decode(vector["compressed_b64"])
        self.assertTrue(encoded.endswith(b"bvx$"))
        with self.assertRaises(lzfse.LZFSEError):
            lzfse.decompress(encoded[:-4])

    def test_corrupt_block_raises(self):
        with self.assertRaises(lzfse.LZFSEError):
            lzfse.decompress(b"bvx2" + b"\x00" * 40)

    def test_absurd_declared_size_is_refused_fast(self):
        payload = b"bvx-" + (0xFFFFFFFF).to_bytes(4, "little") + b"short"
        with self.assertRaises(lzfse.LZFSEError):
            lzfse.decompress(payload)

    def test_type_error_on_non_bytes(self):
        with self.assertRaises(TypeError):
            lzfse.decompress("not bytes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
