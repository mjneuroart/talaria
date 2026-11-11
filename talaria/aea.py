"""AEA1 container parsing (what a signed .shortcut actually is).

Measured layout of exp/signed/hello-hubsign.shortcut (22011 bytes):

    off 0     "AEA1"
    off 4     uint32 LE flags          = 0
    off 8     uint32 LE header_len     = 2204
    off 12    bplist00 header, header_len bytes   (plistlib parses this slice)
    off 2216  DER ECDSA signature (0x30 0x45 ... , 73 bytes)
    off 2289  zero padding
    off 2325  body ... 22011 (ends with the LZFSE end-of-stream magic "bvx$")

The header plist holds one key, SigningCertificateChain: a list of DER certs
(778 / 746 / 583 bytes here; leaf = "Apple System Integration CA 4" style
issuer chain, root issuer contains "Apple").

The BODY is LZFSE-compressed: parsing it with plistlib raises InvalidFile.
This module therefore never tries.  It exposes the raw body, plus a decoder
hook (register_body_decoder) that another module fills in.
"""

from __future__ import annotations

import plistlib
import struct
from typing import Callable

MAGIC = b"AEA1"

#: LZFSE stream/block magics, used only to describe the body.
LZFSE_MAGICS = (b"bvx2", b"bvx1", b"bvxn", b"bvx-", b"bvx$")

BodyDecoder = Callable[[bytes], bytes]
_decoder: BodyDecoder | None = None


class AEAError(ValueError):
    """The bytes are not a parseable AEA1 container."""


class BodyDecoderMissing(RuntimeError):
    """No LZFSE decoder registered: the body cannot be decompressed here."""


def register_body_decoder(fn: BodyDecoder) -> None:
    """Install the LZFSE decompressor (e.g. a ctypes binding to liblzfse)."""
    global _decoder
    if not callable(fn):
        raise TypeError("body decoder must be callable")
    _decoder = fn


def has_body_decoder() -> bool:
    return _decoder is not None


# --------------------------------------------------------------------------
# Minimal DER reader: enough to name the certificates, nothing more.
# --------------------------------------------------------------------------

def _tlv(buf: bytes, i: int) -> tuple[int, int, int, int]:
    """Return (tag, start_of_value, end_of_value, next_index)."""
    if i + 2 > len(buf):
        raise AEAError("truncated DER")
    tag = buf[i]
    length = buf[i + 1]
    j = i + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or j + n > len(buf):
            raise AEAError("bad DER length")
        length = int.from_bytes(buf[j:j + n], "big")
        j += n
    end = j + length
    if end > len(buf):
        raise AEAError("DER value runs past end")
    return tag, j, end, end


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    i = start
    while i < end:
        tag, vs, ve, nxt = _tlv(buf, i)
        out.append((tag, vs, ve))
        i = nxt
    return out


def _name_rdns(buf: bytes, start: int, end: int) -> list[str]:
    """Flatten an X.501 Name into ['CN=..', 'O=..'] strings."""
    labels = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU",
              "2.5.4.6": "C", "2.5.4.5": "serialNumber"}
    out: list[str] = []
    for tag, s, e in _children(buf, start, end):       # tag 0x31: SET
        if tag != 0x31:
            continue
        for t2, s2, e2 in _children(buf, s, e):        # SEQUENCE(OID, value)
            if t2 != 0x30:
                continue
            parts = _children(buf, s2, e2)
            if len(parts) < 2:
                continue
            _, os_, oe = parts[0]
            oid = _decode_oid(buf[os_:oe])
            vtag, vs, ve = parts[1]
            raw = buf[vs:ve]
            text = raw.decode("utf-16-be", "replace") if vtag == 0x1E else raw.decode("utf-8", "replace")
            out.append(f"{labels.get(oid, oid)}={text}")
    return out


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for byte in raw[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def cert_facts(der: bytes) -> dict:
    """{subject, issuer, serial, not_before, not_after, size} for one DER cert."""
    tag, s, e, _ = _tlv(der, 0)
    if tag != 0x30:
        raise AEAError("certificate is not a DER SEQUENCE")
    cert = _children(der, s, e)
    if not cert or cert[0][0] != 0x30:
        raise AEAError("certificate has no tbsCertificate")
    _, ts, te = cert[0]
    fields = _children(der, ts, te)
    if fields and fields[0][0] == 0xA0:      # explicit [0] version
        fields = fields[1:]
    # serial, signatureAlgorithm, issuer, validity, subject, spki
    issuer = _name_rdns(der, fields[2][1], fields[2][2]) if len(fields) > 3 else []
    subject = _name_rdns(der, fields[4][1], fields[4][2]) if len(fields) > 5 else []
    serial = der[fields[0][1]:fields[0][2]].hex() if fields else None
    not_before = not_after = None
    if len(fields) > 3:
        val = _children(der, fields[3][1], fields[3][2])
        if len(val) == 2:
            not_before = _asn1_time(der[val[0][1]:val[0][2]])
            not_after = _asn1_time(der[val[1][1]:val[1][2]])
    return {
        "subject": ", ".join(subject),
        "issuer": ", ".join(issuer),
        "serial": serial,
        "not_before": not_before,
        "not_after": not_after,
        "size": len(der),
    }


def _asn1_time(raw: bytes) -> str:
    text = raw.decode("ascii", "replace")
    if text.endswith("Z"):
        text = text[:-1]
    if len(text) == 12:                       # UTCTime YYMMDDHHMMSS
        yy = int(text[:2])
        text = ("19" if yy >= 50 else "20") + text
    return text


# --------------------------------------------------------------------------
# Container
# --------------------------------------------------------------------------

def parse_header(blob: bytes) -> dict:
    """Parse the AEA1 header.  Raises AEAError on anything unexpected."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("parse_header expects bytes")
    blob = bytes(blob)
    if len(blob) < 12 or blob[:4] != MAGIC:
        raise AEAError(f"not an AEA1 container (first 4 bytes: {blob[:4]!r})")

    flags = struct.unpack("<I", blob[4:8])[0]
    header_len = struct.unpack("<I", blob[8:12])[0]
    header_end = 12 + header_len
    if header_len == 0 or header_end > len(blob):
        raise AEAError(f"header length {header_len} does not fit in {len(blob)} bytes")

    try:
        header = plistlib.loads(blob[12:header_end])
    except Exception as exc:                     # plistlib raises several types
        raise AEAError(f"header plist unreadable: {type(exc).__name__}: {exc}") from exc
    if not isinstance(header, dict):
        raise AEAError("header plist is not a dictionary")

    chain = header.get("SigningCertificateChain") or []
    if not isinstance(chain, list):
        raise AEAError("SigningCertificateChain is not a list")
    certs = [cert_facts(c) for c in chain if isinstance(c, (bytes, bytearray))]

    sig_len = 0
    if header_end + 2 <= len(blob) and blob[header_end] == 0x30:
        try:
            _, _, _, sig_end = _tlv(blob, header_end)
            sig_len = sig_end - header_end
        except AEAError:
            sig_len = 0

    raw_offset = header_end + sig_len
    body_offset = raw_offset
    while body_offset < len(blob) and blob[body_offset] == 0x00:
        body_offset += 1

    return {
        "magic": blob[:4].decode("ascii", "replace"),
        "flags": flags,
        "header_len": header_len,
        "header_keys": sorted(header.keys()),
        "chain": [c for c in chain if isinstance(c, (bytes, bytearray))],
        "chain_sizes": [len(c) for c in chain if isinstance(c, (bytes, bytearray))],
        "certs": certs,
        "issuers": [c["issuer"] for c in certs],
        "subjects": [c["subject"] for c in certs],
        "apple_issued": any("apple" in c["issuer"].lower() for c in certs),
        "header_end": header_end,
        "signature_len": sig_len,
        "body_offset_raw": raw_offset,
        "body_offset": body_offset,
        "total_len": len(blob),
    }


def body(blob: bytes, header: dict | None = None) -> bytes:
    """Raw (still LZFSE-compressed) body bytes."""
    hdr = header or parse_header(blob)
    return bytes(blob[hdr["body_offset"]:])


def scan_blocks(raw: bytes) -> list[dict]:
    """Locate LZFSE block magics inside the body.  Evidence, not decompression."""
    found = []
    for i in range(len(raw) - 4):
        magic = raw[i:i + 4]
        if magic in LZFSE_MAGICS:
            found.append({"offset": i, "magic": magic.decode("ascii", "replace")})
    return found


def decode_body(blob: bytes, header: dict | None = None) -> bytes:
    """Decompress the body through the registered hook, or explain why not."""
    if _decoder is None:
        raise BodyDecoderMissing(
            "no LZFSE decoder registered; call aea.register_body_decoder(fn) "
            "with a ctypes binding to liblzfse (lzfse_decode_buffer)"
        )
    return _decoder(body(blob, header))


def summary(blob: bytes) -> dict:
    """Header facts plus a body description; never decompresses."""
    hdr = parse_header(blob)
    raw = body(blob, hdr)
    return {
        "magic": hdr["magic"],
        "header_len": hdr["header_len"],
        "flags": hdr["flags"],
        "chain_sizes": hdr["chain_sizes"],
        "issuers": hdr["issuers"],
        "subjects": hdr["subjects"],
        "apple_issued": hdr["apple_issued"],
        "signature_len": hdr["signature_len"],
        "body_offset": hdr["body_offset"],
        "body_len": len(raw),
        "body_blocks": scan_blocks(raw),
        "body_decoder": has_body_decoder(),
        "total_len": hdr["total_len"],
    }
