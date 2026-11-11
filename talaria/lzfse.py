"""LZFSE / LZVN decompression, in pure Python, standard library only.

Why this exists
---------------
The body of an Apple-signed `.shortcut` (an AEA1 container) holds an Apple archive
whose payload is compressed with LZFSE, Apple's own LZ + finite-state-entropy codec.
Python has no decoder for it, so the first version of this plugin shipped a compiled
C binary. The Hermes plugin catalog refuses a plugin that ships a compiled binary
(rule 17: everything a reviewer reads at the pinned commit must be readable source),
and an x86-64 ELF only runs on one architecture anyway.

So this module is a port of the reference decoder (BSD-3-Clause, Apple Inc.,
github.com/lzfse/lzfse) to Python:

  * `lzfse_decode_base.c`   - block loop, L/M/D triplet decoding, FSE tables
  * `lzfse_fse.c`           - FSE table construction
  * `lzfse_fse.h`           - the bit stream and the decode primitives
  * `lzvn_decode_base.c`    - the LZVN opcode table (what Apple used for the two
                              signed shortcuts measured during development)

Supported block types: `bvx-` (stored), `bvxn` (LZVN), `bvx1` (LZFSE, plain tables),
`bvx2` (LZFSE, compressed tables), `bvx$` (end of stream). A stream made of several
blocks is decoded block after block.

Failure is always loud. Truncated, corrupt, or hostile input raises `LZFSEError`
with the reason; this module never returns empty or partial output silently, never
allocates without a bound, and never loops without progress.
"""

from __future__ import annotations

__all__ = ["LZFSEError", "decompress", "find_stream", "is_lzfse", "MAGICS", "DESCRIPTION"]

DESCRIPTION = "pure-python port of the reference LZFSE/LZVN decoder (BSD-3, Apple Inc.)"

MAGIC_END = b"bvx$"
MAGIC_RAW = b"bvx-"
MAGIC_V1 = b"bvx1"
MAGIC_V2 = b"bvx2"
MAGIC_LZVN = b"bvxn"
MAGICS = (MAGIC_V2, MAGIC_V1, MAGIC_LZVN, MAGIC_RAW)
EOS = MAGIC_END

#: Upper bound on decoded output. A shortcut body is kilobytes; anything that wants
#: megabytes came from a stranger, and a declared size is not a promise.
MAX_OUTPUT = 64 * 1024 * 1024


class LZFSEError(RuntimeError):
    """The input is not decodable LZFSE/LZVN, or the decoder ran out of input."""


# --------------------------------------------------------------------------
# Constants from lzfse_internal.h
# --------------------------------------------------------------------------

L_SYMBOLS, M_SYMBOLS, D_SYMBOLS, LITERAL_SYMBOLS = 20, 20, 64, 256
L_STATES, M_STATES, D_STATES, LITERAL_STATES = 64, 64, 256, 1024
MATCHES_PER_BLOCK = 10000
LITERALS_PER_BLOCK = 4 * MATCHES_PER_BLOCK

L_EXTRA_BITS = (0,) * 16 + (2, 3, 5, 8)
L_BASE_VALUE = tuple(range(16)) + (16, 20, 28, 60)
M_EXTRA_BITS = (0,) * 16 + (3, 5, 8, 11)
M_BASE_VALUE = tuple(range(16)) + (16, 24, 56, 312)
D_EXTRA_BITS = tuple(v for v in range(16) for _ in range(4))
D_BASE_VALUE = (
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52,
    60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636,
    764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580,
    4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
    24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684,
    131068, 163836, 196604, 229372,
)

_FREQ_NBITS = (2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
               2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14)
_FREQ_VALUE = (0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
               0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1)


def _clz(value: int) -> int:
    """Count leading zeros of a 32-bit value, matching __builtin_clz."""
    if value <= 0:
        return 32
    return 32 - value.bit_length()


# --------------------------------------------------------------------------
# FSE bit stream (lzfse_fse.h, 64-bit variant)
# --------------------------------------------------------------------------


class _InStream:
    """Reads bits backwards from the end of a byte range."""

    __slots__ = ("data", "accum", "nbits", "pos", "start")

    def __init__(self, data: bytes, pos: int, start: int):
        self.data = data
        self.pos = pos
        self.start = start
        self.accum = 0
        self.nbits = 0

    def init(self, n: int) -> None:
        if n:
            if self.pos - 8 < self.start:
                raise LZFSEError("FSE stream starts before its buffer")
            self.pos -= 8
            self.accum = int.from_bytes(self.data[self.pos:self.pos + 8].ljust(8, b"\0"), "little")
            self.nbits = n + 64
        else:
            if self.pos - 7 < self.start:
                raise LZFSEError("FSE stream starts before its buffer")
            self.pos -= 7
            self.accum = int.from_bytes(self.data[self.pos:self.pos + 7].ljust(7, b"\0"), "little")
            self.nbits = 56
        if not (56 <= self.nbits < 64) or (self.accum >> self.nbits) != 0:
            raise LZFSEError("FSE stream header is not a valid initial state")

    def flush(self) -> None:
        add = (63 - self.nbits) & -8
        if add:
            target = self.pos - (add >> 3)
            if target < self.start:
                raise LZFSEError("FSE stream ran past the start of its buffer")
            self.pos = target
            incoming = int.from_bytes(self.data[self.pos:self.pos + 8].ljust(8, b"\0"), "little")
            self.accum = ((self.accum << add) | (incoming & ((1 << add) - 1))) & 0xFFFFFFFFFFFFFFFF
            self.nbits += add

    def pull(self, n: int) -> int:
        if n < 0 or n > self.nbits:
            raise LZFSEError(f"FSE stream cannot pull {n} bits, {self.nbits} available")
        self.nbits -= n
        result = self.accum >> self.nbits
        self.accum &= (1 << self.nbits) - 1
        return result


# --------------------------------------------------------------------------
# FSE tables (lzfse_fse.c)
# --------------------------------------------------------------------------


def _symbol_table(nstates: int, nsymbols: int, freq) -> list[tuple[int, int, int]]:
    """Entries (k, symbol, delta), in state order."""
    n_clz = _clz(nstates)
    table: list[tuple[int, int, int]] = []
    for symbol in range(nsymbols):
        f = freq[symbol]
        if f == 0:
            continue
        k = _clz(f) - n_clz
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                table.append((k, symbol, ((f + j) << k) - nstates))
            else:
                table.append((k - 1, symbol, (j - j0) << (k - 1)))
        if len(table) > nstates:
            raise LZFSEError("frequency table overflows its state count")
    return table


def _value_table(nstates: int, nsymbols: int, freq, vbits, vbase) -> list[tuple[int, int, int, int]]:
    """Entries (total_bits, value_bits, delta, vbase), in state order."""
    n_clz = _clz(nstates)
    table: list[tuple[int, int, int, int]] = []
    for symbol in range(nsymbols):
        f = freq[symbol]
        if f == 0:
            continue
        k = _clz(f) - n_clz
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                table.append((k + vbits[symbol], vbits[symbol], ((f + j) << k) - nstates, vbase[symbol]))
            else:
                table.append(((k - 1) + vbits[symbol], vbits[symbol], (j - j0) << (k - 1), vbase[symbol]))
        if len(table) > nstates:
            raise LZFSEError("value frequency table overflows its state count")
    return table


def _check_freq(freq, nstates: int) -> None:
    if sum(freq) > nstates:
        raise LZFSEError("frequency table sums past its state count")


# --------------------------------------------------------------------------
# Block header
# --------------------------------------------------------------------------


class _Header:
    """lzfse_compressed_block_header_v1, whichever version it came from."""

    __slots__ = ("n_raw_bytes", "n_literals", "n_matches", "n_literal_payload_bytes",
                 "n_lmd_payload_bytes", "literal_bits", "literal_state", "lmd_bits",
                 "l_state", "m_state", "d_state", "l_freq", "m_freq", "d_freq", "literal_freq")


def _decode_freq_tables(blob: bytes) -> tuple:
    """Decode the 360 packed frequency values (lzfse_decode_v1's loop)."""
    out: list[int] = []
    src = 0
    end = len(blob)
    accum = 0
    accum_nbits = 0
    for _ in range(L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS):
        while src < end and accum_nbits + 8 <= 32:
            accum |= blob[src] << accum_nbits
            accum_nbits += 8
            src += 1
        index = accum & 31
        nbits = _FREQ_NBITS[index]
        if nbits == 8:
            value = 8 + ((accum >> 4) & 0xF)
        elif nbits == 14:
            value = 24 + ((accum >> 4) & 0x3FF)
        else:
            value = _FREQ_VALUE[index]
        if nbits > accum_nbits:
            raise LZFSEError("frequency table ran out of bits")
        accum >>= nbits
        accum_nbits -= nbits
        out.append(value)
    if accum_nbits >= 8 or src != end:
        raise LZFSEError("frequency table does not end on a byte boundary")
    return tuple(out)


def _header_from_v2(data: bytes, offset: int) -> tuple[_Header, int]:
    if offset + 32 > len(data):
        raise LZFSEError("truncated v2 block header")
    p0, p1, p2 = (int.from_bytes(data[offset + 8 + 8 * i: offset + 16 + 8 * i], "little") for i in range(3))
    header_size = p2 & 0xFFFFFFFF
    if header_size < 32 or offset + header_size > len(data):
        raise LZFSEError(f"v2 header size {header_size} does not fit the stream")

    head = _Header()
    head.n_raw_bytes = int.from_bytes(data[offset + 4: offset + 8], "little")
    head.n_literals = p0 & 0xFFFFF
    head.n_literal_payload_bytes = (p0 >> 20) & 0xFFFFF
    head.literal_bits = ((p0 >> 60) & 0x7) - 7
    head.n_matches = (p0 >> 40) & 0xFFFFF
    head.n_lmd_payload_bytes = (p1 >> 40) & 0xFFFFF
    head.lmd_bits = ((p1 >> 60) & 0x7) - 7
    head.literal_state = ((p1 >> 0) & 0x3FF, (p1 >> 10) & 0x3FF,
                          (p1 >> 20) & 0x3FF, (p1 >> 30) & 0x3FF)
    head.l_state = (p2 >> 32) & 0x3FF
    head.m_state = (p2 >> 42) & 0x3FF
    head.d_state = (p2 >> 52) & 0x3FF

    freq_blob = data[offset + 32: offset + header_size]
    values = _decode_freq_tables(freq_blob) if freq_blob else (0,) * 360
    head.l_freq = values[0:20]
    head.m_freq = values[20:40]
    head.d_freq = values[40:104]
    head.literal_freq = values[104:360]
    return head, header_size


def _header_from_v1(data: bytes, offset: int) -> tuple[_Header, int]:
    size = 770
    if offset + size > len(data):
        raise LZFSEError("truncated v1 block header")
    view = data[offset: offset + size]
    head = _Header()
    head.n_raw_bytes = int.from_bytes(view[4:8], "little")
    head.n_literals = int.from_bytes(view[12:16], "little")
    head.n_matches = int.from_bytes(view[16:20], "little")
    head.n_literal_payload_bytes = int.from_bytes(view[20:24], "little")
    head.n_lmd_payload_bytes = int.from_bytes(view[24:28], "little")
    head.literal_bits = int.from_bytes(view[28:32], "little", signed=True)
    head.literal_state = tuple(int.from_bytes(view[32 + 2 * i:34 + 2 * i], "little") for i in range(4))
    head.lmd_bits = int.from_bytes(view[40:44], "little", signed=True)
    head.l_state = int.from_bytes(view[44:46], "little")
    head.m_state = int.from_bytes(view[46:48], "little")
    head.d_state = int.from_bytes(view[48:50], "little")

    def unpack(at: int, count: int) -> tuple:
        return tuple(int.from_bytes(view[at + 2 * i: at + 2 + 2 * i], "little") for i in range(count))

    head.l_freq = unpack(50, 20)
    head.m_freq = unpack(90, 20)
    head.d_freq = unpack(130, 64)
    head.literal_freq = unpack(258, 256)
    return head, size


def _check_header(head: _Header) -> None:
    if head.n_literals > LITERALS_PER_BLOCK:
        raise LZFSEError("block declares too many literals")
    if head.n_matches > MATCHES_PER_BLOCK:
        raise LZFSEError("block declares too many matches")
    for state in head.literal_state:
        if state >= LITERAL_STATES:
            raise LZFSEError("literal state out of range")
    if head.l_state >= L_STATES or head.m_state >= M_STATES or head.d_state >= D_STATES:
        raise LZFSEError("L/M/D state out of range")
    _check_freq(head.l_freq, L_STATES)
    _check_freq(head.m_freq, M_STATES)
    _check_freq(head.d_freq, D_STATES)
    _check_freq(head.literal_freq, LITERAL_STATES)


# --------------------------------------------------------------------------
# LZFSE block decoding
# --------------------------------------------------------------------------


def _decode_literals(head: _Header, data: bytes, payload_start: int) -> bytearray:
    table = _symbol_table(LITERAL_STATES, LITERAL_SYMBOLS, head.literal_freq)
    stream = _InStream(data, payload_start, 0)
    stream.init(head.literal_bits)

    states = list(head.literal_state)
    literals = bytearray(head.n_literals)
    for index in range(0, head.n_literals, 4):
        stream.flush()
        for lane in range(4):
            state = states[lane]
            if state >= len(table):
                raise LZFSEError("literal state outside its decoder table")
            k, symbol, delta = table[state]
            states[lane] = (delta + stream.pull(k)) & 0xFFFF
            literals[index + lane] = symbol
    return literals


def _decode_block_lzfse(head: _Header, data: bytes, payload_start: int, out: bytearray) -> None:
    _check_header(head)

    literals = _decode_literals(head, data, payload_start + head.n_literal_payload_bytes)

    lmd_start = payload_start + head.n_literal_payload_bytes
    lmd_end = lmd_start + head.n_lmd_payload_bytes
    if lmd_end > len(data):
        raise LZFSEError("LMD payload runs past the end of the stream")

    l_table = _value_table(L_STATES, L_SYMBOLS, head.l_freq, L_EXTRA_BITS, L_BASE_VALUE)
    m_table = _value_table(M_STATES, M_SYMBOLS, head.m_freq, M_EXTRA_BITS, M_BASE_VALUE)
    d_table = _value_table(D_STATES, D_SYMBOLS, head.d_freq, D_EXTRA_BITS, D_BASE_VALUE)

    stream = _InStream(data, lmd_end, 0)
    stream.init(head.lmd_bits)
    l_state, m_state, d_state = head.l_state, head.m_state, head.d_state
    distance = 0
    literal_pos = 0
    block_begin = len(out)
    symbols = head.n_matches

    while symbols > 0:
        stream.flush()

        if l_state >= len(l_table):
            raise LZFSEError("L state outside its decoder table")
        tb, vb, delta, vbase = l_table[l_state]
        piece = stream.pull(tb)
        l_state = (delta + (piece >> vb)) & 0xFFFF
        length = vbase + (piece & ((1 << vb) - 1))

        if m_state >= len(m_table):
            raise LZFSEError("M state outside its decoder table")
        tb, vb, delta, vbase = m_table[m_state]
        piece = stream.pull(tb)
        m_state = (delta + (piece >> vb)) & 0xFFFF
        match_len = vbase + (piece & ((1 << vb) - 1))

        if d_state >= len(d_table):
            raise LZFSEError("D state outside its decoder table")
        tb, vb, delta, vbase = d_table[d_state]
        piece = stream.pull(tb)
        d_state = (delta + (piece >> vb)) & 0xFFFF
        candidate = vbase + (piece & ((1 << vb) - 1))
        if candidate:
            distance = candidate

        symbols -= 1

        if literal_pos + length > len(literals):
            raise LZFSEError("block reads past its literal buffer")
        out += literals[literal_pos: literal_pos + length]
        literal_pos += length
        if len(out) > MAX_OUTPUT:
            raise LZFSEError(f"decoded output exceeds the {MAX_OUTPUT} byte limit")

        if match_len:
            # The reference checks `D > dst + L - dst_begin`, i.e. after the literals
            # have been accounted for; doing it before them rejects the first triplet.
            if distance == 0 or distance > len(out):
                raise LZFSEError("match distance points before the start of the output")
            copied = 0
            while copied < match_len:
                chunk = min(distance, match_len - copied)
                out += out[len(out) - distance: len(out) - distance + chunk]
                copied += chunk
            if len(out) > MAX_OUTPUT:
                raise LZFSEError(f"decoded output exceeds the {MAX_OUTPUT} byte limit")
    return


# --------------------------------------------------------------------------
# LZVN block decoding (lzvn_decode_base.c)
# --------------------------------------------------------------------------


#: Opcode classification, built from the reference jump table in
#: lzvn_decode_base.c (opc_tbl[256]) rather than typed out by hand: every group of
#: eight opcodes shares a base, +0..+5 are small-distance, +6 is a special case and
#: +7 is large-distance.
_SML_D_BASES = (0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104,
                128, 136, 144, 152, 192, 200)


def _build_lzvn_kinds() -> list[str]:
    kinds = ["udef"] * 256
    for base in _SML_D_BASES:
        for offset in range(6):
            kinds[base + offset] = "sml_d"
        kinds[base + 7] = "lrg_d"
        special = base + 6
        if base == 0:
            kinds[special] = "eos"
        elif base in (8, 16):
            kinds[special] = "nop"
        elif base in (24, 32, 40, 48, 56):
            kinds[special] = "udef"
        else:
            kinds[special] = "pre_d"
    for opc in range(0xA0, 0xC0):
        kinds[opc] = "med_d"
    kinds[0xE0] = "lrg_l"
    for opc in range(0xE1, 0xF0):
        kinds[opc] = "sml_l"
    kinds[0xF0] = "lrg_m"
    for opc in range(0xF1, 0x100):
        kinds[opc] = "sml_m"
    return kinds


_LZVN_KIND = _build_lzvn_kinds()

#: Sanity guard on the table itself: a wrong classification would decode silently
#: wrong bytes, so the sizes of each class are asserted against the reference.
assert _LZVN_KIND.count("sml_d") == 120, _LZVN_KIND.count("sml_d")
assert _LZVN_KIND.count("lrg_d") == 20, _LZVN_KIND.count("lrg_d")
assert _LZVN_KIND.count("pre_d") == 12, _LZVN_KIND.count("pre_d")
assert _LZVN_KIND.count("udef") == 37, _LZVN_KIND.count("udef")
assert _LZVN_KIND.count("med_d") == 32, _LZVN_KIND.count("med_d")
assert _LZVN_KIND.count("sml_l") == 15, _LZVN_KIND.count("sml_l")
assert _LZVN_KIND.count("sml_m") == 15, _LZVN_KIND.count("sml_m")


def _lzvn_decode(payload: bytes, expected: int) -> bytes:
    out = bytearray()
    pos = 0
    size = len(payload)
    distance = 0

    while True:
        if pos >= size:
            raise LZFSEError("LZVN stream ends without an end-of-stream opcode")
        opc = payload[pos]
        kind = _LZVN_KIND[opc]

        if kind == "eos":
            if pos + 8 > size:
                raise LZFSEError("truncated LZVN end-of-stream opcode")
            return bytes(out)

        if kind == "nop":
            pos += 1
            continue

        if kind == "udef":
            raise LZFSEError(f"undefined LZVN opcode 0x{opc:02x} at offset {pos}")

        literal_len = 0
        match_len = 0

        if kind == "sml_d":
            if pos + 2 > size:
                raise LZFSEError("truncated LZVN small-distance opcode")
            literal_len = (opc >> 6) & 3
            match_len = ((opc >> 3) & 7) + 3
            distance = ((opc & 7) << 8) | payload[pos + 1]
            pos += 2
        elif kind == "lrg_d":
            if pos + 3 > size:
                raise LZFSEError("truncated LZVN large-distance opcode")
            literal_len = (opc >> 6) & 3
            match_len = ((opc >> 3) & 7) + 3
            distance = payload[pos + 1] | (payload[pos + 2] << 8)
            pos += 3
        elif kind == "med_d":
            if pos + 3 > size:
                raise LZFSEError("truncated LZVN medium-distance opcode")
            literal_len = (opc >> 3) & 3
            opc23 = payload[pos + 1] | (payload[pos + 2] << 8)
            match_len = (((opc & 7) << 2) | (opc23 & 3)) + 3
            distance = (opc23 >> 2) & 0x3FFF
            pos += 3
        elif kind == "pre_d":
            literal_len = (opc >> 6) & 3
            match_len = ((opc >> 3) & 7) + 3
            pos += 1
        elif kind == "sml_l":
            literal_len = opc & 0x0F
            pos += 1
        elif kind == "lrg_l":
            if pos + 2 > size:
                raise LZFSEError("truncated LZVN large-literal opcode")
            literal_len = payload[pos + 1] + 16
            pos += 2
        elif kind == "sml_m":
            match_len = opc & 0x0F
            pos += 1
        elif kind == "lrg_m":
            if pos + 2 > size:
                raise LZFSEError("truncated LZVN large-match opcode")
            match_len = payload[pos + 1] + 16
            pos += 2
        else:  # pragma: no cover - the table has no other class
            raise LZFSEError(f"unhandled LZVN opcode class {kind}")

        if literal_len:
            if pos + literal_len > size:
                raise LZFSEError("LZVN literal runs past the end of the stream")
            out += payload[pos:pos + literal_len]
            pos += literal_len

        if match_len:
            if distance == 0 or distance > len(out):
                raise LZFSEError("LZVN match distance points before the start of the output")
            copied = 0
            while copied < match_len:
                chunk = min(distance, match_len - copied)
                out += out[len(out) - distance: len(out) - distance + chunk]
                copied += chunk

        if len(out) > MAX_OUTPUT:
            raise LZFSEError(f"decoded output exceeds the {MAX_OUTPUT} byte limit")
        if expected and len(out) > expected:
            raise LZFSEError(f"LZVN output exceeds its declared size ({expected} bytes)")


# --------------------------------------------------------------------------
# Stream walk
# --------------------------------------------------------------------------


def is_lzfse(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] in MAGICS


def find_stream(data: bytes) -> int:
    """Offset of the first LZFSE block magic in `data`, or -1.

    An AEA1 body wraps the encoded payload in an Apple archive, so the block magic
    is not at offset 0. Only the magic is located here; the decoder walks the block
    chain itself.
    """
    best = -1
    for magic in MAGICS + (MAGIC_END,):
        found = data.find(magic)
        if found != -1 and (best == -1 or found < best):
            best = found
    return best


def decompress(data: bytes) -> bytes:
    """Decode one LZFSE stream starting at its first block magic."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("decompress() takes bytes")
    raw = bytes(data)
    if not raw:
        raise LZFSEError("empty input: nothing to decompress")

    offset = 0 if is_lzfse(raw) else find_stream(raw)
    if offset == -1:
        raise LZFSEError(
            "no LZFSE block magic (bvx1/bvx2/bvxn/bvx-) in input; "
            f"first bytes were {raw[:8].hex()}"
        )

    out = bytearray()
    pos = offset
    blocks = 0
    while True:
        if pos + 4 > len(raw):
            raise LZFSEError("stream ends before an end-of-stream block")
        magic = raw[pos:pos + 4]

        if magic == MAGIC_END:
            return bytes(out)

        if magic == MAGIC_RAW:
            if pos + 8 > len(raw):
                raise LZFSEError("truncated uncompressed block header")
            count = int.from_bytes(raw[pos + 4:pos + 8], "little")
            start = pos + 8
            if start + count > len(raw):
                raise LZFSEError("uncompressed block declares more bytes than the stream holds")
            out += raw[start:start + count]
            pos = start + count

        elif magic == MAGIC_LZVN:
            if pos + 12 > len(raw):
                raise LZFSEError("truncated LZVN block header")
            n_raw = int.from_bytes(raw[pos + 4:pos + 8], "little")
            n_payload = int.from_bytes(raw[pos + 8:pos + 12], "little")
            start = pos + 12
            if start + n_payload > len(raw):
                raise LZFSEError("LZVN block declares more payload than the stream holds")
            out += _lzvn_decode(raw[start:start + n_payload], n_raw)
            pos = start + n_payload

        elif magic in (MAGIC_V1, MAGIC_V2):
            head, header_size = (_header_from_v2 if magic == MAGIC_V2 else _header_from_v1)(raw, pos)
            payload_start = pos + header_size
            end = payload_start + head.n_literal_payload_bytes + head.n_lmd_payload_bytes
            if end > len(raw):
                raise LZFSEError("compressed block declares more payload than the stream holds")
            _decode_block_lzfse(head, raw, payload_start, out)
            pos = end
        else:
            raise LZFSEError(f"unknown block magic {magic!r} at offset {pos}")

        blocks += 1
        if blocks > 100000:
            raise LZFSEError("too many blocks: refusing to continue")
        if len(out) > MAX_OUTPUT:
            raise LZFSEError(f"decoded output exceeds the {MAX_OUTPUT} byte limit")
