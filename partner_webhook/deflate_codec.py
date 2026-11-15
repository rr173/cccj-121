"""Production DEFLATE primitives used by the seekable gzip index.

This module intentionally does not import or call :mod:`gzip` or
:func:`zlib.decompress`/decompressobj.  zlib.crc32 is used by the gzip layer,
not as an inflate implementation.

The decoder is restartable: :class:`DeflateState` captures every piece of
state needed after an instruction boundary.  In particular, dynamic Huffman
tables and the 32 KiB window are part of that state because a resume in the
middle of a long block cannot re-read a block header or reconstruct history.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

WINDOW_SIZE = 32768
MAX_MATCH_LEN = 258
MAX_BITS = 15
LITLEN_SYMBOLS = 286
DIST_SYMBOLS = 32
MAX_DIST_TABLE = 30  # distance codes 30 and 31 are reserved
CL_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)

# RFC 1951 tables (base value and extra bits), indexed by DEFLATE symbol.
LENGTH_BASE = (
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
)
LENGTH_EXTRA = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
)
DIST_BASE = (
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
)
DIST_EXTRA = (
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
)


class DeflateError(Exception):
    """A malformed DEFLATE stream or illegal restart state."""


class TruncatedStream(DeflateError):
    """The compressed stream ended before the requested symbol/byte."""


class BitSource(Protocol):
    def read_bit(self) -> int: ...
    def read_bits(self, count: int) -> int: ...
    def byte_position(self) -> int: ...
    def bit_position(self) -> int: ...
    def read_aligned_bytes(self, count: int) -> bytes: ...
    def align_to_byte(self) -> None: ...


class BitReader:
    """LSB-first bit reader over a seekable paged compressed source."""

    def __init__(self, source):
        self.source = source
        self.bit_pos = 0
        self._byte_index = -1
        self._bit_buf = 0

    def seek_bit(self, bit_pos: int) -> None:
        self.bit_pos = int(bit_pos)
        self.source.seek(self.bit_pos // 8)
        self._byte_index = -1
        self._bit_buf = 0

    def read_bit(self) -> int:
        byte_index = self.bit_pos >> 3
        bit_index = self.bit_pos & 7
        if byte_index != self._byte_index:
            self.source.seek(byte_index)
            data = self.source.read(1)
            if not data:
                raise TruncatedStream(
                    f"truncated DEFLATE bit stream at compressed byte "
                    f"{byte_index}"
                )
            self._bit_buf = data[0]
            self._byte_index = byte_index
        value = (self._bit_buf >> bit_index) & 1
        self.bit_pos += 1
        return value

    def read_bits(self, count: int) -> int:
        if count < 0:
            raise ValueError("negative bit count")
        value = 0
        for index in range(count):
            value |= self.read_bit() << index
        return value

    def byte_position(self) -> int:
        return self.bit_pos // 8

    def bit_position(self) -> int:
        return self.bit_pos

    def align_to_byte(self) -> None:
        padding = self.bit_pos & 7
        if padding:
            self.read_bits(8 - padding)

    def read_aligned_bytes(self, count: int) -> bytes:
        if self.bit_pos & 7:
            raise DeflateError("aligned read requested on an unaligned cursor")
        byte_pos = self.bit_pos // 8
        self.source.seek(byte_pos)
        data = self.source.read(count)
        if len(data) != count:
            raise TruncatedStream(
                f"truncated compressed stream at compressed byte "
                f"{self.source.tell()}; wanted {count}, got {len(data)}"
            )
        self.bit_pos += count * 8
        self._byte_index = -1
        self._bit_buf = 0
        return data


@dataclass(frozen=True)
class HuffmanTable:
    count: int
    symbols: tuple[int, ...]
    max_bits: int
    lengths: tuple[int, ...] = ()
    first_code: tuple[int, ...] = ()
    last_code: tuple[int, ...] = ()

    @classmethod
    def from_lengths(cls, lengths: Sequence[int], max_allowed: int = MAX_BITS,
                     allow_empty: bool = False):
        count = len(lengths)
        if count == 0 and allow_empty:
            return cls(0, (), 0)
        if count <= 0:
            raise DeflateError("empty Huffman code is not legal here")
        if any(x < 0 or x > max_allowed for x in lengths):
            raise DeflateError("Huffman code length outside permitted range")
        bl_count = [0] * (max_allowed + 1)
        for length in lengths:
            if length:
                bl_count[length] += 1
        if not any(bl_count):
            if allow_empty:
                return cls(0, (), 0, 0, (), ())
            raise DeflateError("empty Huffman code is not legal here")
        max_bits = max(i for i, value in enumerate(bl_count) if value)
        code = 0
        next_code = [0] * (max_allowed + 1)
        for bits in range(1, max_bits + 1):
            next_code[bits] = code
            code = code + bl_count[bits]
            if bits < max_bits:
                code <<= 1
        # Kraft sum scaled to integer numerators: sum(count/2^len) == 1.
        # Incomplete DEFLATE code-length tables are legal and leave unused bit
        # sequences; only over-subscription is rejected here.
        allocated = 0
        for bits in range(1, max_bits + 1):
            allocated += bl_count[bits] << (max_bits - bits)
        capacity = 1 << max_bits
        if allocated > capacity:
            raise DeflateError(
                "over-subscribed Huffman table "
                f"(allocated={allocated}, capacity={capacity})"
            )
        # Store one entry per canonical code rather than padding short codes to
        # the maximum code width; decode checks prefix boundaries explicitly.
        symbols = [0] * (1 << max_bits)
        for length in range(1, max_bits + 1):
            for symbol, symbol_length in enumerate(lengths):
                if symbol_length != length:
                    continue
                canonical = next_code[length]
                next_code[length] += 1
                symbols[canonical] = symbol
        first_code = [-1] * (max_bits + 1)
        last_code = [-1] * (max_bits + 1)
        for length in range(1, max_bits + 1):
            if bl_count[length]:
                first_code[length] = next_code[length] - bl_count[length]
                last_code[length] = next_code[length] - 1
        return cls(count, tuple(symbols), max_bits, tuple(lengths),
                   tuple(first_code), tuple(last_code))

    def decode(self, reader: BitSource) -> int:
        if self.count == 0:
            raise DeflateError("use of empty distance Huffman code")
        # The first received bit is the canonical prefix's most-significant bit.
        # Build that prefix one bit at a time and stop at the first matching
        # code length, so bits belonging to the next symbol are not consumed.
        read_bits = 0
        code = 0
        while read_bits < self.max_bits:
            code = (code << 1) | reader.read_bit()
            read_bits += 1
            if self.first_code[read_bits] >= 0 and \
                    self.first_code[read_bits] <= code <= self.last_code[read_bits]:
                symbol = self.symbols[code]
                if symbol >= self.count:
                    raise DeflateError(f"invalid Huffman symbol {symbol}")
                return symbol
        raise DeflateError("Huffman decoding exceeded maximum code length")


def fixed_litlen_table() -> HuffmanTable:
    lengths = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
    return HuffmanTable.from_lengths(lengths)


def fixed_distance_table() -> HuffmanTable:
    return HuffmanTable.from_lengths([5] * 30)


@dataclass(frozen=True)
class DeflateState:
    """Complete restart state at a complete literal or length/distance command."""

    bit_pos: int
    block_type: int = -1          # -1: before next block; 0/1/2
    bfinal_seen: bool = False
    stored_bytes_remaining: int = 0
    lit_lengths: tuple[int, ...] | None = None
    dist_lengths: tuple[int, ...] | None = None
    window: bytes = b""          # At most WINDOW_SIZE, oldest-to-newest.
    output_offset: int = 0
    crc32_state: int = 0
    member_index: int = 0
    member_start_output: int = 0
    member_start_compressed: int = 0
    member_header_length: int = 0
    member_optional_header_length: int = 0

    def validate(self) -> None:
        if self.bit_pos < 0:
            raise DeflateError("negative compressed bit cursor")
        if self.block_type not in (-1, 0, 1, 2):
            raise DeflateError("unknown block type in checkpoint")
        if len(self.window) > WINDOW_SIZE:
            raise DeflateError("checkpoint window exceeds 32 KiB")
        for field_name in (
            "member_index", "member_start_output", "member_start_compressed",
            "member_header_length", "member_optional_header_length",
        ):
            if getattr(self, field_name) < 0:
                raise DeflateError(f"negative {field_name} in checkpoint")
        if self.member_header_length < 10:
            raise DeflateError("invalid gzip member header length")
        if self.block_type == 0 and self.stored_bytes_remaining < 0:
            raise DeflateError("negative stored-block remainder")
        if self.block_type == 2:
            if not self.lit_lengths:
                raise DeflateError("dynamic block checkpoint lacks literal table")
            if self.dist_lengths is None:
                raise DeflateError("dynamic block checkpoint lacks distance table")
            if len(self.lit_lengths) > LITLEN_SYMBOLS:
                raise DeflateError("oversize literal/length table")
            if len(self.dist_lengths) > DIST_SYMBOLS:
                raise DeflateError("oversize distance table")
        if self.block_type in (0, 1) and (
            self.lit_lengths is not None or self.dist_lengths is not None
        ):
            raise DeflateError("non-dynamic checkpoint cannot carry dynamic tables")

    def to_json(self) -> dict:
        return {
            "bit_pos": self.bit_pos,
            "block_type": self.block_type,
            "bfinal_seen": self.bfinal_seen,
            "stored_bytes_remaining": self.stored_bytes_remaining,
            "lit_lengths": list(self.lit_lengths) if self.lit_lengths else [],
            "dist_lengths": list(self.dist_lengths) if self.dist_lengths else [],
            "window_b64": _b64encode(self.window),
            "output_offset": self.output_offset,
            "crc32_state": self.crc32_state & 0xffffffff,
            "member_index": self.member_index,
            "member_start_output": self.member_start_output,
            "member_start_compressed": self.member_start_compressed,
            "member_header_length": self.member_header_length,
            "member_optional_header_length": self.member_optional_header_length,
        }

    @classmethod
    def from_json(cls, doc: dict) -> "DeflateState":
        import base64
        try:
            window = base64.b64decode(doc["window_b64"], validate=True)
            lit = doc.get("lit_lengths") or []
            dist = doc.get("dist_lengths") or []
            state = cls(
                bit_pos=int(doc["bit_pos"]),
                block_type=int(doc["block_type"]),
                bfinal_seen=bool(doc["bfinal_seen"]),
                stored_bytes_remaining=int(doc["stored_bytes_remaining"]),
                lit_lengths=tuple(int(x) for x in lit) if lit else None,
                dist_lengths=tuple(int(x) for x in dist) if dist else None,
                window=bytes(window),
                output_offset=int(doc["output_offset"]),
                crc32_state=int(doc["crc32_state"]) & 0xffffffff,
                member_index=int(doc.get("member_index", 0)),
                member_start_output=int(doc.get("member_start_output", 0)),
                member_start_compressed=int(doc.get("member_start_compressed", 0)),
                member_header_length=int(doc.get("member_header_length", 0)),
                member_optional_header_length=int(
                    doc.get("member_optional_header_length", 0)
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DeflateError(f"invalid checkpoint state: {exc}") from exc
        state.validate()
        return state

    def copy(self) -> "DeflateState":
        return DeflateState(
            bit_pos=self.bit_pos,
            block_type=self.block_type,
            bfinal_seen=self.bfinal_seen,
            stored_bytes_remaining=self.stored_bytes_remaining,
            lit_lengths=self.lit_lengths,
            dist_lengths=self.dist_lengths,
            window=self.window,
            output_offset=self.output_offset,
            crc32_state=self.crc32_state,
            member_index=self.member_index,
            member_start_output=self.member_start_output,
            member_start_compressed=self.member_start_compressed,
            member_header_length=self.member_header_length,
            member_optional_header_length=self.member_optional_header_length,
        )


def _b64encode(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


def _build_tables(bit: BitReader) -> tuple[HuffmanTable, HuffmanTable]:
    hlit = bit.read_bits(5) + 257
    hdist = bit.read_bits(5) + 1
    hclen = bit.read_bits(4) + 4
    if not (257 <= hlit <= LITLEN_SYMBOLS):
        raise DeflateError(f"invalid HLIT={hlit}")
    if not (1 <= hdist <= DIST_SYMBOLS):
        raise DeflateError(f"invalid HDIST={hdist}")
    if not (4 <= hclen <= 19):
        raise DeflateError(f"invalid HCLEN={hclen}")
    cl_lengths = [0] * 19
    for index in range(hclen):
        cl_lengths[CL_ORDER[index]] = bit.read_bits(3)
    cl_table = HuffmanTable.from_lengths(cl_lengths, max_allowed=7)
    lengths: list[int] = []
    while len(lengths) < hlit + hdist:
        symbol = cl_table.decode(bit)
        if 0 <= symbol <= 15:
            lengths.append(symbol)
        elif symbol == 16:
            if not lengths:
                raise DeflateError("code length repeat 16 has no previous value")
            repeat = bit.read_bits(2) + 3
            if len(lengths) + repeat > hlit + hdist:
                raise DeflateError("code length repeat 16 overruns table")
            lengths.extend([lengths[-1]] * repeat)
        elif symbol == 17:
            repeat = bit.read_bits(3) + 3
            if len(lengths) + repeat > hlit + hdist:
                raise DeflateError("code length repeat 17 overruns table")
            lengths.extend([0] * repeat)
        elif symbol == 18:
            repeat = bit.read_bits(7) + 11
            if len(lengths) + repeat > hlit + hdist:
                raise DeflateError("code length repeat 18 overruns table")
            lengths.extend([0] * repeat)
        else:
            raise DeflateError(f"invalid code-length symbol {symbol}")
    lit_lengths = tuple(lengths[:hlit])
    dist_lengths = tuple(lengths[hlit:])
    # RFC permits a one-symbol, one-bit distance code.  The all-zero distance
    # code is separately legal and means no distance instruction may occur.
    lit_table = HuffmanTable.from_lengths(lit_lengths)
    dist_table = HuffmanTable.from_lengths(
        dist_lengths, max_allowed=MAX_BITS, allow_empty=True
    )
    return lit_table, dist_table


class DeflateDecoder:
    """Decode gzip DEFLATE members with bounded output and checkpoints."""

    def __init__(self, source, state: DeflateState, *, max_output: int | None):
        self.bit = BitReader(source)
        self.bit.seek_bit(state.bit_pos)
        self.state = state
        self.output_offset = state.output_offset
        self.crc32_state = state.crc32_state
        self.max_output = max_output
        self.window = bytearray(state.window)
        self.block_type = state.block_type
        self.stored_remaining = state.stored_bytes_remaining
        self.bfinal_seen = state.bfinal_seen
        self.lit_table: HuffmanTable | None = None
        self.dist_table: HuffmanTable | None = None
        if state.block_type == 1:
            self.lit_table = fixed_litlen_table()
            self.dist_table = fixed_distance_table()
        elif state.block_type == 2:
            if state.lit_lengths is None or state.dist_lengths is None:
                raise DeflateError("dynamic resume state missing Huffman tables")
            self.lit_table = HuffmanTable.from_lengths(state.lit_lengths)
            self.dist_table = HuffmanTable.from_lengths(
                state.dist_lengths, allow_empty=True
            )
        self.decoded_bytes = 0

    def checkpoint_state(self) -> DeflateState:
        current = DeflateState(
            bit_pos=self.bit.bit_position(),
            block_type=self.block_type,
            bfinal_seen=self.bfinal_seen,
            stored_bytes_remaining=self.stored_remaining if self.block_type == 0 else 0,
            lit_lengths=self.lit_table.lengths if self.block_type == 2 else None,
            dist_lengths=self.dist_table.lengths if self.block_type == 2 else None,
            window=bytes(self.window),
            output_offset=self.output_offset,
            crc32_state=self.crc32_state,
            member_index=self.state.member_index,
            member_start_output=self.state.member_start_output,
            member_start_compressed=self.state.member_start_compressed,
            member_header_length=self.state.member_header_length,
            member_optional_header_length=(
                self.state.member_optional_header_length
            ),
        )
        current.validate()
        return current

    def _emit(self, value: int) -> int:
        if self.max_output is not None and self.output_offset >= self.max_output:
            raise DeflateError(
                f"decompressed size limit {self.max_output} exceeded"
            )
        self.window.append(value)
        if len(self.window) > WINDOW_SIZE:
            del self.window[0]
        self.output_offset += 1
        self.decoded_bytes += 1
        return value

    def _copy_match(self, distance: int, length: int) -> list[int]:
        if distance <= 0:
            raise DeflateError(f"non-positive back-reference distance {distance}")
        if distance > len(self.window):
            raise DeflateError(
                f"back-reference distance {distance} has no history "
                f"(window valid length={len(self.window)}) at compressed bit "
                f"{self.bit.bit_position()}"
            )
        if not (1 <= length <= MAX_MATCH_LEN):
            raise DeflateError(f"invalid match length {length}")
        out: list[int] = []
        # Byte-at-a-time correctly implements overlapping copies.
        for _ in range(length):
            out.append(self._emit(self.window[-distance]))
        return out

    def _start_block(self) -> bool:
        if self.bfinal_seen:
            raise DeflateError("data after BFINAL inside same DEFLATE stream")
        bfinal = self.bit.read_bit()
        block_type = self.bit.read_bits(2)
        self.bfinal_seen = bool(bfinal)
        self.block_type = block_type
        self.stored_remaining = 0
        if block_type == 0:
            self.lit_table = None
            self.dist_table = None
            self.bit.align_to_byte()
            length = int.from_bytes(self.bit.read_aligned_bytes(2), "little")
            nlength = int.from_bytes(self.bit.read_aligned_bytes(2), "little")
            if length != (nlength ^ 0xffff):
                raise DeflateError(
                    f"stored block LEN/NLEN mismatch at compressed bit "
                    f"{self.bit.bit_position()}"
                )
            self.stored_remaining = length
        elif block_type == 1:
            self.lit_table = fixed_litlen_table()
            self.dist_table = fixed_distance_table()
        elif block_type == 2:
            self.lit_table, self.dist_table = _build_tables(self.bit)
        else:
            raise DeflateError(
                f"reserved DEFLATE block type 3 at compressed bit "
                f"{self.bit.bit_position()}"
            )
        return bool(bfinal)

    def _end_block(self) -> None:
        self.block_type = -1
        self.lit_table = None
        self.dist_table = None
        self.stored_remaining = 0

    def decode_until(self, target_offset: int, emit, *,
                     stop_at_end: bool = False,
                     allow_member_end: bool = False) -> None:
        """Decode complete instructions until output reaches target offset."""
        if target_offset < self.output_offset:
            raise DeflateError("decode target precedes checkpoint")
        while self.output_offset < target_offset:
            if self.block_type < 0:
                self._start_block()
            if self.block_type == 0:
                while (self.stored_remaining and
                       self.output_offset < target_offset):
                    value = self.bit.read_aligned_bytes(1)[0]
                    self.stored_remaining -= 1
                    emit(self._emit(value))
                if self.stored_remaining == 0 and self.block_type == 0:
                    bfinal = self.bfinal_seen
                    self._end_block()
                    if bfinal and self.output_offset < target_offset:
                        if stop_at_end or allow_member_end:
                            return
                        raise TruncatedStream(
                            "BFINAL stored block ended before requested output "
                            f"target {target_offset}"
                        )
                continue
            assert self.lit_table is not None and self.dist_table is not None
            symbol = self.lit_table.decode(self.bit)
            if symbol < 256:
                emit(self._emit(symbol))
            elif symbol == 256:
                bfinal = self.bfinal_seen
                self._end_block()
                if bfinal and self.output_offset < target_offset:
                    if stop_at_end or allow_member_end:
                        return
                    raise TruncatedStream(
                        "BFINAL end-of-block reached before requested output "
                        f"target {target_offset}"
                    )
            elif symbol <= 285:
                index = symbol - 257
                if index >= len(LENGTH_BASE):
                    raise DeflateError(f"reserved length symbol {symbol}")
                length = LENGTH_BASE[index] + self.bit.read_bits(
                    LENGTH_EXTRA[index]
                )
                dist_symbol = self.dist_table.decode(self.bit)
                if dist_symbol >= MAX_DIST_TABLE:
                    raise DeflateError(
                        f"reserved distance symbol {dist_symbol} at compressed bit "
                        f"{self.bit.bit_position()}"
                    )
                distance = DIST_BASE[dist_symbol] + self.bit.read_bits(
                    DIST_EXTRA[dist_symbol]
                )
                for value in self._copy_match(distance, length):
                    emit(value)
            else:
                raise DeflateError(
                    f"reserved literal/length symbol {symbol} at compressed bit "
                    f"{self.bit.bit_position()}"
                )
        # A target exactly at an instruction/stored-byte boundary is valid.
