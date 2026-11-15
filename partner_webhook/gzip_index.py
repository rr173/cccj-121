"""Seekable gzip index for accepted webhook request bodies.

The public operations are :func:`build_index`, :func:`extract_range` and
:func:`verify_index`.  They deliberately use a separate SQLite index database;
the webhook source database is opened through a read-only URI and never
modified.

Evidence boundary: build and verify read every 64 KiB compressed page and the
whole-source SHA-256.  extract validates only pages reached while resuming from
the nearest checkpoint and decoding the requested range; untouched corrupt
pages therefore cannot affect a local extraction and are not detected by it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import quote

if __package__ in (None, ""):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from partner_webhook.deflate_codec import (  # noqa: E402
        DeflateDecoder,
        DeflateError,
        DeflateState,
        TruncatedStream,
    )
else:
    from .deflate_codec import (
        DeflateDecoder,
        DeflateError,
        DeflateState,
        TruncatedStream,
    )

INDEX_MAGIC = "partner-webhook-seekable-gzip-v1"
PAGE_SIZE = 64 * 1024
INDEX_TABLES = {
    "header", "source_binding", "page_checksums", "checkpoints",
}
DEFAULT_MAX_OUTPUT = 512 * 1024 * 1024
DEFAULT_MAX_HEADER = 64 * 1024
DEFAULT_SPACING = 1024 * 1024
MAX_BATCH = 128


class GzipIndexError(Exception):
    """Base class for user-facing seekable gzip failures."""


class GzipFormatError(GzipIndexError):
    """A gzip framing or checksum failure."""


def _sha256() -> "hashlib._Hash":
    return hashlib.sha256()


def _feed_digest(digest, *parts: bytes | int | str) -> None:
    for part in parts:
        if isinstance(part, str):
            data = part.encode("utf-8")
        elif isinstance(part, int):
            data = str(part).encode("ascii")
        else:
            data = part
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b":")
        digest.update(data)


def _row_digest(table: str, values: list) -> str:
    digest = _sha256()
    _feed_digest(digest, table)
    for value in values:
        if value is None:
            digest.update(b"null")
        elif isinstance(value, int):
            _feed_digest(digest, value)
        elif isinstance(value, str):
            _feed_digest(digest, value)
        else:
            _feed_digest(digest, bytes(value))
    return digest.hexdigest()


def connect_source_readonly(db_path: str | Path) -> sqlite3.Connection:
    uri = "file:" + quote(str(Path(db_path).resolve()), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def locate_accepted_body(conn: sqlite3.Connection, partner_id: str,
                         event_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT ae.partner_id, ae.event_id, ae.body_sha256, "
        "       rb.byte_length, length(rb.body_blob) AS blob_length "
        "FROM accepted_events AS ae "
        "JOIN raw_bodies AS rb ON rb.body_sha256 = ae.body_sha256 "
        "WHERE ae.partner_id = ? AND ae.event_id = ?",
        (partner_id, event_id),
    ).fetchone()
    if row is None:
        raise GzipIndexError(
            f"accepted event not found: partner_id={partner_id!r}, "
            f"event_id={event_id!r}"
        )
    if row["byte_length"] != row["blob_length"]:
        raise GzipIndexError(
            f"raw_bodies byte_length {row['byte_length']} does not match BLOB "
            f"length {row['blob_length']}"
        )
    return row


class BlobByteStream:
    """Fixed-buffer paged reader over a SQLite BLOB.

    Only one 64 KiB compressed page is held at a time.  Every ``read`` is
    counted so operation statistics describe actual source I/O rather than
    bytes decoded.
    """

    def __init__(self, conn: sqlite3.Connection, body_sha256: str,
                 length: int, page_hashes: dict[int, str] | None = None):
        rowid = conn.execute(
            "SELECT rowid FROM raw_bodies WHERE body_sha256 = ?",
            (body_sha256,),
        ).fetchone()[0]
        self.blob = conn.blobopen("raw_bodies", "body_blob", rowid,
                                  readonly=True)
        self.length = int(length)
        self.pos = 0
        self.page_hashes = page_hashes or {}
        self.pages_read: set[int] = set()
        self.bytes_read = 0
        self._page_no = -1
        self._page = b""

    def close(self) -> None:
        self.blob.close()

    def seek(self, pos: int) -> None:
        if pos < 0 or pos > self.length:
            raise GzipIndexError(f"seek outside compressed source: {pos}")
        self.pos = int(pos)
        page_no = self.pos // PAGE_SIZE
        if page_no != self._page_no:
            self._page_no = -1
            self._page = b""

    def tell(self) -> int:
        return self.pos

    def _load_page(self, page_no: int) -> bytes:
        start = page_no * PAGE_SIZE
        take = min(PAGE_SIZE, self.length - start)
        self.blob.seek(start)
        data = self.blob.read(take)
        if len(data) != take:
            raise TruncatedStream(
                f"short BLOB read at compressed page {page_no} offset {start}"
            )
        expected = self.page_hashes.get(page_no)
        if expected is not None:
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                raise GzipIndexError(
                    f"compressed page {page_no} checksum mismatch; source "
                    f"offset {start}..{start + take}"
                )
        self.pages_read.add(page_no)
        self.bytes_read += len(data)
        self._page_no = page_no
        self._page = data
        return data

    def read(self, count: int) -> bytes:
        if count <= 0 or self.pos >= self.length:
            return b""
        page_no = self.pos // PAGE_SIZE
        in_page = self.pos % PAGE_SIZE
        if page_no != self._page_no:
            page = self._load_page(page_no)
        else:
            page = self._page
        take = min(count, len(page) - in_page, self.length - self.pos)
        data = page[in_page:in_page + take]
        self.pos += take
        return data


@dataclass
class Config:
    spacing: int
    max_output: int
    max_optional_header: int
    tmp_dir: Path

    @classmethod
    def create(cls, *, spacing: int, max_output: int,
               max_optional_header: int, tmp_dir: str | Path) -> "Config":
        if spacing <= 0:
            raise GzipIndexError("checkpoint spacing S must be positive")
        if max_output <= 0:
            raise GzipIndexError("cumulative decompressed limit must be positive")
        if max_optional_header <= 0:
            raise GzipIndexError("optional gzip header length limit must be positive")
        path = Path(tmp_dir)
        if not path.is_dir():
            raise GzipIndexError(f"temporary directory does not exist: {path}")
        return cls(int(spacing), int(max_output), int(max_optional_header), path)


class _GzipParser:
    def __init__(self, stream: BlobByteStream, max_optional_header: int):
        self.stream = stream
        self.max_optional_header = max_optional_header
        self.optional_used = 0

    def read_exact(self, count: int, what: str) -> bytes:
        data = self.stream.read(count)
        if len(data) != count:
            raise TruncatedStream(
                f"truncated gzip {what} at compressed byte {stream_pos(self.stream)}"
            )
        return data

    def parse_member_header(self) -> tuple[int, int, int, int]:
        """Return data start, header CRC, total header length and optional length."""
        member_start = self.stream.tell()
        header = self.read_exact(10, "member header")
        if header[0:2] != b"\x1f\x8b":
            if member_start == 0 and self.stream.length == 0:
                raise GzipFormatError("zero-byte body is not a gzip member")
            raise GzipFormatError(
                f"invalid gzip magic at member starting byte {member_start}"
            )
        if header[2] != 8:
            raise GzipFormatError(
                f"unsupported CM={header[2]} at member byte {member_start}"
            )
        flg = header[3]
        if flg & 0b11100000:
            raise GzipFormatError(
                f"reserved gzip FLG bits set at member byte {member_start}"
            )
        header_crc = zlib.crc32(header) & 0xffffffff
        optional_start = self.stream.tell()

        def take_optional(count: int, label: str) -> bytes:
            if self.optional_used + count > self.max_optional_header:
                raise GzipFormatError(
                    f"{label} would exceed optional header limit "
                    f"{self.max_optional_header} at member byte {member_start}"
                )
            data = self.read_exact(count, label)
            self.optional_used += count
            return data

        if flg & 4:  # FEXTRA
            xlen = int.from_bytes(take_optional(2, "FEXTRA XLEN"), "little")
            extra = take_optional(xlen, "FEXTRA payload")
            header_crc = zlib.crc32(extra, header_crc) & 0xffffffff
        if flg & 8:  # FNAME, NUL-terminated ISO-Latin-1 name
            while True:
                value = take_optional(1, "FNAME byte")
                header_crc = zlib.crc32(value, header_crc) & 0xffffffff
                if value == b"\x00":
                    break
        if flg & 16:  # FCOMMENT
            while True:
                value = take_optional(1, "FCOMMENT byte")
                header_crc = zlib.crc32(value, header_crc) & 0xffffffff
                if value == b"\x00":
                    break
        if flg & 2:  # FHCRC
            expected = int.from_bytes(take_optional(2, "FHCRC"), "little")
            actual = header_crc & 0xffff
            if expected != actual:
                raise GzipFormatError(
                    f"FHCRC mismatch at member byte {member_start}: "
                    f"expected {expected:#06x}, got {actual:#06x}"
                )
        actual_optional = self.stream.tell() - optional_start
        if actual_optional > self.max_optional_header:
            raise GzipFormatError("optional gzip header exceeds configured limit")
        return (
            self.stream.tell(), header_crc,
            self.stream.tell() - member_start, actual_optional,
        )

    def read_trailer(self, expected_size: int, expected_crc: int | None = None) -> None:
        trailer_pos = self.stream.tell()
        trailer = self.read_exact(8, "member trailer")
        crc = int.from_bytes(trailer[:4], "little")
        isize = int.from_bytes(trailer[4:], "little")
        if expected_crc is not None and crc != expected_crc:
            raise GzipFormatError(
                f"CRC32 mismatch at member trailer byte {trailer_pos}: "
                f"expected {expected_crc:#010x}, got {crc:#010x}"
            )
        if isize != (expected_size & 0xffffffff):
            raise GzipFormatError(
                f"ISIZE mismatch at member trailer byte {trailer_pos}: "
                f"expected {expected_size & 0xffffffff:#010x}, got {isize:#010x}"
            )


def stream_pos(stream: BlobByteStream) -> int:
    return stream.tell()


class _BuildSink:
    def __init__(self, config: Config):
        self.config = config
        self.decoder: DeflateDecoder | None = None
        self.last_checkpoint_output = 0
        self.member_start_output = 0
        self.member_crc = 0
        self.member_count = 0
        self.checkpoint_count = 0
        self.checkpoint_callback: Callable[[DeflateState], None] | None = None
        self.crc_buffer = bytearray()

    def attach(self, decoder: DeflateDecoder, state: DeflateState,
               callback: Callable[[DeflateState], None]) -> None:
        self.decoder = decoder
        self.member_start_output = state.output_offset
        self.member_crc = state.crc32_state
        self.checkpoint_callback = callback
        # The first complete point in a member is immediately after its header.
        self._record(state, force=self.checkpoint_count == 0)

    def emit(self, value: int) -> None:
        self.crc_buffer.append(value)
        if len(self.crc_buffer) >= 4096:
            self.flush_crc()
        assert self.decoder is not None
        gap = self.decoder.output_offset - self.last_checkpoint_output
        if gap >= self.config.spacing:
            self.flush_crc()
            self._record(self.decoder.checkpoint_state(), force=True)

    def flush_crc(self) -> None:
        if self.crc_buffer:
            self.member_crc = zlib.crc32(bytes(self.crc_buffer),
                                         self.member_crc) & 0xffffffff
            self.crc_buffer.clear()
            if self.decoder is not None:
                self.decoder.crc32_state = self.member_crc

    def finish_member(self) -> int:
        self.flush_crc()
        size = self.decoder.output_offset - self.member_start_output
        self.member_count += 1
        return size

    def _record(self, state: DeflateState, force: bool = False) -> None:
        if force or state.output_offset != self.last_checkpoint_output:
            if self.checkpoint_callback:
                self.checkpoint_callback(state)
            self.last_checkpoint_output = state.output_offset
            self.checkpoint_count += 1


class IndexWriter:
    def __init__(self, path: Path, config: Config, binding: sqlite3.Row,
                 source_digest: str):
        self.path = path
        self.config = config
        self.page_batch: list[tuple] = []
        self.checkpoint_count = 0
        fd, tmp_name = tempfile.mkstemp(
            prefix=".gzip-index-", suffix=".sqlite", dir=config.tmp_dir
        )
        os.close(fd)
        self.tmp_path = Path(tmp_name)
        self.conn = sqlite3.connect(self.tmp_path)
        self._create()
        self.binding_values = [
            binding["partner_id"], binding["event_id"], binding["body_sha256"],
            int(binding["byte_length"]), source_digest,
        ]

    def _create(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE header (
                magic TEXT NOT NULL,
                format_version INTEGER NOT NULL,
                page_size INTEGER NOT NULL,
                spacing INTEGER NOT NULL,
                max_output INTEGER NOT NULL,
                max_optional_header INTEGER NOT NULL,
                decompressed_size INTEGER NOT NULL,
                member_count INTEGER NOT NULL,
                checkpoint_count INTEGER NOT NULL,
                root_sha256 TEXT NOT NULL,
                header_sha256 TEXT NOT NULL
            );
            CREATE TABLE source_binding (
                partner_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                source_length INTEGER NOT NULL,
                source_sha256 TEXT NOT NULL,
                row_sha256 TEXT NOT NULL
            );
            CREATE TABLE page_checksums (
                page_no INTEGER PRIMARY KEY,
                page_offset INTEGER NOT NULL,
                page_length INTEGER NOT NULL,
                page_sha256 TEXT NOT NULL,
                row_sha256 TEXT NOT NULL
            );
            CREATE TABLE checkpoints (
                output_offset INTEGER PRIMARY KEY,
                state_json TEXT NOT NULL,
                state_sha256 TEXT NOT NULL,
                row_sha256 TEXT NOT NULL
            );
            """
        )

    def add_binding(self) -> None:
        row_sha = _row_digest("source_binding", self.binding_values)
        values = [*self.binding_values, row_sha]
        self.conn.execute(
            "INSERT INTO source_binding VALUES (?,?,?,?,?,?)", values
        )

    def add_page(self, page_no: int, offset: int, length: int, digest: str) -> None:
        values = [page_no, offset, length, digest]
        row_sha = _row_digest("page_checksums", values)
        self.page_batch.append((*values, row_sha))
        if len(self.page_batch) >= MAX_BATCH:
            self.flush_pages()

    def flush_pages(self) -> None:
        if self.page_batch:
            self.conn.executemany(
                "INSERT INTO page_checksums VALUES (?,?,?,?,?)", self.page_batch
            )
            self.page_batch.clear()

    def add_checkpoint(self, state: DeflateState) -> None:
        doc = state.to_json()
        text = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        state_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        values = [state.output_offset, text, state_sha]
        row_sha = _row_digest("checkpoints", values)
        self.conn.execute(
            "INSERT INTO checkpoints VALUES (?,?,?,?)",
            (*values, row_sha),
        )
        self.checkpoint_count += 1

    def close(self, decompressed_size: int, member_count: int) -> None:
        self.flush_pages()
        root = _sha256()
        binding_row = self.conn.execute(
            "SELECT row_sha256 FROM source_binding"
        ).fetchone()
        root.update(binding_row[0].encode("ascii"))
        for row in self.conn.execute(
            "SELECT row_sha256 FROM page_checksums ORDER BY page_no"
        ):
            root.update(row[0].encode("ascii"))
        for row in self.conn.execute(
            "SELECT row_sha256 FROM checkpoints ORDER BY output_offset"
        ):
            root.update(row[0].encode("ascii"))
        root_sha = root.hexdigest()
        header_values = [
            INDEX_MAGIC, 1, PAGE_SIZE, self.config.spacing,
            self.config.max_output, self.config.max_optional_header,
            decompressed_size, member_count, self.checkpoint_count, root_sha,
        ]
        header_sha = _row_digest("header", header_values)
        self.conn.execute(
            "INSERT INTO header VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (*header_values, header_sha),
        )
        self.conn.commit()
        self.conn.close()
        if self.path.exists():
            raise GzipIndexError(f"refusing to overwrite existing index: {self.path}")
        os.replace(self.tmp_path, self.path)

    def abort(self) -> None:
        if hasattr(self, "conn"):
            self.conn.close()
        try:
            self.tmp_path.unlink()
        except FileNotFoundError:
            pass


def _run_gzip(stream: BlobByteStream, config: Config,
              sink: _BuildSink) -> dict:
    parser = _GzipParser(stream, config.max_optional_header)
    member_count = 0
    total = 0
    while stream.tell() < stream.length:
        member_start = stream.tell()
        data_start, _header_crc, header_length, optional_length = \
            parser.parse_member_header()
        state = DeflateState(
            bit_pos=data_start * 8,
            output_offset=total,
            crc32_state=0,
            member_index=member_count,
            member_start_output=total,
            member_start_compressed=member_start,
            member_header_length=header_length,
            member_optional_header_length=optional_length,
        )
        decoder = DeflateDecoder(stream, state, max_output=config.max_output)
        sink.attach(decoder, state, sink.checkpoint_callback)
        # For build, target is max output limit and decoder enforces it.
        # Build must consume each complete member; the output-limit check is
        # enforced inside DeflateDecoder._emit.
        decoder.decode_until(config.max_output, sink.emit, stop_at_end=True)
        if decoder.block_type >= 0 or not decoder.bfinal_seen:
            raise TruncatedStream(
                f"DEFLATE member starting at byte {member_start} ended without "
                "BFINAL end-of-block"
            )
        member_size = sink.finish_member()
        parser.read_trailer(member_size, decoder.crc32_state)
        total = decoder.output_offset
        member_count += 1
    if member_count == 0:
        raise GzipFormatError("empty gzip source contains no members")
    if stream.tell() != stream.length:
        raise GzipFormatError(
            f"extra data after final gzip member at compressed byte "
            f"{stream.tell()}"
        )
    return {"members": member_count, "decompressed_size": total}


def build_index(source_db: str | Path, partner_id: str, event_id: str,
                index_path: str | Path, config: Config) -> dict:
    index = Path(index_path)
    if index.exists():
        raise GzipIndexError(f"refusing to overwrite existing index: {index}")
    conn = connect_source_readonly(source_db)
    writer: IndexWriter | None = None
    source_digest = _sha256()
    try:
        binding = locate_accepted_body(conn, partner_id, event_id)
        if binding["byte_length"] <= 0:
            raise GzipFormatError("zero-byte body is not a gzip member")
        stream = BlobByteStream(conn, binding["body_sha256"],
                                binding["byte_length"])
        try:
            writer = IndexWriter(index, config, binding, "")
            writer.add_binding()

            # Wrap page loading so whole-source digest and fixed 64 KiB page
            # digests are observed on the actual read path.
            original_load = stream._load_page
            def counted_load(page_no: int) -> bytes:
                page = original_load(page_no)
                source_digest.update(page)
                offset = page_no * PAGE_SIZE
                writer.add_page(page_no, offset, len(page),
                                hashlib.sha256(page).hexdigest())
                return page
            stream._load_page = counted_load  # type: ignore[method-assign]

            sink = _BuildSink(config)
            sink.checkpoint_callback = writer.add_checkpoint
            result = _run_gzip(stream, config, sink)
            if stream.tell() != binding["byte_length"]:
                raise GzipFormatError("parser did not consume whole gzip source")
        finally:
            stream.close()
        # Rebuild the binding row now that the whole-source digest is known.
        writer.binding_values[-1] = source_digest.hexdigest()
        writer.conn.execute("DELETE FROM source_binding")
        writer.add_binding()
        writer.close(result["decompressed_size"], result["members"])
        stats = {
            "operation": "build",
            "partner_id": partner_id,
            "event_id": event_id,
            "source_compressed_bytes": binding["byte_length"],
            "decompressed_bytes": result["decompressed_size"],
            "member_count": result["members"],
            "checkpoint_count": writer.checkpoint_count,
            "pages_read": len(stream.pages_read),
            "compressed_bytes_read": stream.bytes_read,
            "index_bytes": index.stat().st_size,
            "index_path": str(index),
        }
        return stats
    except Exception:
        if writer is not None:
            writer.abort()
        raise
    finally:
        conn.close()


def _connect_index(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise GzipIndexError(f"index does not exist: {path}")
    conn = sqlite3.connect(f"file:{quote(str(path.resolve()), safe='/')}?mode=ro",
                           uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def _load_index_binding(conn: sqlite3.Connection, partner_id: str,
                        event_id: str) -> sqlite3.Row:
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    unknown = names - INDEX_TABLES - {"sqlite_sequence"}
    missing = INDEX_TABLES - names
    if unknown or missing:
        raise GzipIndexError(
            f"index table set invalid; missing={sorted(missing)}, "
            f"unknown={sorted(unknown)}"
        )
    header = conn.execute("SELECT * FROM header").fetchone()
    if header is None:
        raise GzipIndexError("index header is missing")
    expected_header = _row_digest("header", [
        header["magic"], header["format_version"], header["page_size"],
        header["spacing"], header["max_output"], header["max_optional_header"],
        header["decompressed_size"], header["member_count"],
        header["checkpoint_count"], header["root_sha256"],
    ])
    if header["magic"] != INDEX_MAGIC or expected_header != header["header_sha256"]:
        raise GzipIndexError("index header integrity check failed")
    if header["page_size"] != PAGE_SIZE:
        raise GzipIndexError("index page size does not match supported format")
    binding = conn.execute("SELECT * FROM source_binding").fetchone()
    expected_binding = _row_digest("source_binding", [
        binding["partner_id"], binding["event_id"], binding["body_sha256"],
        binding["source_length"], binding["source_sha256"],
    ])
    if expected_binding != binding["row_sha256"]:
        raise GzipIndexError("source binding integrity check failed")
    if len(binding["source_sha256"]) != 64:
        raise GzipIndexError("index has an invalid registered source digest")
    if binding["partner_id"] != partner_id or binding["event_id"] != event_id:
        raise GzipIndexError(
            "index is bound to another event: "
            f"{binding['partner_id']}/{binding['event_id']} != "
            f"{partner_id}/{event_id}"
        )
    return binding


class _OnDemandPageHashes:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.cache: dict[int, str] = {}

    def get(self, page_no: int, default=None):
        if page_no not in self.cache:
            row = self.conn.execute(
                "SELECT page_sha256 FROM page_checksums WHERE page_no=?",
                (page_no,),
            ).fetchone()
            self.cache[page_no] = row[0] if row else None
        return self.cache[page_no] if self.cache[page_no] is not None else default


def _page_hash_map(conn: sqlite3.Connection) -> _OnDemandPageHashes:
    return _OnDemandPageHashes(conn)


class _ExtractSink:
    def __init__(self, start: int, length: int, output, resume_offset: int):
        self.skipped_at_resume = resume_offset
        self.start = start
        self.end = start + length
        self.output = output
        self.relative_offset = 0
        self.written = 0
        self.skipped = 0
        self.crc = 0
        self.buffer = bytearray()

    def emit(self, value: int) -> None:
        absolute = self.skipped_at_resume + self.relative_offset
        self.relative_offset += 1
        if absolute < self.start:
            self.skipped += 1
        elif absolute < self.end:
            self.buffer.append(value)
            self.written += 1
            if len(self.buffer) >= 4096:
                self.output.write(self.buffer)
                self.buffer.clear()

    def decoded_position(self) -> int:
        return self.skipped + self.written

    def finish(self) -> None:
        if self.buffer:
            self.output.write(self.buffer)
            self.buffer.clear()


def extract_range(source_db: str | Path, partner_id: str, event_id: str,
                  index_path: str | Path, start: int, length: int,
                  output_path: str | Path) -> dict:
    if start < 0:
        raise GzipIndexError("range start must be non-negative")
    if length < 0:
        raise GzipIndexError("range length must be non-negative")
    out = Path(output_path)
    if out.exists():
        raise GzipIndexError(f"refusing to overwrite existing output: {out}")
    index = Path(index_path)
    index_conn = _connect_index(index)
    source_conn = connect_source_readonly(source_db)
    tmp_out: Path | None = None
    try:
        binding = _load_index_binding(index_conn, partner_id, event_id)
        source_row = locate_accepted_body(source_conn, partner_id, event_id)
        if source_row["body_sha256"] != binding["body_sha256"]:
            raise GzipIndexError("event body SHA-256 differs from index binding")
        if source_row["byte_length"] != binding["source_length"]:
            raise GzipIndexError("source length differs from index binding")
        # Registered digest and source length are binding metadata. This
        # equality check does not stream the BLOB through Python; local page
        # digests below provide the evidence for bytes actually read.
        if binding["body_sha256"].lower() != binding["source_sha256"]:
            raise GzipIndexError(
                "registered raw-body digest does not match source digest"
            )
        header = index_conn.execute("SELECT * FROM header").fetchone()
        total = int(header["decompressed_size"])
        end = start + length
        if start > total or end > total:
            raise GzipIndexError(
                f"range [{start},{end}) exceeds decompressed size {total}"
            )
        checkpoint_row = index_conn.execute(
            "SELECT * FROM checkpoints WHERE output_offset <= ?\n"
            "ORDER BY output_offset DESC LIMIT 1",
            (int(start),),
        ).fetchone()
        if checkpoint_row is None:
            raise GzipIndexError("no eligible checkpoint found")
        if int(checkpoint_row["output_offset"]) > int(start):
            raise GzipIndexError(
                f"internal checkpoint query returned future offset "
                f"{checkpoint_row['output_offset']} for start {start}"
            )
        expected_state_sha = hashlib.sha256(
            checkpoint_row["state_json"].encode("utf-8")
        ).hexdigest()
        if expected_state_sha != checkpoint_row["state_sha256"]:
            raise GzipIndexError("checkpoint state integrity check failed")
        expected_row_sha = _row_digest("checkpoints", [
            checkpoint_row["output_offset"], checkpoint_row["state_json"],
            checkpoint_row["state_sha256"],
        ])
        if expected_row_sha != checkpoint_row["row_sha256"]:
            raise GzipIndexError("checkpoint row integrity check failed")
        state = DeflateState.from_json(json.loads(checkpoint_row["state_json"]))
        if state.output_offset != checkpoint_row["output_offset"]:
            raise GzipIndexError(
                "checkpoint offset/state binding mismatch: "
                f"row={checkpoint_row['output_offset']} state={state.output_offset}"
            )
        if start - state.output_offset > header["spacing"] + 257:
            raise GzipIndexError("checkpoint is too far from requested start")

        page_hashes = _page_hash_map(index_conn)
        stream = BlobByteStream(source_conn, binding["body_sha256"],
                                binding["source_length"], page_hashes)
        try:
            parent = out.parent or Path(".")
            if not parent.is_dir():
                raise GzipIndexError(
                    f"output directory does not exist: {parent}"
                )
            fd, tmp_name = tempfile.mkstemp(prefix=".gzip-extract-",
                                            dir=parent)
            os.close(fd)
            tmp_out = Path(tmp_name)
            with tmp_out.open("wb") as output:
                sink = _ExtractSink(start, length, output,
                                    state.output_offset)
                config = Config(
                    spacing=int(header["spacing"]),
                    max_output=int(header["max_output"]),
                    max_optional_header=int(header["max_optional_header"]),
                    tmp_dir=parent,
                )

                # Reuse gzip member framing. Resume at the saved DEFLATE cursor;
                # if the range crosses a member boundary, verify that member's
                # trailer and parse only the subsequent headers required.
                parser = _GzipParser(stream,
                                     config.max_optional_header)
                current = state
                total_decoded = 0
                while current.output_offset < end:
                    decoder = DeflateDecoder(stream, current,
                                             max_output=config.max_output)
                    decoder.decode_until(end, sink.emit,
                                         allow_member_end=True)
                    total_decoded += decoder.decoded_bytes
                    if decoder.output_offset >= end:
                        break
                    if decoder.block_type >= 0 or not decoder.bfinal_seen:
                        raise TruncatedStream(
                            "member ended before BFINAL during resumed extraction"
                        )
                    member_size = (
                        decoder.output_offset - current.member_start_output
                    )
                    # If this member was resumed at its first output byte, the
                    # running CRC is complete; otherwise local extraction cannot
                    # claim a full-member CRC check without replaying history.
                    trailer_crc = (
                        decoder.crc32_state
                        if decoder.output_offset == current.member_start_output
                        else None
                    )
                    parser.read_trailer(member_size, trailer_crc)
                    if stream.tell() >= stream.length:
                        raise TruncatedStream(
                            "range crosses past the final gzip member"
                        )
                    member_start = stream.tell()
                    data_start, _crc, header_len, optional_len = \
                        parser.parse_member_header()
                    current = DeflateState(
                        bit_pos=data_start * 8,
                        output_offset=decoder.output_offset,
                        crc32_state=0,
                        member_index=current.member_index + 1,
                        member_start_output=decoder.output_offset,
                        member_start_compressed=member_start,
                        member_header_length=header_len,
                        member_optional_header_length=optional_len,
                    )
                sink.finish()
                stats_decoded = total_decoded
        finally:
            stream.close()
        os.replace(tmp_out, out)
        tmp_out = None
        return {
            "operation": "extract",
            "partner_id": partner_id,
            "event_id": event_id,
            "range_start": start,
            "range_length": length,
            "range_end": end,
            "decompressed_size": total,
            "resume_checkpoint": state.output_offset,
            "bytes_skipped_after_checkpoint": start - state.output_offset,
            "bytes_decoded": stats_decoded,
            "pages_read": len(stream.pages_read),
            "compressed_bytes_read": stream.bytes_read,
            "output_bytes": sink.written,
            "output_path": str(out),
        }
    except Exception:
        if tmp_out is not None:
            try:
                tmp_out.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        index_conn.close()
        source_conn.close()


def verify_index(source_db: str | Path, index_path: str | Path,
                 tmp_dir: str | Path | None = None) -> dict:
    index = Path(index_path)
    index_conn = _connect_index(index)
    source_conn = connect_source_readonly(source_db)
    try:
        index_header = index_conn.execute("SELECT * FROM header").fetchone()
        expected_header = _row_digest("header", [
            index_header["magic"], index_header["format_version"],
            index_header["page_size"], index_header["spacing"],
            index_header["max_output"], index_header["max_optional_header"],
            index_header["decompressed_size"], index_header["member_count"],
            index_header["checkpoint_count"], index_header["root_sha256"],
        ])
        if (index_header["magic"] != INDEX_MAGIC or
                expected_header != index_header["header_sha256"]):
            raise GzipIndexError("index header integrity check failed")
        if index_header["page_size"] != PAGE_SIZE:
            raise GzipIndexError("index page size does not match supported format")
        # Verify uses the event identity recorded inside the index, then checks
        # that the same accepted event still exists in the read-only source DB.
        binding = index_conn.execute("SELECT * FROM source_binding").fetchone()
        expected = _row_digest("source_binding", [
            binding["partner_id"], binding["event_id"], binding["body_sha256"],
            binding["source_length"], binding["source_sha256"],
        ])
        if expected != binding["row_sha256"]:
            raise GzipIndexError("source binding integrity check failed")
        source_row = locate_accepted_body(
            source_conn, binding["partner_id"], binding["event_id"]
        )
        if source_row["body_sha256"] != binding["body_sha256"]:
            raise GzipIndexError("event body SHA-256 differs from index binding")
        if source_row["byte_length"] != binding["source_length"]:
            raise GzipIndexError("source length differs from index binding")
        page_rows = index_conn.execute(
            "SELECT * FROM page_checksums ORDER BY page_no"
        ).fetchall()
        expected_pages = (binding["source_length"] + PAGE_SIZE - 1) // PAGE_SIZE
        if len(page_rows) != expected_pages:
            raise GzipIndexError("page checksum count does not cover source")
        page_map: dict[int, str] = {}
        root = _sha256()
        binding_root_sha = binding["row_sha256"]
        root.update(binding_root_sha.encode("ascii"))
        previous_no = -1
        for row in page_rows:
            if row["page_no"] != previous_no + 1:
                raise GzipIndexError("non-contiguous compressed page checksums")
            expected_row = _row_digest("page_checksums", [
                row["page_no"], row["page_offset"], row["page_length"],
                row["page_sha256"],
            ])
            if expected_row != row["row_sha256"]:
                raise GzipIndexError(
                    f"page checksum row {row['page_no']} integrity check failed"
                )
            page_map[int(row["page_no"])] = row["page_sha256"]
            root.update(row["row_sha256"].encode("ascii"))
            previous_no = int(row["page_no"])
        checkpoint_rows = index_conn.execute(
            "SELECT * FROM checkpoints ORDER BY output_offset"
        ).fetchall()
        header = index_header
        if len(checkpoint_rows) != header["checkpoint_count"]:
            raise GzipIndexError("checkpoint count does not match header")
        previous_offset = None
        max_gap = 0
        for row in checkpoint_rows:
            state_sha = hashlib.sha256(
                row["state_json"].encode("utf-8")
            ).hexdigest()
            if state_sha != row["state_sha256"]:
                raise GzipIndexError(
                    f"checkpoint {row['output_offset']} state digest mismatch"
                )
            row_sha = _row_digest("checkpoints", [
                row["output_offset"], row["state_json"], row["state_sha256"],
            ])
            if row_sha != row["row_sha256"]:
                raise GzipIndexError(
                    f"checkpoint {row['output_offset']} row digest mismatch"
                )
            state = DeflateState.from_json(json.loads(row["state_json"]))
            if state.output_offset != row["output_offset"]:
                raise GzipIndexError("checkpoint state offset mismatch")
            state.validate()
            if previous_offset is not None:
                gap = row["output_offset"] - previous_offset
                if gap <= 0:
                    raise GzipIndexError("checkpoint offsets must be increasing")
                max_gap = max(max_gap, gap)
                if gap > header["spacing"] + 257:
                    raise GzipIndexError(
                        f"checkpoint gap {gap} exceeds S+257"
                    )
            previous_offset = row["output_offset"]
            root.update(row["row_sha256"].encode("ascii"))
        if root.hexdigest() != header["root_sha256"]:
            raise GzipIndexError("index root integrity check failed")

        stream = BlobByteStream(source_conn, binding["body_sha256"],
                                binding["source_length"], page_map)
        try:
            whole = _sha256()
            original_load = stream._load_page
            def verify_load(page_no: int) -> bytes:
                data = original_load(page_no)
                whole.update(data)
                return data
            stream._load_page = verify_load  # type: ignore[method-assign]
            config = Config(
                spacing=int(header["spacing"]),
                max_output=int(header["max_output"]),
                max_optional_header=int(header["max_optional_header"]),
                tmp_dir=Path(tmp_dir or tempfile.gettempdir()),
            )
            sink = _BuildSink(config)
            expected_states = {
                row["output_offset"]: json.loads(row["state_json"])
                for row in checkpoint_rows
            }
            sink.checkpoint_callback = lambda state: (
                expected_states.pop(state.output_offset, None)
                if state.to_json() == expected_states.get(state.output_offset)
                else _raise_checkpoint_mismatch(state.output_offset)
            )
            result = _run_gzip(stream, config, sink)
            if whole.hexdigest() != binding["source_sha256"]:
                raise GzipIndexError("whole-source SHA-256 mismatch")
            if expected_states:
                raise GzipIndexError(
                    f"index contains {len(expected_states)} checkpoints not "
                    "reproduced by source stream"
                )
        finally:
            stream.close()
        if result["decompressed_size"] != header["decompressed_size"]:
            raise GzipIndexError("decompressed size mismatch")
        if result["members"] != header["member_count"]:
            raise GzipIndexError("gzip member count mismatch")
        return {
            "operation": "verify",
            "partner_id": binding["partner_id"],
            "event_id": binding["event_id"],
            "source_compressed_bytes": binding["source_length"],
            "decompressed_bytes": result["decompressed_size"],
            "member_count": result["members"],
            "checkpoint_count": len(checkpoint_rows),
            "maximum_checkpoint_gap": max_gap,
            "pages_read": len(stream.pages_read),
            "compressed_bytes_read": stream.bytes_read,
            "index_path": str(index),
            "status": "ok",
        }
    finally:
        index_conn.close()
        source_conn.close()


def _raise_checkpoint_mismatch(offset: int):
    raise GzipIndexError(f"checkpoint state mismatch at output offset {offset}")


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def _nonnegative(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-gzip-index",
        description="Build/use a seekable gzip index without changing the source DB.",
    )
    sub = parser.add_subparsers(dest="operation", required=True)

    build = sub.add_parser("build", help="build an independent SQLite index")
    build.add_argument("--source-db", required=True)
    build.add_argument("--partner-id", required=True)
    build.add_argument("--event-id", required=True)
    build.add_argument("--index", required=True)
    build.add_argument("--spacing", type=_positive, default=DEFAULT_SPACING)
    build.add_argument("--max-output", type=_positive,
                       default=DEFAULT_MAX_OUTPUT)
    build.add_argument("--max-optional-header", type=_positive,
                       default=DEFAULT_MAX_HEADER)
    build.add_argument("--tmp-dir", default=tempfile.gettempdir())
    build.set_defaults(command="build")

    extract = sub.add_parser("extract", help="extract a left-closed/right-open range")
    extract.add_argument("--source-db", required=True)
    extract.add_argument("--partner-id", required=True)
    extract.add_argument("--event-id", required=True)
    extract.add_argument("--index", required=True)
    extract.add_argument("--start", type=_nonnegative, required=True)
    extract.add_argument("--length", type=_nonnegative, required=True)
    extract.add_argument("--output", required=True)
    extract.set_defaults(command="extract")

    verify = sub.add_parser("verify", help="full source and index verification")
    verify.add_argument("--source-db", required=True)
    verify.add_argument("--index", required=True)
    verify.add_argument("--tmp-dir", default=tempfile.gettempdir())
    verify.set_defaults(command="verify")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            config = Config.create(
                spacing=args.spacing,
                max_output=args.max_output,
                max_optional_header=args.max_optional_header,
                tmp_dir=args.tmp_dir,
            )
            stats = build_index(args.source_db, args.partner_id,
                                args.event_id, args.index, config)
        elif args.command == "extract":
            stats = extract_range(args.source_db, args.partner_id,
                                  args.event_id, args.index, args.start,
                                  args.length, args.output)
        else:
            stats = verify_index(args.source_db, args.index, args.tmp_dir)
    except (GzipIndexError, DeflateError, OSError, sqlite3.Error,
            json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        return 2
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
