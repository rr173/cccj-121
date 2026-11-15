"""正文差量交接的二进制格式常量与编码工具。

三条独立入口共用这里的格式说明：``signature``（下游为旧文件生成块签名）、
``delta``（服务端按签名与新正文生成差量包）、``apply``（下游用旧文件与差量
包还原新正文），另有只读的 ``inspect``。

设计约束
--------

* 只用 Python 标准库；签名与差量包都是**可分块读取**的二进制文件；
* 格式自带版本号与整包 SHA-256，任何读取端都先核头部再分配；
* 所有整数为无符号大端定长（见下），字符串为长度前缀 UTF-8；
* 不声称提供认证：摘要只证明内容完整性、证明字节与某版本一致，不证明
  发送方身份。签名与差量包都没有外部签名/HMAC。

签名格式（``blocksig v1``）::

    magic          8 字节   b"PWSIG01\\n"（含换行，用于判错）
    format_version u16      = 1
    block_size     u32      块长 B，1 <= B <= SIGNATURE_MAX_BLOCK (16 MiB)
    file_length    u64      旧文件全长
    file_sha256    32 字节  旧文件整文件 SHA-256
    block_count    u64      块数 = ceil(file_length / B)，空文件为 0
    blocks         block_count 条，顺序固定：
        offset     u64      该块在旧文件中的起始偏移
        length     u32      该块真实长度；除尾块外恒等于 B，尾块 1..B
        weak       u32      (b << 16) | a，定义见 blocksig.py
        sha256     32 字节  该块字节的 SHA-256
    trailer_sha256 32 字节  以上全部字节（含 magic）的 SHA-256

块严格按旧文件连续、非重叠、B 字节切分，因此 ``offset`` 与顺序都是冗余
但可校验的：读取端要求 ``offset == index * B``、``length == B``（尾块除
外）、块数与文件长度一致，最后一段恰好覆盖文件末尾。

差量包格式（``pwdelta v1``）::

    magic          8 字节   b"PWDELTA1"
    format_version u16      = 1
    partner_len    u16      1..DELTA_MAX_ID_BYTES
    event_len      u16      1..DELTA_MAX_ID_BYTES
    block_size     u32      生成签名时的 B，1 <= B <= DELTA_MAX_BLOCK
    old_length     u64      旧文件全长（与签名一致）
    old_sha256     32 字节  旧文件整文件 SHA-256
    new_length     u64      新正文全长
    new_sha256     32 字节  新正文整文件 SHA-256
    partner_id     partner_len 字节 UTF-8（严格解码，不允许代理/非法序列）
    event_id       event_len 字节 UTF-8
    literal_cap    u32      LITERAL 单条长度上限（生成时使用的 LITERAL_MAX）
    copy_cap       u32      COPY 单条长度上限（<= block_size）
    body:
        opcode u8       1 = COPY，2 = LITERAL
        COPY:
            offset u64  必须是签名中某个**完整块**的起始偏移
            length u32  必须恰等于该块长度（不允许跨块或截取）
        LITERAL:
            length u32  0 < length <= literal_cap
            data   length 字节，原样字节，不转文本
    end_marker     8 字节   b"PWEND001"
    trailer_sha256 32 字节  以上全部字节（含 magic、end_marker）的 SHA-256

读取端必须核对：magic/版本、各长度字段的范围、身份 UTF-8、COPY 边界与
块对齐、LITERAL 上限、所有指令输出之和 == new_length、结束标记、整包
SHA-256，以及结束标记之后没有额外字节。

长度编码：整数均为**无符号大端**定长（u16/u32/u64），无变长编码，因此
每个头部字段的偏移都是固定的，读取时可先读固定头、再按声明长度分配。
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

# --------------------------------------------------------------------- #
# 全局上限（均可通过命令行调小，不可超过这里的硬顶）
# --------------------------------------------------------------------- #
SIG_MAGIC = b"PWSIG01\n"
DELTA_MAGIC = b"PWDELTA1"
END_MARKER = b"PWEND001"

FORMAT_VERSION = 1
SIG_HEADER_FIXED = 8 + 2 + 4 + 8 + 32 + 8          # = 62
SIG_BLOCK_RECORD = 8 + 4 + 4 + 32                   # = 48
SIG_FIXED_TAIL = 32                                 # trailer_sha256

DELTA_HEADER_FIXED = 8 + 2 + 2 + 2 + 4 + 8 + 32 + 8 + 32  # = 98
DELTA_TRAILER_FIXED = 8 + 32                        # end_marker + sha256

MAX_BLOCK_SIZE = 16 * 1024 * 1024
MAX_ID_BYTES = 255
MAX_LITERAL = 4 * 1024 * 1024
MAX_COPY = 16 * 1024 * 1024
MAX_OPERATIONS = 0xFFFFFFFF          # 指令条数上限（u64 也会先检查）
MAX_OUTPUT = (1 << 63) - 1           # 目标总长硬顶

# 推荐的默认值（入口命令行默认；调用方可再调小）
DEFAULT_BLOCK_SIZE = 4096
DEFAULT_LITERAL_MAX = 64 * 1024
DEFAULT_MAX_OPERATIONS = 4_000_000
DEFAULT_MAX_OUTPUT = 1 << 40         # 1 TiB，防止明显荒谬的声明

DEFAULT_READ_CHUNK = 1024 * 1024
DEFAULT_SIG_READ_CACHE = 4 * 1024 * 1024
DEFAULT_TMP_SUFFIX = ".part"


class FormatError(ValueError):
    """格式/完整性错误。``offset`` 为能定位的字节偏移（若有）。"""

    def __init__(self, message: str, *, offset: int | None = None,
                 limit: int | None = None, which: str = "pos"):
        super().__init__(message)
        self.offset = offset
        self.limit = limit
        self.which = which

    def __str__(self) -> str:  # pragma: no cover - 简单拼装
        base = super().__str__()
        if self.offset is None:
            return base
        if self.limit is not None:
            return (f"{base}（请输入 1..{self.limit} 之间的 {self.which}；"
                    f"偏移 {self.offset}）")
        return f"{base}（偏移 {self.offset}）"


class DeltaError(Exception):
    """业务前提错误（事件不存在、摘要不符等），非格式错误。"""


# --------------------------------------------------------------------- #
# 短读安全的读取包装
# --------------------------------------------------------------------- #
class HashingReader:
    """在每次 ``read`` 上更新 SHA-256，摘要严格覆盖**实际读到的字节**。

    这样整包/整签名的校验不依赖“重新编码头部”是否与原始字节逐字节相同；
    任何被读取的字节（包括头部、指令、字面）都计入。读取端在读取尾部
    摘要字段**之前**用 ``snapshot()`` 取当时的摘要。
    """

    def __init__(self, raw):
        self.raw = raw
        self.hasher = hashlib.sha256()
        self.bytes_read = 0

    def read(self, n: int) -> bytes:
        chunk = self.raw.read(n)
        if chunk:
            self.hasher.update(chunk)
            self.bytes_read += len(chunk)
        return chunk

    def snapshot(self) -> bytes:
        return self.hasher.copy().digest()


class ReadWrapper:
    """把任意 ``read(n)`` 可能短读的流包装成**恰好读 n 字节**。

    统计实际调用次数与短读次数，验收脚本与测试可据此证明协议不假设
    ``read(n)`` 一次返回全部字节。``read(n) == b""`` 表示流结束。
    """

    def __init__(self, raw, *, chunk_limit: int | None = None):
        self.raw = raw
        self.chunk_limit = chunk_limit
        self.calls = 0
        self.short_reads = 0
        self.bytes_read = 0
        self._buf = bytearray()

    def read_exact(self, n: int, *, allow_eof_at_start: bool = False) -> bytes:
        if n < 0:
            raise ValueError("读取长度不能为负")
        out = bytearray()
        while len(out) < n:
            want = n - len(out)
            if self.chunk_limit is not None:
                want = min(want, self.chunk_limit)
            chunk = self.raw.read(want)
            self.calls += 1
            if not chunk:
                if allow_eof_at_start and not out:
                    return b""
                raise FormatError(
                    f"意外读到文件结尾（还需要 {n - len(out)} 字节）",
                    offset=self.bytes_read,
                )
            if len(chunk) < want:
                self.short_reads += 1
            out += chunk
            self.bytes_read += len(chunk)
        return bytes(out)

    def at_eof(self) -> bool:
        """尝试读 1 字节判断是否还有尾随数据。"""
        chunk = self.raw.read(1)
        self.calls += 1
        if not chunk:
            return True
        self._buf += chunk
        self.bytes_read += 1
        return False

    def snapshot(self) -> bytes:
        """当前已读字节的 SHA-256（底层需为 :class:`HashingReader`）。"""
        if not isinstance(self.raw, HashingReader):
            raise TypeError("读取包装未接入摘要")
        return self.raw.snapshot()


# --------------------------------------------------------------------- #
# 基础编码
# --------------------------------------------------------------------- #
def u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise FormatError(f"u16 越界: {value}")
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise FormatError(f"u32 越界: {value}")
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise FormatError(f"u64 越界: {value}")
    return value.to_bytes(8, "big")


def decode_u16(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def decode_u32(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def decode_u64(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encode_identity(value: str, *, limit: int = MAX_ID_BYTES) -> bytes:
    """身份字符串必须是非空、严格 UTF-8、无 NUL、长度不超过 limit。"""
    if not isinstance(value, str) or not value:
        raise FormatError("身份字符串必须非空")
    raw = value.encode("utf-8")
    if len(raw) > limit:
        raise FormatError(f"身份字符串超过 {limit} 字节上限")
    if b"\x00" in raw:
        raise FormatError("身份字符串不允许 NUL 字节")
    return raw


def decode_identity(raw: bytes, *, field: str = "身份") -> str:
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise FormatError(f"{field} 不是严格 UTF-8") from exc
    if not value:
        raise FormatError(f"{field} 不能为空")
    if "\x00" in value:
        raise FormatError(f"{field} 不允许 NUL 字符")
    return value


# --------------------------------------------------------------------- #
# 文件分块读取（不把大 BLOB 一次取成 bytes）
# --------------------------------------------------------------------- #
class FileSliceReader:
    """对普通文件做随机访问的 ``read_at``，用于按块读旧文件。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._fh = open(self.path, "rb")
        self.length = os.fstat(self._fh.fileno()).st_size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.length:
            raise FormatError(f"文件读取越界: offset={offset} length={length}",
                              offset=offset)
        self._fh.seek(offset)
        data = self._fh.read(length)
        if len(data) != length:
            raise FormatError("旧文件读取短读", offset=offset)
        return data

    def iter_chunks(self, *, chunk_size: int = DEFAULT_READ_CHUNK):
        self._fh.seek(0)
        remaining = self.length
        while remaining > 0:
            data = self._fh.read(min(chunk_size, remaining))
            if not data:
                raise FormatError("旧文件读取短读", offset=self.length - remaining)
            remaining -= len(data)
            yield data

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def write_atomic(path: str | Path, writer) -> None:
    """先写同目录临时文件再 ``os.replace``，失败时删除临时文件。

    ``writer(fh)`` 负责写入全部内容。已有目标文件**拒绝覆盖**，因此这里
    只在调用方已确认目标不存在后使用。
    """
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    tmp = parent / (target.name + DEFAULT_TMP_SUFFIX)
    if target.exists():
        raise FileExistsError(f"目标已存在: {target}")
    if tmp.exists():
        # 上次失败遗留的临时文件不能被误当完整输出；直接删除它。
        tmp.unlink()
    try:
        with open(tmp, "wb") as fh:
            writer(fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise
