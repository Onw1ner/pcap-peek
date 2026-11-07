"""从 TLS ClientHello 中提取 SNI（服务器名）。

边界：
- 只解析握手的第一条 ClientHello，拿到名字就停
- 不解密、不解析证书、不跟进后续记录
- SNI 可能为空（客户端未发送，或使用 ECH），这是合法情况，返回 ""
"""

from dataclasses import dataclass

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
RECORD_HEADER_LEN = 5
HANDSHAKE_HEADER_LEN = 4
RANDOM_LEN = 32
EXT_SERVER_NAME = 0x0000
SNI_TYPE_HOSTNAME = 0x00


class TlsError(Exception):
    """TLS 记录不合法，或不是可解析的 ClientHello。"""


@dataclass(frozen=True)
class ClientHello:
    server_name: str
    version: tuple[int, int]

    @property
    def version_str(self) -> str:
        return f"{self.version[0]}.{self.version[1]}"


def _read(data: bytes, offset: int, size: int) -> bytes:
    """从 offset 读 size 字节，不够就报错（切片越界不会自己报错）。"""
    chunk = data[offset:offset + size]
    if len(chunk) < size:
        raise TlsError(f"越界：从第 {offset} 字节读 {size} 字节，实际只有 {len(chunk)}")
    return chunk


def _u8(data: bytes, offset: int) -> int:
    return _read(data, offset, 1)[0]


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(_read(data, offset, 2), "big")


def _u24(data: bytes, offset: int) -> int:
    return int.from_bytes(_read(data, offset, 3), "big")


def _parse_server_name(data: bytes) -> str:
    """解析 SNI 扩展的内容：列表长度 + 若干 (类型, 名字长度, 名字)。"""
    list_len = _u16(data, 0)
    end = 2 + list_len
    offset = 2

    while offset + 3 <= end:
        name_type = _u8(data, offset)
        name_len = _u16(data, offset + 1)
        offset += 3
        raw = _read(data, offset, name_len)
        offset += name_len
        if name_type == SNI_TYPE_HOSTNAME:
            return raw.decode("ascii", errors="replace")

    raise TlsError("server_name 扩展里没有 host_name 条目")


def _find_sni(extensions: bytes) -> str:
    """在扩展列表里找 server_name（类型 0x0000），找不到返回空字符串。"""
    offset = 0
    while offset + 4 <= len(extensions):
        ext_type = _u16(extensions, offset)
        ext_len = _u16(extensions, offset + 2)
        offset += 4
        ext_data = _read(extensions, offset, ext_len)
        offset += ext_len
        if ext_type == EXT_SERVER_NAME:
            return _parse_server_name(ext_data)
    return ""


def parse_client_hello(data: bytes) -> ClientHello:
    """解析一条 TLS 记录，返回 ClientHello 里的 SNI 与版本。"""
    if _u8(data, 0) != CONTENT_TYPE_HANDSHAKE:
        raise TlsError(f"不是握手记录：ContentType=0x{data[0]:02X}")

    record_len = _u16(data, 3)
    record = _read(data, RECORD_HEADER_LEN, record_len)

    hs_type = _u8(record, 0)
    if hs_type != HANDSHAKE_CLIENT_HELLO:
        raise TlsError(f"不是 ClientHello：握手类型=0x{hs_type:02X}")

    hs_len = _u24(record, 1)
    hs = _read(record, HANDSHAKE_HEADER_LEN, hs_len)

    version = (_u8(hs, 0), _u8(hs, 1))

    offset = 2 + RANDOM_LEN
    offset += 1 + _u8(hs, offset)          # 会话 ID
    offset += 2 + _u16(hs, offset)         # 密码套件
    offset += 1 + _u8(hs, offset)          # 压缩方法

    ext_total = _u16(hs, offset)
    offset += 2
    extensions = _read(hs, offset, ext_total)

    return ClientHello(server_name=_find_sni(extensions), version=version)


MAX_PENDING = 16384


@dataclass
class _Pending:
    """一条连接的重组状态。"""

    base_seq: int
    buffer: bytearray


class HandshakeAssembler:
    """按 TCP 序列号把跨段数据拼成一条完整 TLS 记录。

    三种真实情况：
    - 重传：同一 seq 再来一次，重叠部分丢弃
    - 迟到：起点落在已收范围内，只取没覆盖的尾巴
    - 空洞：起点超过已收长度，说明中间缺段，放弃该连接（不猜）
    """

    def __init__(self) -> None:
        self._pending: dict[object, _Pending] = {}
        self._done: set[object] = set()

    def feed(self, key: object, seq: int, payload: bytes) -> bytes | None:
        if key in self._done:
            return None

        state = self._pending.get(key)

        if state is None:
            if not payload:
                return None
            if not payload.startswith(b"\x16"):
                self._done.add(key)
                return None
            state = _Pending(base_seq=seq, buffer=bytearray())
            self._pending[key] = state
            
        offset = seq - state.base_seq

        if offset < 0:
            payload = payload[-offset:]
            offset = 0

        if offset > len(state.buffer):
            self._pending.pop(key, None)
            self._done.add(key)
            return None

        if offset < len(state.buffer):
            payload = payload[len(state.buffer) - offset:]

        state.buffer += payload

        if len(state.buffer) < RECORD_HEADER_LEN:
            return None

        record_len = int.from_bytes(state.buffer[3:5], "big")
        total = RECORD_HEADER_LEN + record_len

        if total > MAX_PENDING:
            self._pending.pop(key, None)
            self._done.add(key)
            return None

        if len(state.buffer) < total:
            return None

        data = bytes(state.buffer[:total])
        self._pending.pop(key, None)
        self._done.add(key)
        return data

    def __len__(self) -> int:
        return len(self._pending)