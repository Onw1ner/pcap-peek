"""TLS 握手跨 TCP 段重组：按序列号放置，能识别重传与空洞。"""

from pcappeek.app.tls import MAX_PENDING, HandshakeAssembler


def record(total: int) -> bytes:
    """造一条「声称 total 字节」的 TLS 记录。"""
    return b"\x16\x03\x01" + (total - 5).to_bytes(2, "big") + b"\x00" * (total - 5)


def test_single_segment_record():
    a = HandshakeAssembler()
    data = record(40)
    assert a.feed(("k",), 0, data) == data


def test_split_record_in_order():
    a = HandshakeAssembler()
    data = record(100)
    assert a.feed(("k",), 0, data[:60]) is None
    assert a.feed(("k",), 60, data[60:]) == data


def test_retransmission_is_idempotent():
    a = HandshakeAssembler()
    data = record(100)
    assert a.feed(("k",), 0, data[:60]) is None
    assert a.feed(("k",), 0, data[:60]) is None      # 重传：不能重复追加
    assert a.feed(("k",), 60, data[60:]) == data


def test_gap_aborts_connection():
    a = HandshakeAssembler()
    data = record(300)
    assert a.feed(("k",), 0, data[:60]) is None
    assert a.feed(("k",), 200, data[200:]) is None   # 中间缺 140 字节
    assert a.feed(("k",), 60, data[60:200]) is None  # 迟到也补不回来


def test_connection_is_not_retried_after_success():
    a = HandshakeAssembler()
    data = record(40)
    assert a.feed(("k",), 0, data) == data
    assert a.feed(("k",), 40, data) is None


def test_ignores_payload_not_starting_with_handshake():
    a = HandshakeAssembler()
    assert a.feed(("k",), 0, b"\x17\x03\x03\x00\x05hello") is None


def test_buffer_cap_drops_connection():
    a = HandshakeAssembler()
    header = b"\x16\x03\x01" + (65535).to_bytes(2, "big")
    assert a.feed(("k",), 0, header) is None
    assert a.feed(("k",), 5, b"\x00" * MAX_PENDING) is None
    assert a.feed(("k",), 5 + MAX_PENDING, b"\x00" * 100) is None


def test_empty_payload_does_not_poison_connection():
    a = HandshakeAssembler()
    data = record(40)
    assert a.feed(("k",), 0, b"") is None      # 纯 ACK，先来一个空的
    assert a.feed(("k",), 0, data) == data     # 连接还得能继续用