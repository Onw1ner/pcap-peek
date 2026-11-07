"""TLS 握手跨 TCP 段重组。"""

import pytest

from pcappeek.app.tls import MAX_PENDING, HandshakeAssembler


def record(total: int) -> bytes:
    """造一条「声称 total 字节」的 TLS 记录。"""
    return b"\x16\x03\x01" + (total - 5).to_bytes(2, "big") + b"\x00" * (total - 5)


def test_single_packet_record():
    a = HandshakeAssembler()
    data = record(40)
    assert a.feed(("k",), data) == data


def test_split_record():
    a = HandshakeAssembler()
    data = record(100)
    assert a.feed(("k",), data[:60]) is None
    assert a.feed(("k",), data[60:]) == data


def test_ignores_payload_not_starting_with_handshake():
    a = HandshakeAssembler()
    assert a.feed(("k",), b"\x17\x03\x03\x00\x05hello") is None


def test_buffer_cap_drops_connection():
    a = HandshakeAssembler()
    header = b"\x16\x03\x01" + (65535).to_bytes(2, "big")
    assert a.feed(("k",), header) is None
    assert a.feed(("k",), b"\x00" * MAX_PENDING) is None
    assert a.feed(("k",), b"\x00" * 100) is None


def test_connection_is_not_retried_after_success():
    a = HandshakeAssembler()
    data = record(40)
    assert a.feed(("k",), data) == data
    assert a.feed(("k",), data) is None