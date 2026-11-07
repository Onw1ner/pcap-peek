"""TLS ClientHello 里 SNI 的解析测试。

只解析握手的第一条 ClientHello，拿到服务器名就停：
不解密、不解析证书、不跟进后续记录。
"""

import pytest

from pcappeek.app.tls import TlsError, parse_client_hello


def client_hello(hostname: str | None = "example.com") -> bytes:
    """造一条携带 SNI 的 ClientHello 记录。"""
    ext = b""
    if hostname is not None:
        name = hostname.encode()
        entry = b"\x00" + len(name).to_bytes(2, "big") + name      # 类型0 + 长度 + 名字
        sni = len(entry).to_bytes(2, "big") + entry                # server_name_list
        ext = (0x0000).to_bytes(2, "big") + len(sni).to_bytes(2, "big") + sni

    body = b"\x03\x03"                    # client_version = TLS 1.2
    body += b"\x00" * 32                  # random
    body += b"\x00"                       # session_id 长度 = 0
    body += b"\x00\x02\x13\x01"           # cipher_suites：1 个套件
    body += b"\x01\x00"                   # compression_methods：1 个 null
    body += len(ext).to_bytes(2, "big") + ext

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_reads_sni():
    hello = parse_client_hello(client_hello("www.example.com"))
    assert hello.server_name == "www.example.com"


def test_no_sni_returns_empty():
    hello = parse_client_hello(client_hello(None))
    assert hello.server_name == ""


def test_non_handshake_record_raises():
    with pytest.raises(TlsError):
        parse_client_hello(b"\x17\x03\x03\x00\x05" + b"\x00" * 5)


def test_truncated_raises():
    with pytest.raises(TlsError):
        parse_client_hello(client_hello()[:30])


def test_sni_length_beyond_data_raises():
    # 手工造一个「名字长度 100、实际只有 3 字节」的坏扩展
    entry = b"\x00" + b"\x00\x64" + b"abc"
    sni = len(entry).to_bytes(2, "big") + entry
    ext = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += len(ext).to_bytes(2, "big") + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    with pytest.raises(TlsError):
        parse_client_hello(record)