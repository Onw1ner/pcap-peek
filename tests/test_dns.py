"""DNS 查询解析的测试。只解析「查询」，不解析应答里的资源记录。"""

import pytest

from pcappeek.app.dns import DnsError, parse_dns_query


def dns_query(name: bytes, qtype: int = 1, ident: int = 0x1234) -> bytes:
    """造一个 DNS 查询报文（12 字节头 + 问题段）。"""
    header = ident.to_bytes(2, "big")      # 事务 ID
    header += b"\x01\x00"                  # 标志：QR=0 查询、RD=1 期望递归
    header += b"\x00\x01"                  # QDCOUNT=1 一个问题
    header += b"\x00\x00" * 3              # ANCOUNT / NSCOUNT / ARCOUNT = 0
    return header + name + qtype.to_bytes(2, "big") + b"\x00\x01"


def test_simple_question():
    name = b"\x03www\x07example\x03com\x00"
    q = parse_dns_query(dns_query(name))
    assert q.name == "www.example.com"
    assert q.qtype == 1


def test_response_is_rejected():
    header = b"\x12\x34" + b"\x81\x80" + b"\x00\x01" + b"\x00\x00" * 3
    payload = header + b"\x03www\x00" + b"\x00\x01\x00\x01"
    with pytest.raises(DnsError):
        parse_dns_query(payload)


def test_truncated_name_raises():
    header = b"\x12\x34\x01\x00\x00\x01" + b"\x00\x00" * 3
    with pytest.raises(DnsError):
        parse_dns_query(header + b"\x07examp")


def test_zero_questions_raises():
    header = b"\x12\x34\x01\x00\x00\x00" + b"\x00\x00" * 3
    with pytest.raises(DnsError):
        parse_dns_query(header)