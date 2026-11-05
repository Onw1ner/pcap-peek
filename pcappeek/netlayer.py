"""IPv4 头部解析。"""

import ipaddress
from dataclasses import dataclass

IPV4_MIN_HEADER_LEN = 20

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


class NetError(Exception):
    """网络层解析失败时抛出。"""


@dataclass(frozen=True)
class IPv4Packet:
    src: str
    dst: str
    protocol: int
    payload: bytes


def parse_ipv4(data: bytes) -> IPv4Packet:
    if len(data) < IPV4_MIN_HEADER_LEN:
        raise NetError(f"IPv4 头太短：{len(data)} 字节，至少需要 {IPV4_MIN_HEADER_LEN} 字节")

    version = data[0] >> 4
    ihl = data[0] & 0x0F
    header_len = ihl * 4

    if version != 4:
        raise NetError(f"不是 IPv4：版本字段为 {version}")
    if header_len < IPV4_MIN_HEADER_LEN:
        raise NetError(f"IPv4 头长度异常：IHL={ihl}，换算后 {header_len} 字节")
    if len(data) < header_len:
        raise NetError(f"IPv4 头被截断：声明 {header_len} 字节，实际只有 {len(data)} 字节")

    return IPv4Packet(
        src=str(ipaddress.IPv4Address(data[12:16])),
        dst=str(ipaddress.IPv4Address(data[16:20])),
        protocol=data[9],
        payload=data[header_len:],
    )