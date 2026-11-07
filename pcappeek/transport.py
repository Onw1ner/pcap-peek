"""传输层：UDP 段解析。"""

from dataclasses import dataclass

UDP_HEADER_LEN = 8
TCP_MIN_HEADER_LEN = 20


class TransportError(Exception):
    """传输层解析失败时抛出。"""


@dataclass(frozen=True)
class UDPSegment:
    src_port: int
    dst_port: int
    payload: bytes


def parse_udp(data: bytes) -> UDPSegment:
    if len(data) < UDP_HEADER_LEN:
        raise TransportError(
            f"UDP 头太短：{len(data)} 字节，至少需要 {UDP_HEADER_LEN} 字节"
        )

    src_port = int.from_bytes(data[0:2], "big")
    dst_port = int.from_bytes(data[2:4], "big")

    return UDPSegment(
        src_port=src_port,
        dst_port=dst_port,
        payload=data[UDP_HEADER_LEN:],
    )


@dataclass(frozen=True)
class TCPSegment:
    src_port: int
    dst_port: int
    flags: int
    payload: bytes


def parse_tcp(data: bytes) -> TCPSegment:
    if len(data) < TCP_MIN_HEADER_LEN:
        raise TransportError(
            f"TCP 头太短：{len(data)} 字节，至少需要 {TCP_MIN_HEADER_LEN} 字节"
        )

    data_offset = (data[12] >> 4) * 4

    if data_offset < TCP_MIN_HEADER_LEN:
        raise TransportError(
            f"TCP 头长度异常：数据偏移={data[12] >> 4}，换算后 {data_offset} 字节"
        )
    if len(data) < data_offset:
        raise TransportError(
            f"TCP 头被截断：声明 {data_offset} 字节，实际只有 {len(data)} 字节"
        )

    return TCPSegment(
        src_port=int.from_bytes(data[0:2], "big"),
        dst_port=int.from_bytes(data[2:4], "big"),
        flags=data[13],
        payload=data[data_offset:],
    )