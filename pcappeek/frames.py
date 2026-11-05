"""以太网帧头部解析。"""

from dataclasses import dataclass

ETHERNET_HEADER_LEN = 14


class FrameError(Exception):
    """帧解析失败时抛出。"""


@dataclass(frozen=True)
class EtherFrame:
    dst: str
    src: str
    ethertype: int
    payload: bytes


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(data: bytes) -> EtherFrame:
    if len(data) < ETHERNET_HEADER_LEN:
        raise FrameError(f"帧太短：{len(data)} 字节，以太网头需要 {ETHERNET_HEADER_LEN} 字节")
    return EtherFrame(
        dst=_mac(data[0:6]),
        src=_mac(data[6:12]),
        ethertype=int.from_bytes(data[12:14], "big"),
        payload=data[14:],
    )