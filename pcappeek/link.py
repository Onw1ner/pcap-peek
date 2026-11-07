"""链路层归一化：把不同的链路层封装拆成 (ethertype, 网络层负载)。

为什么需要：一次真实抓包里可能混着多种封装。本机走 Wi-Fi 时，
pktmon 会把同一条流量的「原始 802.11 帧」和「以太网封装帧」都记下来，
而 pcapng 的 linktype 字段仍然只写 1（以太网）。不做归一化就只能解析一部分。
"""

from pcappeek.frames import FrameError

ETHERNET_HEADER_LEN = 14

KNOWN_ETHERTYPES = frozenset({
    0x0800,  # IPv4
    0x0806,  # ARP
    0x86DD,  # IPv6
    0x8100,  # VLAN 标签（802.1Q）
    0x8847,  # MPLS 单播
    0x8848,  # MPLS 组播
    0x8864,  # PPPoE 会话
    0x888E,  # EAPOL（802.1X）
    0x88CC,  # LLDP
})

DOT11_DATA_TYPE_MASK = 0x0C
DOT11_DATA_TYPE = 0x08
DOT11_QOS_SUBTYPE_MASK = 0xF0
DOT11_QOS_SUBTYPE = 0x80
DOT11_BASE_HEADER_LEN = 24
DOT11_ADDR4_EXTRA_LEN = 6
DOT11_QOS_EXTRA_LEN = 2

LLC_SNAP_LEN = 8
LLC_SNAP_PREFIX = b"\xaa\xaa\x03"
SNAP_OUI_ETHERNET = b"\x00\x00\x00"


def _dot11_header_len(data: bytes) -> int | None:
    """若是 802.11 数据帧，返回 MAC 头长度；否则返回 None。"""
    if len(data) < DOT11_BASE_HEADER_LEN:
        return None

    fc0, fc1 = data[0], data[1]

    if fc0 & 0x03 != 0:
        return None
    if fc0 & DOT11_DATA_TYPE_MASK != DOT11_DATA_TYPE:
        return None

    length = DOT11_BASE_HEADER_LEN
    if fc1 & 0x03 == 0x03:
        length += DOT11_ADDR4_EXTRA_LEN
    if fc0 & DOT11_QOS_SUBTYPE_MASK == DOT11_QOS_SUBTYPE:
        length += DOT11_QOS_EXTRA_LEN
    return length


def parse_dot11(data: bytes) -> tuple[int, bytes]:
    """拆 802.11 数据帧，返回 (ethertype, 网络层负载)。"""
    header_len = _dot11_header_len(data)
    if header_len is None:
        raise FrameError("不是 802.11 数据帧")

    llc = data[header_len:header_len + LLC_SNAP_LEN]
    if len(llc) < LLC_SNAP_LEN:
        raise FrameError(f"802.11 帧太短，取不到 LLC/SNAP 头（只有 {len(llc)} 字节）")
    if not llc.startswith(LLC_SNAP_PREFIX):
        raise FrameError(f"802.11 帧里没有 LLC/SNAP 头：{llc[:3].hex()}")
    if llc[3:6] != SNAP_OUI_ETHERNET:
        raise FrameError(f"不支持的 SNAP OUI：{llc[3:6].hex()}")

    ethertype = int.from_bytes(llc[6:8], "big")
    return ethertype, data[header_len + LLC_SNAP_LEN:]


def link_payload(data: bytes) -> tuple[int, bytes]:
    """把任意链路层封装拆成 (ethertype, 网络层负载)。"""
    if len(data) >= ETHERNET_HEADER_LEN:
        ethertype = int.from_bytes(data[12:ETHERNET_HEADER_LEN], "big")
        if ethertype in KNOWN_ETHERTYPES:
            return ethertype, data[ETHERNET_HEADER_LEN:]
    return parse_dot11(data)