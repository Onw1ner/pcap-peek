"""链路层归一化的测试：以太网帧与 802.11 数据帧都要能拆出 (ethertype, 负载)。"""

import pytest

from pcappeek.frames import FrameError
from pcappeek.link import link_payload

LLC_SNAP_IPV4 = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"


def dot11_frame(fc0: int, fc1: int, payload: bytes, llc: bytes | None = None) -> bytes:
    """造一个 802.11 数据帧。

    头部顺序（IEEE 802.11 §9.2）：帧控制2 + 持续时间2 + 地址1/2/3各6
                              + 序列控制2 + [地址4 6] + [QoS控制 2]
    """
    header = bytes([fc0, fc1]) + b"\x00\x00"
    header += bytes.fromhex("aabbccddeeff")   # 地址1
    header += bytes.fromhex("112233445566")   # 地址2
    header += bytes.fromhex("778899aabbcc")   # 地址3
    header += b"\x00\x00"                      # 序列控制
    if fc1 & 0x03 == 0x03:                     # ToDS 与 FromDS 同时置位 → 四地址
        header += bytes.fromhex("deadbeef0001")  # 地址4
    if fc0 & 0xF0 == 0x80:                     # QoS Data 多 2 字节
        header += b"\x00\x00"
    return header + (LLC_SNAP_IPV4 if llc is None else llc) + payload


def test_ethernet_ipv4():
    data = bytes.fromhex("aabbccddeeff" "112233445566" "0800") + b"\x45\x00"
    ethertype, payload = link_payload(data)
    assert ethertype == 0x0800
    assert payload == b"\x45\x00"


def test_dot11_data():
    data = dot11_frame(0x08, 0x01, b"\x45\x00\x00\x14")
    ethertype, payload = link_payload(data)
    assert ethertype == 0x0800
    assert payload == b"\x45\x00\x00\x14"


def test_dot11_qos_data():
    data = dot11_frame(0x88, 0x02, b"\x45\x00\x00\x14")
    ethertype, payload = link_payload(data)
    assert ethertype == 0x0800
    assert payload == b"\x45\x00\x00\x14"


def test_dot11_four_address():
    data = dot11_frame(0x08, 0x03, b"\x45\x00\x00\x14")
    ethertype, payload = link_payload(data)
    assert ethertype == 0x0800
    assert payload == b"\x45\x00\x00\x14"


def test_dot11_without_llc_snap_raises():
    data = dot11_frame(0x08, 0x01, b"\x45\x00", llc=b"\x00" * 8)
    with pytest.raises(FrameError):
        link_payload(data)


def test_garbage_raises():
    with pytest.raises(FrameError):
        link_payload(b"\x00" * 40)