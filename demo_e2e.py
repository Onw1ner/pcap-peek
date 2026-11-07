"""端到端演示：造样本 → 读 pcap → 剥以太网 → 剥 IPv4 → 统计协议分布。"""

import struct
from collections import Counter
from pathlib import Path

from pcappeek.frames import FrameError, parse_ethernet
from pcappeek.netlayer import NetError, parse_ipv4
from pcappeek.pcap import PcapReader

MAC_DST = bytes.fromhex("aabbccddeeff")
MAC_SRC = bytes.fromhex("112233445566")
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def ethernet_frame(payload: bytes) -> bytes:
    return MAC_DST + MAC_SRC + b"\x08\x00" + payload


def ipv4_packet(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), 0x1C46, 0x4000, 64, proto, 0, src_b, dst_b,
    )
    return header + payload


def tcp_segment(src_port: int, dst_port: int, payload: bytes, flags: int = 0x18) -> bytes:
    header = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, 1, 0, 0x50, flags, 8192, 0, 0,
    )
    return header + payload


def udp_segment(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def pcap_bytes(frames: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", 100 + i, 0, len(frame), len(frame)) + frame
    return out


def main() -> None:
    frames = [
        ethernet_frame(
            ipv4_packet("192.168.1.1", "8.8.8.8", 6, tcp_segment(50000, 443, b"hello"))
        ),
        ethernet_frame(
            ipv4_packet("192.168.1.1", "8.8.4.4", 17, udp_segment(50001, 53, b"query"))
        ),
        ethernet_frame(ipv4_packet("192.168.1.2", "1.1.1.1", 1, b"icmp")),
    ]

    out_dir = Path("samples/_local")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "demo.pcap"
    path.write_bytes(pcap_bytes(frames))

    proto_counter = Counter()
    src_counter = Counter()
    total = 0
    failed = 0

    for frame in PcapReader(path):
        total += 1
        try:
            eth = parse_ethernet(frame.data)
            if eth.ethertype != 0x0800:
                continue
            ip = parse_ipv4(eth.payload)
        except (FrameError, NetError):
            failed += 1
            continue
        proto_counter[PROTO_NAMES.get(ip.protocol, str(ip.protocol))] += 1
        src_counter[ip.src] += 1

    print(f"帧总数: {total}")
    print(f"解析失败: {failed}")
    print("协议分布:")
    for name, n in proto_counter.most_common():
        print(f"  {name:<5}{n}")
    print("源 IP 分布:")
    for addr, n in src_counter.most_common():
        print(f"  {addr:<13}{n}")


if __name__ == "__main__":
    main()