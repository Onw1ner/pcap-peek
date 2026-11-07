"""造一个"可疑样本"：端口扫描 + 明文凭据 + DNS 隧道，用来验证三条检测规则。"""

import struct
from pathlib import Path

from demo_e2e import ethernet_frame, ipv4_packet, pcap_bytes, tcp_segment, udp_segment

SCANNER = "10.0.0.5"
TARGET = "10.0.0.9"
BROWSER = "10.0.0.6"
TUNNEL = "10.0.0.7"
DNS_SERVER = "8.8.8.8"


def dns_query(name: str, qtype: int = 16) -> bytes:
    """拼一条 DNS 查询报文：12 字节头 + QNAME + QTYPE + QCLASS。"""
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", qtype, 1)


def main() -> None:
    frames = []

    # ① 端口扫描：30 个 SYN，一个都不完成
    for port in range(1000, 1030):
        frames.append(
            ethernet_frame(
                ipv4_packet(SCANNER, TARGET, 6, tcp_segment(40000, port, b"", flags=0x02))
            )
        )

    # ② 明文凭据：admin:secret123 的 Basic 头
    request = (
        b"GET /admin HTTP/1.1\r\n"
        b"Host: 10.0.0.9\r\n"
        b"Authorization: Basic YWRtaW46c2VjcmV0MTIz\r\n"
        b"\r\n"
    )
    frames.append(
        ethernet_frame(ipv4_packet(BROWSER, TARGET, 6, tcp_segment(40001, 80, request)))
    )

    # ③ DNS 隧道：12 条超长子域，都挂在同一个基域下
    for i in range(12):
        label = f"{i:02d}" + "a" * 48
        name = f"{label}.t.evil-dns.com"
        frames.append(
            ethernet_frame(
                ipv4_packet(TUNNEL, DNS_SERVER, 17, udp_segment(50000 + i, 53, dns_query(name)))
            )
        )

    out_dir = Path("samples/_local")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "suspicious.pcap"
    path.write_bytes(pcap_bytes(frames))
    print(f"已生成: {path}（{len(frames)} 帧）")


if __name__ == "__main__":
    main()