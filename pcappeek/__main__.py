"""命令行入口：python -m pcappeek stats """

import sys
from collections import Counter

from pcappeek.frames import FrameError, parse_ethernet
from pcappeek.netlayer import NetError, parse_ipv4
from pcappeek.pcap import PcapError, PcapReader

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def collect_stats(path: str) -> dict:
    proto = Counter()
    src = Counter()
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
        proto[PROTO_NAMES.get(ip.protocol, str(ip.protocol))] += 1
        src[ip.src] += 1

    return {"total": total, "failed": failed, "proto": proto, "src": src}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if len(argv) != 2 or argv[0] != "stats":
        print("用法: python -m pcappeek stats 【pcap 文件】", file=sys.stderr)
        return 2

    try:
        s = collect_stats(argv[1])
    except PcapError as exc:
        print(f"读取失败: {exc}", file=sys.stderr)
        return 1

    print(f"帧总数: {s['total']}")
    print(f"解析失败: {s['failed']}")
    print("协议分布:")
    for name, n in s["proto"].most_common():
        print(f"  {name:<5}{n}")
    print("源 IP 分布:")
    for addr, n in s["src"].most_common():
        print(f"  {addr:<13}{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())