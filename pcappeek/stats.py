"""离线统计：把一个 pcap/pcapng 文件读成一份统计字典。"""

from collections import Counter

from pcappeek.app.dns import DnsError, parse_dns_query
from pcappeek.app.tls import HandshakeAssembler, TlsError, parse_client_hello
from pcappeek.detect import ScanTracker, check_dns_tunnel, check_http_basic
from pcappeek.frames import FrameError
from pcappeek.link import link_payload
from pcappeek.netlayer import NetError, parse_ipv4
from pcappeek.pcap import PcapError, PcapReader
from pcappeek.pcapng import PcapngError, PcapngReader
from pcappeek.session import FlowTable, flow_key
from pcappeek.transport import TransportError, parse_tcp, parse_udp

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"




def open_reader(path: str):
    """按文件头 4 字节选读取器：pcapng 用 PcapngReader，其余交给 PcapReader。"""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError as exc:
        raise PcapError(f"无法打开 {path}: {exc}") from exc

    if len(head) < 4:
        raise PcapError(f"文件太短：只有 {len(head)} 字节，连标识都读不到")

    if head == PCAPNG_MAGIC:
        return PcapngReader(path)
    return PcapReader(path)


def collect_stats(path: str) -> dict:
    proto = Counter()
    src = Counter()
    table = FlowTable()
    total = 0
    failed = 0
    skipped = 0
    eths = Counter()
    dns_names = Counter()
    sni_names = Counter()
    tls_seen = 0
    assembler = HandshakeAssembler()
    tls_ok = 0
    tls_bad = 0
    tls_no_sni = 0
    scan = ScanTracker()
    http_hits = []

    for frame in open_reader(path):
        total += 1

        # 第一层：以太网 → IPv4
        try:
            ethertype, payload = link_payload(frame.data)
        except FrameError:
            failed += 1
            continue

        eths[ethertype] += 1

        if ethertype != 0x0800:
            skipped += 1
            continue

        try:
            ip = parse_ipv4(payload)
        except NetError:
            failed += 1
            continue

        proto[PROTO_NAMES.get(ip.protocol, str(ip.protocol))] += 1
        src[ip.src] += 1

        # 第二层：TCP / UDP（ICMP 没有端口，跳过）
        try:
            if ip.protocol == 6:
                seg = parse_tcp(ip.payload)
            elif ip.protocol == 17:
                seg = parse_udp(ip.payload)
            else:
                continue
        except TransportError:
            failed += 1
            continue
        if ip.protocol == 6:
            scan.feed(ip.src, ip.dst, seg.dst_port, seg.flags)
            if seg.dst_port == 80:
                http_hits.extend(
                    check_http_basic(
                        seg.payload,
                        subject=f"{ip.src}:{seg.src_port} -> {ip.dst}:80",
                    )
                )   
        key = flow_key(ip.src, ip.dst, seg.src_port, seg.dst_port, ip.protocol)
        table.add(key, nbytes=len(ip.payload))
        if ip.protocol == 17 and seg.dst_port == 53:
            try:
                dns_names[parse_dns_query(seg.payload).name] += 1
            except DnsError:
                pass
        if ip.protocol == 6 and seg.dst_port == 443:
            record = assembler.feed(key, seg.seq, seg.payload)
            if record is not None:
                tls_seen += 1
                try:
                    name = parse_client_hello(record).server_name
                except TlsError:
                    tls_bad += 1
                else:
                    if name:
                        tls_ok += 1
                        sni_names[name] += 1
                    else:
                        tls_no_sni += 1
        
    findings = scan.findings() + check_dns_tunnel(dns_names) + http_hits

    return {
        "total": total,
        "skipped": skipped,
        "failed": failed,
        "proto": proto,
        "src": src,
        "flows": table.flows(),
        "eths": eths,
        "dns": dns_names,
        "sni": sni_names,
        "tls_seen": tls_seen,
        "tls_ok": tls_ok,
        "tls_bad": tls_bad,
        "tls_no_sni": tls_no_sni,
        "findings": findings,
    }