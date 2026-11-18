"""命令行入口：python -m pcappeek stats """

import sys


from pcappeek.pcap import PcapError
from pcappeek.pcapng import PcapngError
from pcappeek.report import build_report
from pcappeek.stats import PROTO_NAMES,collect_stats



USAGE = (
    "用法: python -m pcappeek stats 【pcap 文件】\n"
    "      python -m pcappeek report 【pcap 文件】 [-o 输出文件]"
)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if len(argv) < 2 or argv[0] not in ("stats", "report"):
        print(USAGE, file=sys.stderr)
        return 2

    command, path, rest = argv[0], argv[1], argv[2:]

    output = ""
    if rest:
        if len(rest) != 2 or rest[0] != "-o":
            print(USAGE, file=sys.stderr)
            return 2
        output = rest[1]

    try:
        s = collect_stats(path)
    except (PcapError, PcapngError) as exc:
        print(f"读取失败: {exc}", file=sys.stderr)
        return 1

    if command == "report":
        text = build_report(s, source=path)
        if output:
            try:
                with open(output, "w", encoding="utf-8", newline="\n") as f:
                    f.write(text)
            except OSError as exc:
                print(f"写入失败: {exc}", file=sys.stderr)
                return 1
            print(f"报告已写入 {output}")
        else:
            print(text, end="")
        return 0

    print(f"帧总数: {s['total']}")
    print(f"跳过（非 IPv4）: {s['skipped']}")
    print(f"解析失败: {s['failed']}")
    print("ethertype 分布（已归一化）:")
    for eth_type, n in s["eths"].most_common(6):
        print(f"  0x{eth_type:04X}  {n}")
    print("协议分布:")
    for name, n in s["proto"].most_common():
        print(f"  {name:<5}{n}")
    print("源 IP 分布:")
    for addr, n in s["src"].most_common():
        print(f"  {addr:<16}{n}")
    if s["dns"]:
        print("DNS 查询 Top:")
        for name, n in s["dns"].most_common(8):
            print(f"  {name}  {n}")
    print(
        f"TLS 握手：拼出 {s['tls_seen']} 条，解析出 {s['tls_ok']} 条，"
        f"无 SNI {s['tls_no_sni']} 条，格式错误 {s['tls_bad']} 条"
    )
    if s["sni"]:
                print("TLS SNI Top:")
                for name, n in s["sni"].most_common(8):
                    print(f"  {name}  {n}")
    print(f"发现: {len(s['findings'])} 条")
    for finding in s["findings"]:
        print(f"  [{finding.severity}] {finding.rule} {finding.subject}")
        print(f"      {finding.detail}")                    
    print(f"会话数: {len(s['flows'])}")
    print("Top 会话:")
    for flow in s["flows"][:5]:
        k = flow.key
        name = PROTO_NAMES.get(k.protocol, str(k.protocol))
        print(
            f"  {k.a_ip}:{k.a_port} <-> {k.b_ip}:{k.b_port}  "
            f"{name}  {flow.packets} 包  {flow.total_bytes} 字节"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())