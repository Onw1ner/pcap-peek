"""报告生成：把 collect_stats() 的结果渲染成一段文本（Markdown 风格）。"""

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _top_items(counter, top):
    """取次数最多的前 top 项，返回 [(名字, 次数), ...]。

    只用 .items()：Counter 和普通 dict 都能这样遍历。
    """
    return sorted(counter.items(), key=lambda item: item[1], reverse=True)[:top]


def _rows(counter, top):
    """渲染成表格行：["| TCP | 2 |", ...]。"""
    return [f"| {name} | {n} |" for name, n in _top_items(counter, top)]


def _section(title, lines):
    """一个小节：标题 + 内容行；内容为空时整节不出现。"""
    if not lines:
        return []
    return [f"## {title}", *lines, ""]


def build_report(stats, source="", top=5):
    """把统计结果渲染成报告文本。

    stats:  collect_stats() 的返回值
    source: 显示在开头的文件名
    top:    分布类小节最多列几行
    """
    out = ["# pcap-peek 报告", ""]
    if source:
        out += [f"源文件: {source}", ""]

    out += _section("概览", [
        f"| 帧总数 | {stats['total']} |",
        f"| 跳过（非 IPv4） | {stats['skipped']} |",
        f"| 解析失败 | {stats['failed']} |",
        f"| 会话数 | {len(stats['flows'])} |",
    ])
    findings = stats.get("findings", [])
    if findings:
        out += _section("发现", [
            "| 严重度 | 规则 | 对象 | 说明 |",
            *[
                f"| {f.severity} | {f.rule} | {f.subject} | {f.detail} |"
                for f in findings
            ],
        ])
    out += _section("以太网类型", [
        f"| 0x{eth_type:04X} | {n} |"
        for eth_type, n in _top_items(stats["eths"], top)
    ])

    out += _section("协议分布", _rows(stats["proto"], top))
    out += _section("源 IP 分布", _rows(stats["src"], top))
    out += _section("DNS 查询", _rows(stats["dns"], top))

    out += _section("TLS 握手", [
        f"| 拼出 | {stats['tls_seen']} |",
        f"| 解析出 | {stats['tls_ok']} |",
        f"| 无 SNI | {stats['tls_no_sni']} |",
        f"| 格式错误 | {stats['tls_bad']} |",
    ])

    out += _section("TLS SNI", _rows(stats["sni"], top))

    flows = []
    for flow in stats["flows"][:top]:
        key = flow.key
        name = PROTO_NAMES.get(key.protocol, str(key.protocol))
        flows.append(
            f"| {key.a_ip}:{key.a_port} <-> {key.b_ip}:{key.b_port} | {name} | "
            f"{flow.packets} | {flow.total_bytes} |"
        )
    out += _section("Top 会话", flows)

    return "\n".join(out).rstrip() + "\n"