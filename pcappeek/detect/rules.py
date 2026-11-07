"""检测规则：每个函数都是纯函数，输入数字或文本，输出 Finding 列表。"""
import base64
import binascii
from dataclasses import dataclass


SYN_SCAN_MIN_SYNS = 20
SYN_SCAN_MAX_RATIO = 0.3


@dataclass(frozen=True)
class Finding:
    """一条判定结果。"""

    rule: str
    """规则名，如 syn_scan。"""

    severity: str
    """严重程度：high / medium / low。"""

    subject: str
    """判定对象：源 IP、域名或会话。"""

    detail: str
    """给人看的一句话说明。"""

    count: int = 0
    """涉及的报文数，没有意义时留 0。"""


def check_syn_scan(
    src_ip,
    syns,
    completed,
    min_syns=SYN_SCAN_MIN_SYNS,
    max_ratio=SYN_SCAN_MAX_RATIO,
):
    """判断某个源 IP 是否在扫描：SYN 很多，但建连完成率很低。"""
    if syns < min_syns:
        return []

    ratio = completed / syns if syns else 1.0
    if ratio >= max_ratio:
        return []

    return [
        Finding(
            rule="syn_scan",
            severity="high",
            subject=src_ip,
            detail=f"{syns} 次 SYN，仅 {completed} 次完成（{ratio:.0%}）",
            count=syns,
        )
    ]


DNS_TUNNEL_MIN_SUBDOMAINS = 10
DNS_TUNNEL_MIN_LABEL_LEN = 40


def check_dns_tunnel(
    names,
    min_subdomains=DNS_TUNNEL_MIN_SUBDOMAINS,
    min_label_len=DNS_TUNNEL_MIN_LABEL_LEN,
):
    """按基域聚合，找出「超长子域数量异常多」的基域，疑似 DNS 隧道。"""
    groups = {}
    for name in names:
        labels = name.rstrip(".").split(".")
        if len(labels) < 4:
            continue
        base = ".".join(labels[-2:])
        prefix = ".".join(labels[:-2])
        if len(prefix) < min_label_len:
            continue
        groups.setdefault(base, set()).add(prefix)

    findings = []
    for base, prefixes in sorted(groups.items()):
        if len(prefixes) < min_subdomains:
            continue
        findings.append(
            Finding(
                rule="dns_tunnel",
                severity="medium",
                subject=base,
                detail=(
                    f"{len(prefixes)} 个超长子域（长度 >= {min_label_len}），疑似隧道"
                ),
                count=len(prefixes),
            )
        )
    return findings


HTTP_BASIC_MARK = b"authorization: basic "


def check_http_basic(payload, subject):
    """从一段 TCP 负载里找 HTTP Basic 凭据；密码只用来确认存在，不写进报告。"""
    position = payload.lower().find(HTTP_BASIC_MARK)
    if position < 0:
        return []

    start = position + len(HTTP_BASIC_MARK)
    end = payload.find(b"\r\n", start)
    if end < 0:
        end = len(payload)

    token = payload[start:end].strip()
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return []

    user = decoded.split(b":", 1)[0].decode("utf-8", "replace")
    return [
        Finding(
            rule="plaintext_credential",
            severity="high",
            subject=subject,
            detail=f"HTTP Basic 凭据：user={user}（密码已隐去）",
            count=1,
        )
    ]