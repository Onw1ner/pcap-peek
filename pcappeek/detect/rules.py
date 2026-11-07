"""检测规则：每个函数都是纯函数，输入数字或文本，输出 Finding 列表。"""

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