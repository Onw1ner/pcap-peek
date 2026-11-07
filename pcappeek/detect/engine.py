"""检测引擎：从报文流里攒证据，最后交给规则判定。"""

from pcappeek.detect.rules import Finding, check_syn_scan


TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10


class ScanTracker:
    """记录每个源 IP 的 SYN 目标，以及之后仍有报文的目标，最后算完成率。"""

    def __init__(self):
        self._syn = {}
        self._live = {}

    def feed(self, src_ip, dst_ip, dst_port, flags):
        """喂一个 TCP 段：只有 SYN、不带 ACK 的算发起。"""
        target = (dst_ip, dst_port)
        is_syn = bool(flags & TCP_FLAG_SYN) and not (flags & TCP_FLAG_ACK)
        if is_syn:
            self._syn.setdefault(src_ip, set()).add(target)
        else:
            self._live.setdefault(src_ip, set()).add(target)

    def findings(self):
        """对每个有 SYN 的源 IP 跑一遍规则。"""
        results = []
        for src_ip in sorted(self._syn):
            targets = self._syn[src_ip]
            completed = len(targets & self._live.get(src_ip, set()))
            results.extend(
                check_syn_scan(src_ip, syns=len(targets), completed=completed)
            )
        return results