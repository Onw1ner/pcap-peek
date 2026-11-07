"""会话表：把 5 元组聚成一条连接。"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowKey:
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    protocol: int


def flow_key(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int
) -> FlowKey:
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if b < a:
        a, b = b, a
    return FlowKey(a[0], a[1], b[0], b[1], protocol)


@dataclass
class Flow:
    key: FlowKey
    packets: int = 0
    total_bytes: int = 0


class FlowTable:
    def __init__(self) -> None:
        self._flows: dict[FlowKey, Flow] = {}

    def add(self, key: FlowKey, nbytes: int = 0) -> Flow:
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(key=key)
            self._flows[key] = flow
        flow.packets += 1
        flow.total_bytes += nbytes
        return flow

    def flows(self) -> list[Flow]:
        return sorted(self._flows.values(), key=lambda f: f.total_bytes, reverse=True)

    def __len__(self) -> int:
        return len(self._flows)