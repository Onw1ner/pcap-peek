"""DNS 查询解析。只解析问题段（QNAME/QTYPE），不解析资源记录。

设计取舍：
- 只处理 QDCOUNT=1 的查询报文。应答、多问题报文一律报错——
  宁可说"不认识"，也不要解出一堆看着像域名的垃圾。
- 不支持名字压缩指针（0xC0）。查询报文里的 QNAME 不会压缩，
  遇到指针说明这是别的东西（或畸形样本），直接报错。
"""

from dataclasses import dataclass

DNS_HEADER_LEN = 12
DNS_FLAG_QR = 0x8000
MAX_LABEL_LEN = 63
MAX_NAME_LEN = 253

DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}


class DnsError(Exception):
    """DNS 报文不合法。"""


@dataclass(frozen=True)
class DnsQuery:
    name: str
    qtype: int
    ident: int = 0

    @property
    def qtype_name(self) -> str:
        return DNS_TYPE_NAMES.get(self.qtype, str(self.qtype))


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """从 offset 处读 QNAME，返回 (域名, 读完后的新偏移)。"""
    labels: list[str] = []
    total = 0

    while True:
        if offset >= len(data):
            raise DnsError(f"域名越界：读到第 {offset} 字节时报文已结束")

        length = data[offset]

        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            raise DnsError(f"不支持压缩指针（偏移 {offset}，值 0x{length:02X}）")
        if length > MAX_LABEL_LEN:
            raise DnsError(f"标签长度 {length} 超过上限 {MAX_LABEL_LEN}")

        start = offset + 1
        label = data[start:start + length]
        if len(label) < length:
            raise DnsError(f"标签被截断：声明 {length} 字节，实际只有 {len(label)} 字节")

        total += length + 1
        if total > MAX_NAME_LEN:
            raise DnsError(f"域名超过 {MAX_NAME_LEN} 字节")

        labels.append(label.decode("ascii", errors="replace"))
        offset = start + length

    return ".".join(labels), offset


def parse_dns_query(data: bytes) -> DnsQuery:
    """解析一个 DNS 查询报文。"""
    if len(data) < DNS_HEADER_LEN:
        raise DnsError(f"DNS 报文太短：只有 {len(data)} 字节，头部需要 {DNS_HEADER_LEN}")

    ident = int.from_bytes(data[0:2], "big")
    flags = int.from_bytes(data[2:4], "big")

    if flags & DNS_FLAG_QR:
        raise DnsError("这是应答报文（QR=1），不是查询")

    qdcount = int.from_bytes(data[4:6], "big")
    if qdcount != 1:
        raise DnsError(f"问题数应为 1，实际是 {qdcount}")

    name, offset = _read_name(data, DNS_HEADER_LEN)

    if offset + 4 > len(data):
        raise DnsError(f"问题段被截断：读完域名在第 {offset} 字节，取不到 QTYPE/QCLASS")

    qtype = int.from_bytes(data[offset:offset + 2], "big")
    return DnsQuery(name=name, qtype=qtype, ident=ident)