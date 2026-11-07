"""pcapng 读取：把 EPB 逐条解析成 Frame。"""

import struct

from pcappeek.pcap import Frame

SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006


class PcapngError(Exception):
    """pcapng 解析失败时抛出。"""


class PcapngReader:
    def __init__(self, path):
        self.path = path
        self.linktype = None
        self.snaplen = None

    def __iter__(self):
        with open(self.path, "rb") as f:
            order = "<"
            index = 0

            while True:
                head = f.read(8)
                if not head:
                    return
                if len(head) != 8:
                    raise PcapngError(f"块头被截断：只剩 {len(head)} 字节")

                # 段头块：先读字节序标记，再决定怎么解长度
                if head[:4] == b"\x0a\x0d\x0d\x0a":
                    magic = f.read(4)
                    if magic == b"\x1a\x2b\x3c\x4d":
                        order = ">"
                    elif magic == b"\x4d\x3c\x2b\x1a":
                        order = "<"
                    else:
                        raise PcapngError(f"字节序标记不认识：{magic.hex()}")

                    total = struct.unpack(order + "I", head[4:8])[0]
                    if total < 16:
                        raise PcapngError(f"段头长度异常：{total}")

                    rest = f.read(total - 12)
                    if len(rest) != total - 12:
                        raise PcapngError(f"段头被截断：缺 {total - 12 - len(rest)} 字节")

                    self.linktype = None
                    self.snaplen = None
                    continue

                btype = struct.unpack(order + "I", head[:4])[0]
                total = struct.unpack(order + "I", head[4:8])[0]
                if total < 12:
                    raise PcapngError(f"块长度异常：type={btype:#010x} total={total}")

                body = f.read(total - 8)
                if len(body) != total - 8:
                    raise PcapngError(f"块被截断：类型 {btype:#010x}")

                if btype == IDB_TYPE:
                    if len(body) < 8:
                        raise PcapngError("接口描述块太短")
                    linktype, _, snaplen = struct.unpack(order + "HHI", body[:8])
                    if self.linktype is None:
                        self.linktype = linktype
                        self.snaplen = snaplen
                    continue

                if btype == EPB_TYPE:
                    if len(body) < 20:
                        raise PcapngError(f"第 {index} 个包块太短：{len(body)} 字节")

                    _, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                        order + "IIIII", body[:20]
                    )
                    data = body[20:20 + cap_len]
                    if len(data) != cap_len:
                        raise PcapngError(
                            f"第 {index} 个包被截断：声明 {cap_len} 字节，实际 {len(data)} 字节"
                        )

                    yield Frame(
                        index=index,
                        ts=((ts_high << 32) | ts_low) / 1_000_000,
                        data=data,
                        orig_len=orig_len,
                    )
                    index += 1
                    continue

                # 其余块（SPB、名称解析、自定义）本轮跳过