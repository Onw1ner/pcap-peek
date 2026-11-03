"""pcap文件读取:把pcap逐条解析成Frame"""

import struct
from dataclasses import dataclass

MAX_INCL_LEN = 0x40000   # 262144：pcap 规范里 snapLen 的上限

class PcapError(Exception):
    """pcap解析失败时抛出。"""

@dataclass(frozen=True)
class Frame:
    index: int
    ts: float
    data: bytes
    orig_len: int

class PcapReader:
    def __init__(self, path):
        self.path = path
        self.linktype = None
        self.snaplen = None

    def __iter__(self):
        try:
            f = open(self.path, "rb")
        except OSError as exc:
            raise PcapError(f"无法打开 {self.path}: {exc}") from exc
        with f:
            raw = f.read(24)
            if len(raw) < 24:
                raise PcapError(f"文件太短：只有 {len(raw)} 字节，不足以构成全局头")
            magic_bytes = raw[:4]
            if magic_bytes in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                order = "<"
            elif magic_bytes in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                order = ">"
            else:
                raise PcapError(f"不是 pcap 文件:magic={magic_bytes.hex()}")

            gh = struct.Struct(order + "IHHiIII")
            rh = struct.Struct(order + "IIII")
            _, _, _, _, _, snaplen, linktype = gh.unpack(raw)
            self.snaplen = snaplen
            self.linktype = linktype

            index = 0
            while True:
                raw = f.read(rh.size)
                if not raw:
                    return
                if len(raw) != rh.size:
                    raise PcapError(f"第 {index} 条记录头被截断：只剩 {len(raw)} 字节")
                ts_sec, ts_usec, incl_len, orig_len = rh.unpack(raw)
                if incl_len > MAX_INCL_LEN:
                    raise PcapError(f"第 {index} 条记录长度异常：{incl_len} 字节，超过上限 {MAX_INCL_LEN}")
                data = f.read(incl_len)
                if len(data) != incl_len:
                    raise PcapError(f"第 {index} 条数据被截断：期望 {incl_len} 字节，实读 {len(data)} 字节")
                yield Frame(
                    index=index,
                    ts=ts_sec + ts_usec / 1_000_000,
                    data=data,
                    orig_len=orig_len,
                )
                index += 1