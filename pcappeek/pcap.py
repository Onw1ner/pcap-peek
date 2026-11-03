"""pcap文件读取:把pcap逐条解析成Frame"""

import struct
from dataclasses import dataclass

GLOBAL_HEADER = struct.Struct("<IHHiIII") #全局头24字节
RECORD_HEADER = struct.Struct("IIII") #记录头16字节

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
        with open(self.path, "rb") as f:
            raw = f.read(GLOBAL_HEADER.size)
            _, _, _, _, _, snaplen, linktype = GLOBAL_HEADER.unpack(raw)
            self.snaplen = snaplen
            self.linktype = linktype

            index = 0
            while True:
                raw = f.read(RECORD_HEADER.size)
                if not raw:
                    return
                ts_sec, ts_usec, incl_len, orig_len = RECORD_HEADER.unpack(raw)
                data = f.read(incl_len)
                yield Frame(
                    index=index,
                    ts=ts_sec + ts_usec / 1_000_000,
                    data=data,
                    orig_len=orig_len,
                )
                index += 1