import struct

from pcappeek.pcap import PcapReader

def build_pcap(payload: bytes) -> bytes:
    # 全局头 24 字节：magic 版本 时区 精度 快照长度 链路类型
    header = struct.pack("<IHHiIII",0xA1B2C3D4,2,4,0,0,65535,1)
    # 记录头 16 字节：秒 微秒 实际长度 原始长度
    record = struct.pack("<IIII",1,0,len(payload),len(payload)) + payload
    return header + record

def test_reads_oneframe(tmp_path):
    f = tmp_path / "one.pcap"
    f.write_bytes(build_pcap(b"\xde\xad\xbe\xef"))
    frames = list(PcapReader(f))
    assert len(frames) == 1