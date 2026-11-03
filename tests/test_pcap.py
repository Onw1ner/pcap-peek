import struct 
import pytest
from pcappeek.pcap import PcapError,PcapReader

from pcappeek.pcap import PcapReader

#构造pcap文件
def build_pcap(payload: bytes) -> bytes:
    # 全局头 24 字节：magic 版本 时区 精度 快照长度 链路类型
    header = struct.pack("<IHHiIII",0xA1B2C3D4,2,4,0,0,65535,1)
    # 记录头 16 字节：秒 微秒 实际长度 原始长度
    record = struct.pack("<IIII",1,0,len(payload),len(payload)) + payload
    return header + record

#测试读出一条记录
def test_reads_oneframe(tmp_path):
    f = tmp_path / "one.pcap"
    f.write_bytes(build_pcap(b"\xde\xad\xbe\xef"))
    frames = list(PcapReader(f))
    assert len(frames) == 1

#测试空文件头
def test_empty_file_has_no_frames(tmp_path):
    f = tmp_path / "header-only.pcap"
    f.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    frames = list(PcapReader(f))
    assert frames == []

#测试不存在文件
def test_missing_file_raises_pcap_error(tmp_path):
    with pytest.raises(PcapError):
        list(PcapReader(tmp_path / "不存在.pcap"))

#测试magic不对
def test_bad_magic_raises_pcap_error(tmp_path):
    f = tmp_path / "bad.pcap"
    f.write_bytes(b"\x00" * 24)
    with pytest.raises(PcapError):
        list(PcapReader(f))

#构造大端文件
def build_pcap_be(payload: bytes) -> bytes:
    header = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(">IIII", 1, 0, len(payload), len(payload)) + payload
    return header + record

#测试大端文件被读成小端
def test_big_endian_file(tmp_path):
    f = tmp_path / "be.pcap"
    f.write_bytes(build_pcap_be(b"\x01\x02"))
    frames = list(PcapReader(f))
    assert len(frames) == 1
    assert frames[0].data == b"\x01\x02"

#测试文件头截断
def test_truncated_record_header_raises(tmp_path):
    f = tmp_path / "trunc.pcap"
    f.write_bytes(build_pcap(b"\x01\x02") + b"\x01\x02\x03\x04\x05\x06\x07\x08")
    with pytest.raises(PcapError):
        list(PcapReader(f))

#测试数据截断
def test_truncated_record_data_raises(tmp_path):
    f = tmp_path / "trunc2.pcap"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, 100, 100) + b"\x01\x02\x03"
    f.write_bytes(header + record)
    with pytest.raises(PcapError):
        list(PcapReader(f))
    
#测试长度爆炸
def test_absurd_incl_len_rejected(tmp_path):
    f = tmp_path / "huge.pcap"
    incl = 0x40001
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, incl, incl) + b"\x00" * incl
    f.write_bytes(header + record)
    with pytest.raises(PcapError):
        list(PcapReader(f))

#短文件
def test_truncated_global_header_raises(tmp_path):
    f = tmp_path / "short.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")
    with pytest.raises(PcapError):
        list(PcapReader(f))