import struct

from pcappeek.pcapng import PcapngReader


def block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def make_pcapng(frames: list[bytes], linktype: int = 1) -> bytes:
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", linktype, 0, 65535))

    for i, data in enumerate(frames):
        ts = (100 + i) * 1_000_000 + 500_000
        body = struct.pack(
            "<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)
        )
        body += data + b"\x00" * ((4 - len(data) % 4) % 4)
        out += block(0x00000006, body)

    return out


def test_reads_one_epb(tmp_path):
    payload = b"\xde\xad\xbe\xef"
    f = tmp_path / "one.pcapng"
    f.write_bytes(make_pcapng([payload]))

    frames = list(PcapngReader(f))

    assert len(frames) == 1
    assert frames[0].data == payload
    assert frames[0].ts == 100.5