import pytest


from pcappeek.frames import parse_ethernet,FrameError


def test_parse_ethernet_header():
    data = bytes.fromhex("aabbccddeeff1122334455660800") + b"\x45\x00"
    frame = parse_ethernet(data)
    assert frame.dst == "aa:bb:cc:dd:ee:ff"
    assert frame.src == "11:22:33:44:55:66"
    assert frame.ethertype == 0x0800
    assert frame.payload == b"\x45\x00"

def test_short_frame_raises():
    with pytest.raises(FrameError):
        parse_ethernet(b"\x00" * 13)


def test_empty_frame_raises():
    with pytest.raises(FrameError):
        parse_ethernet(b"")


def test_header_only_frame_has_empty_payload():
    frame = parse_ethernet(bytes(14))
    assert frame.payload == b""