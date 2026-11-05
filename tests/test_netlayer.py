import pytest


from pcappeek.netlayer import parse_ipv4,NetError


def test_parse_ipv4_header():
    data = bytes.fromhex(
        "4500" "0016" "1c46" "4000" "4006" "0000" "c0a80101" "08080808"
    ) + b"\xde\xad"
    pkt = parse_ipv4(data)
    assert pkt.src == "192.168.1.1"
    assert pkt.dst == "8.8.8.8"
    assert pkt.protocol == 6
    assert pkt.payload == b"\xde\xad"


def test_short_ipv4_raises():
    with pytest.raises(NetError):
        parse_ipv4(bytes(19))


def test_wrong_version_raises():
    data = bytes.fromhex("6500" "0016" "1c46" "4000" "4006" "0000" "c0a80101" "08080808")
    with pytest.raises(NetError):
        parse_ipv4(data)


def test_bad_ihl_raises():
    data = bytes.fromhex("4400" "0016" "1c46" "4000" "4006" "0000" "c0a80101" "08080808")
    with pytest.raises(NetError):
        parse_ipv4(data)


def test_ipv4_options_shift_payload():
    data = bytes.fromhex(
        "4600" "0019" "1c46" "4000" "4006" "0000" "c0a80101" "08080808" "01010101"
    ) + b"\xaa"
    pkt = parse_ipv4(data)
    assert pkt.payload == b"\xaa"