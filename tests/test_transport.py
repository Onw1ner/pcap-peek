from pcappeek.transport import parse_udp,parse_tcp


def test_parse_udp_header():
    data = bytes.fromhex("0035" "c350" "000c" "0000") + b"abcd"

    seg = parse_udp(data)

    assert seg.src_port == 53
    assert seg.dst_port == 50000
    assert seg.payload == b"abcd"

def test_parse_tcp_header():
    data = bytes.fromhex(
        "c350" "0035" "00000001" "00000000" "5002" "2000" "0000" "0000"
    ) + b"hi"

    seg = parse_tcp(data)

    assert seg.src_port == 50000
    assert seg.dst_port == 53
    assert seg.flags == 0x02
    assert seg.payload == b"hi"


def test_tcp_options_shift_payload():
    data = bytes.fromhex(
        "c350" "0035" "00000001" "00000000" "6002" "2000" "0000" "0000"
        "020405b4"
    ) + b"hi"

    seg = parse_tcp(data)

    assert seg.payload == b"hi"