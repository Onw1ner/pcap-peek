from pcappeek.__main__ import main

from demo_e2e import ethernet_frame, ipv4_packet, pcap_bytes,tcp_segment
from tests.test_pcapng import make_pcapng


def test_stats_prints_protocols(tmp_path, capsys):
    frame = ethernet_frame(
        ipv4_packet("10.0.0.1", "10.0.0.2", 6, tcp_segment(50000, 80, b"x"))
    )
    f = tmp_path / "one.pcap"
    f.write_bytes(pcap_bytes([frame]))

    code = main(["stats", str(f)])
    out = capsys.readouterr().out

    assert code == 0
    assert "帧总数: 1" in out
    assert "TCP" in out
    assert "会话数: 1" in out
    assert "10.0.0.1:50000" in out


def test_no_args_shows_usage(capsys):
    code = main([])
    err = capsys.readouterr().err

    assert code == 2
    assert "用法" in err
    assert "【pcap 文件】" in err


def test_missing_file_exit_code(capsys):
    code = main(["stats", "不存在.pcap"])
    err = capsys.readouterr().err

    assert code == 1
    assert "读取失败" in err


def test_stats_reads_pcapng(tmp_path, capsys):
    frame = ethernet_frame(
        ipv4_packet("10.0.0.9", "10.0.0.10", 6, tcp_segment(40000, 80, b"y"))
    )
    f = tmp_path / "one.pcapng"
    f.write_bytes(make_pcapng([frame]))

    code = main(["stats", str(f)])
    out = capsys.readouterr().out

    assert code == 0
    assert "10.0.0.9:40000" in out


def test_stats_counts_non_ipv4(tmp_path, capsys):
    arp = bytes.fromhex("aabbccddeeff" "112233445566" "0806") + bytes(28)
    f = tmp_path / "arp.pcap"
    f.write_bytes(pcap_bytes([arp]))

    code = main(["stats", str(f)])
    out = capsys.readouterr().out

    assert code == 0
    assert "帧总数: 1" in out
    assert "跳过（非 IPv4）: 1" in out
    assert "解析失败: 0" in out
    assert "ethertype 分布（已归一化）:" in out
    assert "0x0806" in out


def test_report_writes_file(tmp_path, capsys):
    frame = ethernet_frame(
        ipv4_packet("10.0.0.1", "10.0.0.2", 6, tcp_segment(50000, 443, b"\x16\x03\x01"))
    )
    src = tmp_path / "one.pcap"
    src.write_bytes(pcap_bytes([frame]))
    out_path = tmp_path / "report.md"

    code = main(["report", str(src), "-o", str(out_path)])
    out = capsys.readouterr().out

    assert code == 0
    assert out_path.exists()
    text = out_path.read_text(encoding="utf-8")
    assert "# pcap-peek 报告" in text
    assert "| 帧总数 | 1 |" in text
    assert "报告已写入" in out


def test_report_prints_to_stdout(tmp_path, capsys):
    frame = ethernet_frame(
        ipv4_packet("10.0.0.1", "10.0.0.2", 6, tcp_segment(50000, 80, b"x"))
    )
    src = tmp_path / "one.pcap"
    src.write_bytes(pcap_bytes([frame]))

    code = main(["report", str(src)])
    out = capsys.readouterr().out

    assert code == 0
    assert "# pcap-peek 报告" in out
    assert "| 帧总数 | 1 |" in out


def test_report_bad_option_shows_usage(capsys):
    code = main(["report", "x.pcap", "-x"])
    err = capsys.readouterr().err

    assert code == 2
    assert "用法" in err