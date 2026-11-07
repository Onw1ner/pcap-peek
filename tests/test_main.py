from pcappeek.__main__ import main

from demo_e2e import ethernet_frame, ipv4_packet, pcap_bytes,tcp_segment


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