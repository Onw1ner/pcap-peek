"""报告生成测试：build_report 是纯函数，给定统计结果就返回一段文本。"""

from pcappeek.report import build_report


def fake_stats():
    return {
        "total": 3,
        "skipped": 0,
        "failed": 0,
        "proto": {"TCP": 2, "UDP": 1},
        "src": {"10.0.0.1": 2, "10.0.0.2": 1},
        "flows": [],
        "eths": {0x0800: 3},
        "dns": {"www.baidu.com": 1},
        "sni": {"example.com": 1},
        "tls_seen": 1,
        "tls_ok": 1,
        "tls_bad": 0,
        "tls_no_sni": 0,
    }


def test_report_has_overview():
    text = build_report(fake_stats(), source="demo.pcap")
    assert "| 帧总数 | 3 |" in text
    assert "| 解析失败 | 0 |" in text
    assert "demo.pcap" in text


def test_report_lists_protocols_and_names():
    text = build_report(fake_stats())
    assert "## 协议分布" in text
    assert "| TCP | 2 |" in text
    assert "www.baidu.com" in text
    assert "example.com" in text


def test_report_respects_top_limit():
    stats = fake_stats()
    stats["src"] = {f"10.0.0.{i}": 10 - i for i in range(1, 9)}
    text = build_report(stats, top=3)
    assert "10.0.0.1" in text
    assert "10.0.0.6" not in text