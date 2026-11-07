"""检测规则测试：规则函数是纯函数，给数字就出结论。"""

from pcappeek.detect import Finding, check_syn_scan


def test_flags_scan_with_low_completion():
    findings = check_syn_scan("10.0.0.5", syns=50, completed=2)
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.rule == "syn_scan"
    assert finding.severity == "high"
    assert finding.subject == "10.0.0.5"
    assert finding.count == 50


def test_ignores_normal_traffic():
    assert check_syn_scan("10.0.0.5", syns=5, completed=5) == []


def test_ignores_busy_but_healthy_host():
    assert check_syn_scan("10.0.0.6", syns=50, completed=45) == []


def test_reports_completion_rate_in_detail():
    findings = check_syn_scan("10.0.0.7", syns=40, completed=4)
    assert "10%" in findings[0].detail