"""检测规则测试：规则函数是纯函数，给数字就出结论。"""

from pcappeek.detect import Finding, check_dns_tunnel, check_http_basic, check_syn_scan, ScanTracker


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


def test_dns_tunnel_detected():
    names = {"x" * 45 + f".{i}.evil.example.com": 1 for i in range(12)}
    findings = check_dns_tunnel(names)
    assert len(findings) == 1
    assert findings[0].rule == "dns_tunnel"
    assert findings[0].severity == "medium"
    assert findings[0].subject == "example.com"
    assert findings[0].count == 12


def test_dns_tunnel_ignores_normal_names():
    names = {"www.baidu.com": 8, "ep0.baidu.com": 4, "example.com": 2}
    assert check_dns_tunnel(names) == []


def test_dns_tunnel_ignores_repeated_same_name():
    names = {"y" * 50 + ".evil.example.com": 30}
    assert check_dns_tunnel(names) == []


def test_dns_tunnel_ignores_short_subdomains():
    names = {f"cdn{i}.static.example.com": 1 for i in range(15)}
    assert check_dns_tunnel(names) == []


def test_dns_tunnel_needs_enough_subdomains():
    names = {"z" * 45 + f".{i}.evil.example.com": 1 for i in range(9)}
    assert check_dns_tunnel(names) == []


def test_http_basic_credentials_detected():
    payload = b"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
    findings = check_http_basic(payload, subject="10.0.0.5")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "plaintext_credential"
    assert finding.severity == "high"
    assert finding.subject == "10.0.0.5"
    assert "user" in finding.detail
    assert "pass" not in finding.detail


def test_http_without_auth_not_flagged():
    payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    assert check_http_basic(payload, subject="10.0.0.5") == []


def test_http_basic_bad_base64_not_flagged():
    payload = b"GET / HTTP/1.1\r\nAuthorization: Basic !!!notbase64!!!\r\n\r\n"
    assert check_http_basic(payload, subject="10.0.0.5") == []


def test_http_basic_header_is_case_insensitive():
    payload = b"GET / HTTP/1.1\r\naUtHoRiZaTiOn: bAsIc dXNlcjpwYXNz\r\n\r\n"
    findings = check_http_basic(payload, subject="10.0.0.5")
    assert len(findings) == 1


def test_tracker_flags_scanner():
    tracker = ScanTracker()
    for port in range(30, 60):
        tracker.feed("10.0.0.5", "10.0.0.9", port, 0x02)
    findings = tracker.findings()
    assert len(findings) == 1
    assert findings[0].subject == "10.0.0.5"
    assert findings[0].count == 30


def test_tracker_ignores_healthy_host():
    tracker = ScanTracker()
    for port in range(30, 60):
        tracker.feed("10.0.0.6", "10.0.0.9", port, 0x02)
        tracker.feed("10.0.0.6", "10.0.0.9", port, 0x10)
    assert tracker.findings() == []


def test_tracker_without_syn_is_silent():
    tracker = ScanTracker()
    tracker.feed("10.0.0.7", "10.0.0.9", 80, 0x10)
    assert tracker.findings() == []