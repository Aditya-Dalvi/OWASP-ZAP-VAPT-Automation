from src.notifications import build_alert_stats, build_csv_bytes, safe_hostname


def test_build_alert_stats_counts_instances_and_unique_plugins():
    alerts = [
        {"pluginId": "100", "riskcode": "3", "name": "SQL Injection"},
        {"pluginId": "100", "riskcode": "3", "name": "SQL Injection"},
        {"pluginId": "200", "riskcode": "1", "name": "Cookie Missing Secure"},
    ]
    stats = build_alert_stats(alerts)
    assert stats["total_instances"] == 3
    assert stats["total_vulns"] == 2
    assert stats["vuln_by_risk"]["3"] == 1
    assert stats["vuln_by_risk"]["1"] == 1
    assert stats["instance_by_risk"]["3"] == 2


def test_build_csv_returns_header_and_rows():
    content = build_csv_bytes([{"pluginId": "100", "name": "Example"}])
    assert b"pluginId" in content
    assert b"Example" in content


def test_safe_hostname_removes_unsafe_characters():
    assert safe_hostname("https://www.example.com/path") == "example.com"
