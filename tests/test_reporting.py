import json

from app.reporting.json_report import generate_json_report
from app.reporting.html_report import generate_html_report


SAMPLE_ALERTS = [
    {
        "alert_type": "PORT_SCAN",
        "source_ip": "192.0.2.10",
        "severity": "HIGH",
    },
    {
        "alert_type": "SSH_BRUTE_FORCE",
        "source_ip": "192.0.2.10",
        "severity": "HIGH",
    },
]


def test_generate_json_report(tmp_path):
    output = tmp_path / "reports" / "report.json"

    result = generate_json_report(SAMPLE_ALERTS, str(output))

    assert output.exists()
    assert result == str(output)

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["tool"] == "PyHunter"
    assert data["total_alerts"] == 2
    assert len(data["alerts"]) == 2


def test_generate_html_report(tmp_path):
    output = tmp_path / "reports" / "report.html"

    result = generate_html_report(SAMPLE_ALERTS, str(output))

    assert output.exists()
    assert result == str(output)

    content = output.read_text(encoding="utf-8")

    assert "PyHunter - Security Analysis Report" in content
    assert "PORT_SCAN" in content
    assert "SSH_BRUTE_FORCE" in content
    assert "192.0.2.10" in content


def test_empty_html_report(tmp_path):
    output = tmp_path / "empty.html"

    generate_html_report([], str(output))

    content = output.read_text(encoding="utf-8")

    assert "No alerts detected" in content
    assert "Total alerts:</strong> 0" in content


def test_empty_json_report(tmp_path):
    output = tmp_path / "empty.json"

    generate_json_report([], str(output))

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["total_alerts"] == 0
    assert data["alerts"] == []
