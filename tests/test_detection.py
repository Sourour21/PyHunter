from pathlib import Path

from app.detection.engine import detect_threats
from app.detection.rules_loader import load_rules
from app.ingestion.pcap_reader import read_pcap
from app.ingestion.authlog_reader import read_authlog
from app.normalization.normalizer import normalize_events


ROOT = Path(__file__).resolve().parents[1]


def get_alerts():
    pcap_events = normalize_events(
        read_pcap(str(ROOT / "samples" / "pcaps" / "lab_traffic.pcap")),
        "PCAP",
    )
    auth_events = normalize_events(
        read_authlog(str(ROOT / "samples" / "logs" / "auth.log")),
        "AUTHLOG",
    )
    return detect_threats(pcap_events + auth_events, load_rules())


def test_detects_port_scan():
    alerts = get_alerts()
    port_scans = [a for a in alerts if a["alert_type"] == "PORT_SCAN"]

    assert len(port_scans) == 1
    assert port_scans[0]["source_ip"] == "192.0.2.10"
    assert len(port_scans[0]["ports_targeted"]) == 11


def test_detects_ssh_brute_force():
    alerts = get_alerts()
    brute_force = [a for a in alerts if a["alert_type"] == "SSH_BRUTE_FORCE"]

    assert len(brute_force) == 1
    assert brute_force[0]["source_ip"] == "192.0.2.10"
    assert brute_force[0]["event_count"] == 10


def test_detects_suspicious_dns():
    alerts = get_alerts()
    dns_alerts = [a for a in alerts if a["alert_type"] == "SUSPICIOUS_DNS"]

    assert len(dns_alerts) == 2
    domains = {a["domain"] for a in dns_alerts}
    assert "a8K2mP9xQ4vL.example.test" in domains
    assert "z7Xq9Wb3Nf5R.example.test" in domains


def test_total_alerts():
    alerts = get_alerts()
    assert len(alerts) == 4
