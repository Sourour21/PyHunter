from datetime import datetime, timedelta, timezone
from math import log2

import pytest

from app.detection.engine import (
    calculate_entropy,
    detect_threats,
    detect_windows_bruteforce,
    parse_timestamp,
)
from app.detection.rules_loader import check_dns_rule, load_rules
from app.enrichment import virustotal
from app.enrichment.cache import IOC_Cache
from app.enrichment.virustotal import VirusTotalEnricher, get_vt_endpoint
from app.ingestion import evtx_reader
from app.ingestion.authlog_reader import read_authlog
from app.normalization.normalizer import normalize_events


WINDOWS_RULE = {
    "enabled": True,
    "threshold": 5,
    "window_seconds": 60,
    "severity": "HIGH",
    "description": "test",
    "mitre_attack": "T1110",
}


def windows_failures(count, ip="192.0.2.50", step_seconds=5):
    start = datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)
    return normalize_events(
        [
            {
                "timestamp": (start + timedelta(seconds=i * step_seconds)).isoformat(),
                "event_id": 4625,
                "source_ip": ip,
                "username": "admin",
                "status": "FAILED",
                "event_type": "WINDOWS_LOGIN",
            }
            for i in range(count)
        ],
        "EVTX",
    )


# --- 1. EVTX events now produce brute-force alerts -------------------------

def test_windows_bruteforce_detected():
    alerts = detect_windows_bruteforce(windows_failures(6), WINDOWS_RULE)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "WINDOWS_BRUTE_FORCE"
    assert alerts[0]["source_ip"] == "192.0.2.50"
    assert alerts[0]["event_count"] == 6


def test_windows_bruteforce_below_threshold():
    assert detect_windows_bruteforce(windows_failures(4), WINDOWS_RULE) == []


def test_windows_bruteforce_outside_window():
    # 6 failures, 20 s apart -> never 5 within 60 s
    events = windows_failures(6, step_seconds=20)
    assert detect_windows_bruteforce(events, WINDOWS_RULE) == []


def test_windows_bruteforce_runs_in_detect_threats():
    alerts = detect_threats(windows_failures(6), load_rules())
    assert [a["alert_type"] for a in alerts] == ["WINDOWS_BRUTE_FORCE"]


def test_windows_events_do_not_trigger_ssh_rule():
    alerts = detect_threats(windows_failures(6), load_rules())
    assert not any(a["alert_type"] == "SSH_BRUTE_FORCE" for a in alerts)


def test_rules_without_windows_rule_still_work():
    rules = load_rules()
    rules.pop("windows_bruteforce")
    assert detect_threats(windows_failures(6), rules) == []


def test_evtx_dash_ip_is_ignored(monkeypatch, tmp_path):
    fake_file = tmp_path / "Security.evtx"
    fake_file.write_bytes(b"fake")

    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>4625</EventID>
    <TimeCreated SystemTime="2026-11-13T10:00:00.000Z"/></System>
    <EventData><Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">-</Data></EventData></Event>"""

    class FakeRecord:
        def xml(self):
            return xml

    class FakeEvtx:
        def __init__(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def records(self):
            return [FakeRecord()]

    monkeypatch.setattr(evtx_reader, "Evtx", FakeEvtx)

    events = evtx_reader.read_evtx(fake_file)
    assert events[0]["source_ip"] is None


# --- 2. DNS entropy rule is consistent -------------------------------------

def test_max_entropy_is_log2_of_length():
    assert calculate_entropy("abcdefghij") == pytest.approx(log2(10))


def test_default_dns_rule_is_reachable():
    rule = load_rules()["suspicious_dns"]
    assert log2(rule["minimum_label_length"]) >= rule["entropy_threshold"]


def test_unreachable_dns_rule_warns():
    with pytest.warns(UserWarning, match="12\\+ characters"):
        check_dns_rule({"entropy_threshold": 3.5, "minimum_label_length": 10})


# --- 3. VirusTotal uses the right endpoint ---------------------------------

@pytest.mark.parametrize(
    "ioc, endpoint",
    [
        ("192.0.2.10", "ip_addresses"),
        ("2001:db8::1", "ip_addresses"),
        ("a8K2mP9xQ4vL.example.test", "domains"),
    ],
)
def test_vt_endpoint(ioc, endpoint):
    assert get_vt_endpoint(ioc) == endpoint


def test_domain_is_queried_on_domains_endpoint(monkeypatch, tmp_path):
    called = []

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}

    def fake_get(url, **kwargs):
        called.append(url)
        return FakeResponse()

    monkeypatch.setattr(virustotal.requests, "get", fake_get)

    enricher = VirusTotalEnricher(
        api_key="test-key", cache=IOC_Cache(str(tmp_path / "cache.json"))
    )
    result = enricher.enrich("evil.example.test")

    assert called == [f"{virustotal.VT_API_URL}/domains/evil.example.test"]
    assert result["status"] == "ANALYZED"
    assert result["malicious"] == 3


# --- 4. Timestamps from every source are compared in UTC -------------------

def test_timestamps_are_utc_aware():
    unix = 1_794_567_600.0  # 2026-11-13 11:00:00 UTC
    expected = datetime(2026, 11, 13, 11, 0, tzinfo=timezone.utc)

    assert parse_timestamp(unix) == expected
    assert parse_timestamp("2026-11-13T11:00:00Z") == expected
    assert parse_timestamp("2026-11-13T12:00:00+01:00") == expected
    assert parse_timestamp("2026-11-13T11:00:00") == expected


def test_pcap_and_evtx_events_share_a_window():
    # Same instant: one as a Unix float (PCAP), one as an ISO string (EVTX)
    unix = parse_timestamp("2026-11-13T10:00:00Z").timestamp()
    events = windows_failures(4)
    events.append({**events[0], "timestamp": unix + 10})

    alerts = detect_windows_bruteforce(events, WINDOWS_RULE)
    assert len(alerts) == 1


# --- 5. auth.log year inference --------------------------------------------

def test_authlog_future_date_rolls_back_one_year(tmp_path):
    future = datetime.now() + timedelta(days=30)
    line = (
        f"{future:%b} {future.day:2d} 10:00:00 host sshd[1]: "
        "Failed password for root from 192.0.2.10 port 4242 ssh2\n"
    )
    log = tmp_path / "auth.log"
    log.write_text(line, encoding="utf-8")

    timestamp = datetime.fromisoformat(read_authlog(log)[0]["timestamp"])

    assert timestamp <= datetime.now()
    assert timestamp.year == future.year - 1


def test_authlog_explicit_year_is_kept(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Dec 31 23:59:00 host sshd[1]: "
        "Failed password for root from 192.0.2.10 port 4242 ssh2\n",
        encoding="utf-8",
    )

    timestamp = read_authlog(log, year=2030)[0]["timestamp"]
    assert timestamp.startswith("2030-12-31")
