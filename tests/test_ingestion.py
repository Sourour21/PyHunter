from pathlib import Path

import pytest

from app.ingestion.pcap_reader import read_pcap
from app.ingestion.authlog_reader import read_authlog


ROOT = Path(__file__).resolve().parents[1]


def test_read_pcap():
    events = read_pcap(str(ROOT / "samples" / "pcaps" / "lab_traffic.pcap"))

    assert len(events) == 14
    assert sum(e["protocol"] == "TCP" for e in events) == 11
    assert sum(e["protocol"] == "UDP" for e in events) == 3
    assert sum(e["dns_query"] is not None for e in events) == 3


def test_read_authlog():
    events = read_authlog(str(ROOT / "samples" / "logs" / "auth.log"))

    assert len(events) == 11
    assert sum(e["status"] == "FAILED" for e in events) == 10
    assert sum(e["status"] == "SUCCESS" for e in events) == 1


def test_missing_pcap():
    with pytest.raises(FileNotFoundError):
        read_pcap(str(ROOT / "samples" / "pcaps" / "missing.pcap"))


def test_missing_authlog():
    with pytest.raises(FileNotFoundError):
        read_authlog(str(ROOT / "samples" / "logs" / "missing.log"))

def test_read_evtx_authentication_events(tmp_path, monkeypatch):
    from app.ingestion import evtx_reader

    fake_file = tmp_path / "Security.evtx"
    fake_file.write_bytes(b"fake evtx fixture")

    xml_success = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <EventID>4624</EventID>
        <TimeCreated SystemTime="2026-11-13T10:00:00.000Z"/>
    </System>
    <EventData>
        <Data Name="TargetUserName">testuser</Data>
        <Data Name="IpAddress">192.0.2.30</Data>
    </EventData>
</Event>
"""

    xml_failed = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <EventID>4625</EventID>
        <TimeCreated SystemTime="2026-11-13T10:01:00.000Z"/>
    </System>
    <EventData>
        <Data Name="TargetUserName">admin</Data>
        <Data Name="IpAddress">192.0.2.10</Data>
    </EventData>
</Event>
"""

    class FakeRecord:
        def __init__(self, xml):
            self._xml = xml

        def xml(self):
            return self._xml

    class FakeEvtx:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def records(self):
            return [
                FakeRecord(xml_success),
                FakeRecord(xml_failed),
            ]

    monkeypatch.setattr(evtx_reader, "Evtx", FakeEvtx)

    events = evtx_reader.read_evtx(fake_file)

    assert len(events) == 2

    assert events[0]["event_id"] == 4624
    assert events[0]["status"] == "SUCCESS"
    assert events[0]["username"] == "testuser"
    assert events[0]["source_ip"] == "192.0.2.30"

    assert events[1]["event_id"] == 4625
    assert events[1]["status"] == "FAILED"
    assert events[1]["username"] == "admin"
    assert events[1]["source_ip"] == "192.0.2.10"
