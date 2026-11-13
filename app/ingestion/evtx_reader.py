from pathlib import Path
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


def read_evtx(evtx_path: str | Path) -> list[dict]:
    """
    Read a Windows EVTX file and extract authentication events.

    Event IDs:
    - 4624: Successful logon
    - 4625: Failed logon
    """

    evtx_path = Path(evtx_path)

    if not evtx_path.is_file():
        raise FileNotFoundError(f"EVTX file not found: {evtx_path}")

    events = []

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())

                namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                event_id_element = root.find(".//e:EventID", namespace)

                if event_id_element is None:
                    continue

                event_id = int(event_id_element.text)

                if event_id not in (4624, 4625):
                    continue

                time_element = root.find(".//e:TimeCreated", namespace)
                timestamp = (
                    time_element.attrib.get("SystemTime")
                    if time_element is not None
                    else None
                )

                data = {}

                for element in root.findall(".//e:EventData/e:Data", namespace):
                    name = element.attrib.get("Name")

                    if name:
                        data[name] = element.text

                status = "SUCCESS" if event_id == 4624 else "FAILED"

                events.append({
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "source_ip": data.get("IpAddress"),
                    "username": data.get("TargetUserName"),
                    "status": status,
                    "event_type": "WINDOWS_LOGIN",
                })

            except (ET.ParseError, ValueError, AttributeError):
                continue

    return events


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[2]
    evtx_file = project_root / "samples" / "evtx" / "Security.evtx"

    results = read_evtx(evtx_file)

    print("\nPyHunter - Windows EVTX Reader")
    print(f"Total events extracted: {len(results)}")
    print(f"Failed logins: {sum(e['status'] == 'FAILED' for e in results)}")
    print(f"Successful logins: {sum(e['status'] == 'SUCCESS' for e in results)}")

    for event in results:
        print(event)
