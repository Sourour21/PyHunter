from collections import defaultdict
from datetime import datetime, timezone
from math import log2
from pathlib import Path

from app.detection.rules_loader import load_rules


def parse_timestamp(value):
    """Convert an event timestamp into a timezone-aware UTC datetime.

    Unix timestamps (PCAP) are interpreted as UTC. ISO strings that carry
    an offset (EVTX) are converted to UTC. Naive values (auth.log has no
    timezone) are assumed to already be UTC so that all sources are
    compared on the same clock.
    """

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    raise ValueError(f"Unsupported timestamp: {value}")


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""

    if not value:
        return 0.0

    entropy = 0.0

    for character in set(value):
        probability = value.count(character) / len(value)
        entropy -= probability * log2(probability)

    return entropy


def detect_port_scan(events: list[dict], rule: dict) -> list[dict]:
    """Detect TCP SYN scans targeting multiple ports."""

    if not rule.get("enabled", True):
        return []

    threshold = rule["threshold"]
    window = rule["window_seconds"]

    grouped = defaultdict(list)

    for event in events:
        if event.get("protocol") != "TCP":
            continue

        flags = str(event.get("tcp_flags") or "")

        if "S" not in flags or "A" in flags:
            continue

        if not event.get("source_ip") or event.get("destination_port") is None:
            continue

        grouped[event["source_ip"]].append(event)

    alerts = []

    for source_ip, source_events in grouped.items():
        source_events.sort(key=lambda e: parse_timestamp(e["timestamp"]))

        for index, first_event in enumerate(source_events):
            start = parse_timestamp(first_event["timestamp"])
            window_events = []

            for event in source_events[index:]:
                current = parse_timestamp(event["timestamp"])

                if (current - start).total_seconds() > window:
                    break

                window_events.append(event)

            ports = sorted({
                event["destination_port"]
                for event in window_events
            })

            if len(ports) >= threshold:
                alerts.append({
                    "alert_type": "PORT_SCAN",
                    "source_ip": source_ip,
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "event_count": len(window_events),
                    "ports_targeted": ports,
                    "window_seconds": window,
                    "mitre_attack": rule["mitre_attack"],
                    "timestamp": first_event["timestamp"],
                })
                break

    return alerts


def detect_bruteforce(
    events: list[dict],
    rule: dict,
    event_type: str,
    alert_type: str,
) -> list[dict]:
    """Detect repeated failed authentication attempts of a given event type."""

    if not rule.get("enabled", True):
        return []

    threshold = rule["threshold"]
    window = rule["window_seconds"]

    grouped = defaultdict(list)

    for event in events:
        if event.get("status") != "FAILED":
            continue

        if event.get("event_type") != event_type:
            continue

        if event.get("source_ip"):
            grouped[event["source_ip"]].append(event)

    alerts = []

    for source_ip, source_events in grouped.items():
        source_events.sort(key=lambda e: parse_timestamp(e["timestamp"]))

        for index, first_event in enumerate(source_events):
            start = parse_timestamp(first_event["timestamp"])
            window_events = []

            for event in source_events[index:]:
                current = parse_timestamp(event["timestamp"])

                if (current - start).total_seconds() > window:
                    break

                window_events.append(event)

            if len(window_events) >= threshold:
                alerts.append({
                    "alert_type": alert_type,
                    "source_ip": source_ip,
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "event_count": len(window_events),
                    "username": first_event.get("username"),
                    "window_seconds": window,
                    "mitre_attack": rule["mitre_attack"],
                    "timestamp": first_event["timestamp"],
                })
                break

    return alerts


def detect_ssh_bruteforce(events: list[dict], rule: dict) -> list[dict]:
    """Detect repeated failed SSH authentication attempts."""

    return detect_bruteforce(events, rule, "SSH_LOGIN", "SSH_BRUTE_FORCE")


def detect_windows_bruteforce(events: list[dict], rule: dict) -> list[dict]:
    """Detect repeated failed Windows logons (Event ID 4625)."""

    return detect_bruteforce(events, rule, "WINDOWS_LOGIN", "WINDOWS_BRUTE_FORCE")


def detect_suspicious_dns(events: list[dict], rule: dict) -> list[dict]:
    """Detect DNS queries containing high-entropy domain labels."""

    if not rule.get("enabled", True):
        return []

    entropy_threshold = rule["entropy_threshold"]
    minimum_length = rule["minimum_label_length"]

    alerts = []

    for event in events:
        domain = event.get("dns_query")

        if not domain:
            continue

        labels = domain.rstrip(".").split(".")

        for label in labels:
            if len(label) < minimum_length:
                continue

            entropy = calculate_entropy(label)

            if entropy >= entropy_threshold:
                alerts.append({
                    "alert_type": "SUSPICIOUS_DNS",
                    "source_ip": event.get("source_ip"),
                    "destination_ip": event.get("destination_ip"),
                    "domain": domain,
                    "suspicious_label": label,
                    "entropy": round(entropy, 3),
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "mitre_attack": rule["mitre_attack"],
                    "timestamp": event.get("timestamp"),
                })
                break

    return alerts


def detect_threats(events: list[dict], rules: dict | None = None) -> list[dict]:
    """Run all enabled detection rules."""

    if rules is None:
        rules = load_rules()

    alerts = []

    alerts.extend(
        detect_port_scan(events, rules["port_scan"])
    )

    alerts.extend(
        detect_ssh_bruteforce(events, rules["ssh_bruteforce"])
    )

    # Optional rule: older custom YAML files may not define it.
    if "windows_bruteforce" in rules:
        alerts.extend(
            detect_windows_bruteforce(events, rules["windows_bruteforce"])
        )

    alerts.extend(
        detect_suspicious_dns(events, rules["suspicious_dns"])
    )

    return alerts


if __name__ == "__main__":
    from app.ingestion.pcap_reader import read_pcap
    from app.ingestion.authlog_reader import read_authlog
    from app.normalization.normalizer import normalize_events

    project_root = Path(__file__).resolve().parents[2]

    pcap_events = normalize_events(
        read_pcap(project_root / "samples" / "pcaps" / "lab_traffic.pcap"),
        "PCAP"
    )

    auth_events = normalize_events(
        read_authlog(project_root / "samples" / "logs" / "auth.log"),
        "AUTHLOG"
    )

    all_events = pcap_events + auth_events
    alerts = detect_threats(all_events)

    print("\nPyHunter - Detection Engine")
    print(f"Events analyzed: {len(all_events)}")
    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print("\n------------------------------")
        for key, value in alert.items():
            print(f"{key}: {value}")
