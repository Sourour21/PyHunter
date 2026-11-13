from datetime import datetime


def normalize_event(event: dict, source: str) -> dict:
    """Normalize an event into a common PyHunter structure."""

    normalized = event.copy()
    timestamp = normalized.get("timestamp")

    if isinstance(timestamp, datetime):
        normalized["timestamp"] = timestamp.isoformat()

    # Keep Unix timestamps as numbers for chronological analysis.
    elif isinstance(timestamp, (int, float)):
        normalized["timestamp"] = timestamp

    elif timestamp is not None:
        normalized["timestamp"] = str(timestamp)

    normalized["source"] = source

    normalized.setdefault("source_ip", None)
    normalized.setdefault("destination_ip", None)
    normalized.setdefault("username", None)
    normalized.setdefault("source_port", None)
    normalized.setdefault("destination_port", None)
    normalized.setdefault("status", None)
    normalized.setdefault("event_type", "NETWORK_EVENT")

    return normalized


def normalize_events(events: list[dict], source: str) -> list[dict]:
    """Normalize a list of events."""

    return [
        normalize_event(event, source)
        for event in events
    ]
