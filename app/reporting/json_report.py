import json
from datetime import datetime, timezone
from pathlib import Path


def generate_json_report(alerts: list[dict], output_path: str) -> str:
    report = {
        "tool": "PyHunter",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False, default=str)

    return str(path)
