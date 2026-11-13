from datetime import datetime, timezone
from pathlib import Path
from html import escape


def generate_html_report(alerts: list[dict], output_path: str) -> str:
    rows = []

    for alert in alerts:
        alert_type = escape(str(alert.get("alert_type", "UNKNOWN")))
        source_ip = escape(str(alert.get("source_ip", "N/A")))
        severity = escape(str(alert.get("severity", "N/A")))
        details = escape(str(alert))

        rows.append(
            f"""
            <tr>
                <td>{alert_type}</td>
                <td>{source_ip}</td>
                <td>{severity}</td>
                <td><pre>{details}</pre></td>
            </tr>
            """
        )

    generated_at = datetime.now(timezone.utc).isoformat()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyHunter Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 30px; background: #f4f6f9; }}
        h1 {{ color: #172554; }}
        .summary {{ background: white; padding: 18px; border-radius: 8px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
        th {{ background: #172554; color: white; }}
        tr:nth-child(even) {{ background: #f8fafc; }}
        pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
    </style>
</head>
<body>
    <h1>PyHunter - Security Analysis Report</h1>
    <div class="summary">
        <p><strong>Total alerts:</strong> {len(alerts)}</p>
        <p><strong>Generated at:</strong> {escape(generated_at)}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Alert type</th>
                <th>Source IP</th>
                <th>Severity</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows) if rows else '<tr><td colspan="4">No alerts detected</td></tr>'}
        </tbody>
    </table>
</body>
</html>
"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")

    return str(path)
