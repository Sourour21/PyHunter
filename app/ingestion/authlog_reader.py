import re
from pathlib import Path
from datetime import datetime, timedelta


AUTHLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<source_port>\d+)"
)

SUCCESS_PATTERN = re.compile(
    r"Accepted password for "
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<source_port>\d+)"
)


def read_authlog(log_path: str | Path, year: int | None = None) -> list[dict]:
    """
    Read a Linux SSH authentication log and extract login events.
    """

    log_path = Path(log_path)

    if not log_path.is_file():
        raise FileNotFoundError(f"Auth log file not found: {log_path}")

    # auth.log lines carry no year. When it is not given, assume the
    # current year, but roll back one year for dates in the future
    # (e.g. a December log analysed in January).
    infer_year = year is None
    now = datetime.now()

    if infer_year:
        year = now.year

    events = []

    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            line = line.strip()

            if not line:
                continue

            header = AUTHLOG_PATTERN.match(line)

            if not header:
                continue

            timestamp = datetime.strptime(
                f"{year} {header.group('month')} {header.group('day')} "
                f"{header.group('time')}",
                "%Y %b %d %H:%M:%S"
            )

            if infer_year and timestamp > now + timedelta(days=1):
                timestamp = timestamp.replace(year=year - 1)

            message = header.group("message")

            failed_match = FAILED_PATTERN.search(message)
            success_match = SUCCESS_PATTERN.search(message)

            if failed_match:
                match = failed_match
                status = "FAILED"
            elif success_match:
                match = success_match
                status = "SUCCESS"
            else:
                continue

            events.append({
                "timestamp": timestamp.isoformat(),
                "source_ip": match.group("source_ip"),
                "username": match.group("username"),
                "source_port": int(match.group("source_port")),
                "status": status,
                "event_type": "SSH_LOGIN",
                "line_number": line_number,
            })

    return events


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[2]
    log_file = project_root / "samples" / "logs" / "auth.log"

    results = read_authlog(log_file)

    print("\nPyHunter - SSH Auth Log Reader")
    print(f"Total events extracted: {len(results)}")
    print(f"Failed logins: {sum(e['status'] == 'FAILED' for e in results)}")
    print(f"Successful logins: {sum(e['status'] == 'SUCCESS' for e in results)}\n")

    for event in results:
        print(event)
