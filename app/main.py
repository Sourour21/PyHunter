from pathlib import Path

from app.cli import parse_args
from app.ingestion.pcap_reader import read_pcap
from app.ingestion.authlog_reader import read_authlog
from app.ingestion.evtx_reader import read_evtx
from app.normalization.normalizer import normalize_events
from app.detection.engine import detect_threats
from app.detection.rules_loader import load_rules
from app.enrichment.virustotal import VirusTotalEnricher
from app.reporting.json_report import generate_json_report
from app.reporting.html_report import generate_html_report


def main():
    args = parse_args()

    events = []

    if not args.pcap and not args.authlog and not args.evtx:
        print(
            "Error: provide at least one input file "
            "(--pcap, --authlog or --evtx)"
        )
        return 1

    if args.pcap:
        print(f"[+] Reading PCAP: {args.pcap}")
        events.extend(
            normalize_events(read_pcap(args.pcap), "PCAP")
        )

    if args.authlog:
        print(f"[+] Reading auth.log: {args.authlog}")
        events.extend(
            normalize_events(read_authlog(args.authlog), "AUTHLOG")
        )

    if args.evtx:
        print(f"[+] Reading Windows EVTX: {args.evtx}")
        events.extend(
            normalize_events(read_evtx(args.evtx), "EVTX")
        )

    print(f"[+] Events loaded: {len(events)}")

    rules = load_rules(args.rules)
    print("[+] Detection rules loaded")

    alerts = detect_threats(events, rules)
    print(f"[+] Alerts detected: {len(alerts)}")

    enricher = VirusTotalEnricher()

    for alert in alerts:
        iocs = []

        source_ip = alert.get("source_ip")
        domain = alert.get("domain")

        if source_ip:
            iocs.append(source_ip)
        if domain:
            iocs.append(domain)

        if iocs:
            alert["ioc_enrichment"] = [
                enricher.enrich(ioc) for ioc in iocs
            ]

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"

    generate_json_report(alerts, str(json_path))
    generate_html_report(alerts, str(html_path))

    print(f"[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")

    print("\nPyHunter analysis completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
