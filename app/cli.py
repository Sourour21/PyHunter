import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="PyHunter - Network Threat Detection Tool"
    )

    parser.add_argument("--pcap", help="Path to a PCAP file")
    parser.add_argument("--authlog", help="Path to a Linux auth.log file")
    parser.add_argument("--evtx", help="Path to a Windows Security EVTX file")

    parser.add_argument(
        "--rules",
        default="rules/detection_rules.yaml",
        help="Path to YAML detection rules",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for reports",
    )

    return parser.parse_args()
