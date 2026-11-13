from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, rdpcap


def read_pcap(pcap_path: str | Path) -> list[dict]:
    pcap_path = Path(pcap_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packets = rdpcap(str(pcap_path))
    events = []

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]

        event = {
            "timestamp": float(packet.time),
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "protocol": "OTHER",
            "source_port": None,
            "destination_port": None,
            "tcp_flags": None,
            "dns_query": None,
        }

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            event["protocol"] = "TCP"
            event["source_port"] = int(tcp_layer.sport)
            event["destination_port"] = int(tcp_layer.dport)
            event["tcp_flags"] = str(tcp_layer.flags)

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            event["protocol"] = "UDP"
            event["source_port"] = int(udp_layer.sport)
            event["destination_port"] = int(udp_layer.dport)

        elif packet.haslayer("ICMP"):
            event["protocol"] = "ICMP"

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = packet[DNS].qd

            if isinstance(query, (list, tuple)):
                query = query[0] if query else None

            if query is not None and hasattr(query, "qname"):
                event["dns_query"] = (
                    query.qname.decode("utf-8", errors="replace").rstrip(".")
                )

        events.append(event)

    return events


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[2]
    pcap_file = project_root / "samples" / "pcaps" / "lab_traffic.pcap"

    results = read_pcap(pcap_file)

    print("\nPyHunter - PCAP Reader")
    print(f"Total events extracted: {len(results)}\n")

    for event in results:
        print(event)
