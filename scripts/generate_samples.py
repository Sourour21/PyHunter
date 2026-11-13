
from pathlib import Path
from datetime import datetime, timedelta
import random

from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    wrpcap,
)

# Racine du projet PyHunter
BASE_DIR = Path(__file__).resolve().parent.parent

PCAP_DIR = BASE_DIR / "samples" / "pcaps"
LOG_DIR = BASE_DIR / "samples" / "logs"

PCAP_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Adresses réservées à la documentation
ATTACKER_IP = "192.0.2.10"
TARGET_IP = "198.51.100.20"

packets = []


def generate_port_scan():
    """Génère plusieurs paquets TCP SYN vers différents ports."""
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]

    for port in ports:
        packet = (
            Ether()
            / IP(src=ATTACKER_IP, dst=TARGET_IP)
            / TCP(
                sport=random.randint(40000, 60000),
                dport=port,
                flags="S"
            )
        )
        packets.append(packet)


def generate_dns_queries():
    """Génère des requêtes DNS synthétiques."""
    domains = [
        "a8K2mP9xQ4vL.example.test",
        "z7Xq9Wb3Nf5R.example.test",
        "normal.example.test",
    ]

    for domain in domains:
        packet = (
            Ether()
            / IP(src=ATTACKER_IP, dst=TARGET_IP)
            / UDP(sport=random.randint(40000, 60000), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype="A")
            )
        )
        packets.append(packet)


def generate_auth_log():
    """Crée un journal SSH synthétique."""
    log_file = LOG_DIR / "auth.log"

    now = datetime.now()

    lines = []

    # Dix tentatives SSH échouées depuis la même adresse IP
    for i in range(10):
        timestamp = now + timedelta(seconds=i * 3)

        line = (
            f"{timestamp.strftime('%b %d %H:%M:%S')} "
            f"lab-server sshd[1234]: "
            f"Failed password for invalid user admin "
            f"from {ATTACKER_IP} port {45000 + i} ssh2"
        )

        lines.append(line)

    # Une connexion réussie pour comparaison
    timestamp = now + timedelta(seconds=35)

    lines.append(
        f"{timestamp.strftime('%b %d %H:%M:%S')} "
        f"lab-server sshd[1235]: "
        f"Accepted password for testuser from "
        f"192.0.2.30 port 45100 ssh2"
    )

    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[OK] Journal SSH créé : {log_file}")


def main():
    print("=== PyHunter - Laboratory Data Generator ===")

    generate_port_scan()
    generate_dns_queries()

    pcap_file = PCAP_DIR / "lab_traffic.pcap"

    wrpcap(str(pcap_file), packets)

    print(f"[OK] PCAP créé : {pcap_file}")
    print(f"[OK] Nombre de paquets : {len(packets)}")

    generate_auth_log()

    print("\nGénération des données terminée.")


if __name__ == "__main__":
    main()
