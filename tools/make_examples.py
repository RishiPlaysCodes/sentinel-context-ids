"""Construct offline examples. This writes files only; it never sends network packets."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pandas as pd
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def main():
    data = ROOT / "data"
    data.mkdir(exist_ok=True)
    training = pd.read_csv(data / "train.csv")
    columns = [
        "flow_duration_s",
        "packets",
        "bytes",
        "syn_count",
        "ack_count",
        "rst_count",
        "failed_logins",
        "unique_dst_ports_60s",
        "connections_60s",
        "dst_port",
    ]
    training.loc[training.auth_available == 1].groupby("label", sort=True).head(1)[
        columns
    ].to_csv(data / "example_unlabeled.csv", index=False)
    packets = []
    for i, flags in enumerate(["S", "SA", "A", "RA"]):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.10", dst="192.0.2.20")
            / TCP(sport=40000, dport=443, flags=flags)
            / Raw(b"x" * 100)
        )
        packet.time = 1700000000 + i
        packets.append(packet)
    for i in range(12):
        packet = (
            Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.30", dst="192.0.2.20")
            / TCP(sport=41000 + i, dport=1000 + i, flags="S")
        )
        packet.time = 1700000010 + i * 20
        packets.append(packet)
    packet = (
        Ether(src="02:00:00:00:00:04", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.40", dst="192.0.2.20")
        / UDP(sport=42000, dport=53)
        / Raw(b"q" * 30)
    )
    packet.time = 1700000020
    packets.append(packet)
    wrpcap(
        str(data / "offline_example.pcap"), sorted(packets, key=lambda p: float(p.time))
    )
    print("Wrote minimal unlabeled CSV and constructed offline PCAP.")


if __name__ == "__main__":
    main()
