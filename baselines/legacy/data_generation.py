from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from .config import RANDOM_SEED


def _ip(rng: np.random.Generator, subnet: str) -> str:
    return f"{subnet}.{int(rng.integers(2, 250))}"


def _rows_for_scenario(
    scenario: str,
    count: int,
    rng: np.random.Generator,
    start_index: int,
) -> list[dict]:
    rows: list[dict] = []
    base_time = datetime(2026, 10, 24, 9, 0, tzinfo=timezone.utc)

    for offset in range(count):
        row_index = start_index + offset
        timestamp = base_time + timedelta(seconds=row_index * 2)
        src_ip = _ip(rng, "10.0.1")
        dst_ip = _ip(rng, "10.0.2")
        protocol = rng.choice(["TCP", "UDP"], p=[0.78, 0.22])
        subtype = "clear"

        if scenario == "benign":
            duration = float(rng.uniform(0.4, 45.0))
            packets = int(rng.integers(4, 420))
            dst_port = int(rng.choice([53, 80, 123, 443, 445, 993]))
            syn_count = int(rng.integers(0, min(7, packets + 1))) if protocol == "TCP" else 0
            ack_count = max(0, packets - syn_count - int(rng.integers(0, 3))) if protocol == "TCP" else 0
            rst_count = int(rng.integers(0, 2))
            failed_logins = 0
            unique_ports = int(rng.integers(1, 6))
            connections = int(rng.integers(1, 18))
            avg_size = float(rng.uniform(260, 1300))
            label = "benign"
        elif scenario == "port_scan":
            duration = float(rng.uniform(2.0, 30.0))
            packets = int(rng.integers(35, 260))
            dst_port = int(rng.integers(1, 65535))
            protocol = "TCP"
            syn_count = int(rng.integers(max(18, packets // 3), max(19, packets)))
            ack_count = int(rng.integers(0, max(2, packets // 8)))
            rst_count = int(rng.integers(0, max(2, packets // 5)))
            failed_logins = 0
            unique_ports = int(rng.integers(24, 180))
            connections = int(rng.integers(30, 230))
            avg_size = float(rng.uniform(45, 160))
            label = "port_scan"
        elif scenario == "dos":
            duration = float(rng.uniform(0.8, 12.0))
            packets = int(rng.integers(1800, 18000))
            dst_port = int(rng.choice([80, 443, 53]))
            protocol = rng.choice(["TCP", "UDP"], p=[0.65, 0.35])
            syn_count = int(rng.integers(300, max(301, packets // 2))) if protocol == "TCP" else 0
            ack_count = int(rng.integers(0, max(2, packets // 8))) if protocol == "TCP" else 0
            rst_count = int(rng.integers(0, 8))
            failed_logins = 0
            unique_ports = int(rng.integers(1, 5))
            connections = int(rng.integers(250, 1800))
            avg_size = float(rng.uniform(70, 520))
            label = "dos"
        elif scenario == "brute_force":
            duration = float(rng.uniform(8.0, 90.0))
            packets = int(rng.integers(60, 650))
            dst_port = int(rng.choice([21, 22, 3389]))
            protocol = "TCP"
            syn_count = int(rng.integers(8, 65))
            ack_count = int(rng.integers(15, max(16, packets // 2)))
            rst_count = int(rng.integers(0, 8))
            failed_logins = int(rng.integers(5, 28))
            unique_ports = int(rng.integers(1, 4))
            connections = int(rng.integers(12, 95))
            avg_size = float(rng.uniform(90, 480))
            label = "brute_force"
        elif scenario == "ambiguous_low_slow_scan":
            duration = float(rng.uniform(45.0, 180.0))
            packets = int(rng.integers(15, 85))
            dst_port = int(rng.integers(1, 65535))
            protocol = "TCP"
            syn_count = int(rng.integers(5, 18))
            ack_count = int(rng.integers(2, 16))
            rst_count = int(rng.integers(0, 5))
            failed_logins = 0
            unique_ports = int(rng.integers(7, 18))
            connections = int(rng.integers(8, 28))
            avg_size = float(rng.uniform(80, 260))
            label = "port_scan"
            subtype = "low_and_slow_reconnaissance"
        elif scenario == "ambiguous_backup_burst":
            duration = float(rng.uniform(1.0, 8.0))
            packets = int(rng.integers(1200, 6200))
            dst_port = int(rng.choice([443, 445]))
            protocol = "TCP"
            syn_count = int(rng.integers(1, 8))
            ack_count = max(1, packets - syn_count - int(rng.integers(0, 5)))
            rst_count = 0
            failed_logins = 0
            unique_ports = int(rng.integers(1, 3))
            connections = int(rng.integers(4, 28))
            avg_size = float(rng.uniform(1150, 1450))
            label = "benign"
            subtype = "legitimate_high_rate_backup"
        else:
            raise ValueError(f"Unknown scenario: {scenario}")

        bytes_count = int(max(packets, packets * avg_size + rng.normal(0, packets * 5)))
        rows.append(
            {
                "flow_id": f"flow-{row_index:06d}",
                "timestamp": timestamp.isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(rng.integers(1024, 65535)),
                "dst_port": dst_port,
                "protocol": protocol,
                "flow_duration_s": round(duration, 4),
                "packets": packets,
                "bytes": bytes_count,
                "syn_count": min(syn_count, packets),
                "ack_count": min(ack_count, packets),
                "rst_count": min(rst_count, packets) if protocol == "TCP" else 0,
                "failed_logins": failed_logins,
                "unique_dst_ports_60s": unique_ports,
                "connections_60s": max(connections, unique_ports),
                "scenario": "ambiguous" if scenario.startswith("ambiguous_") else scenario,
                "scenario_subtype": subtype,
                "label": label,
                "is_ambiguous": scenario.startswith("ambiguous_"),
            }
        )
    return rows


def generate_dataset(seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Create deterministic flow records for clear and ambiguous scenarios."""
    rng = np.random.default_rng(seed)
    plan = [
        ("benign", 1600),
        ("port_scan", 450),
        ("dos", 450),
        ("brute_force", 450),
        ("ambiguous_low_slow_scan", 150),
        ("ambiguous_backup_burst", 150),
    ]
    rows: list[dict] = []
    for scenario, count in plan:
        rows.extend(_rows_for_scenario(scenario, count, rng, len(rows)))
    return pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)


def save_dataset(output_path: str | Path, seed: int = RANDOM_SEED) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    generate_dataset(seed).to_csv(output, index=False)
    return output

