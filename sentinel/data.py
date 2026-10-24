from __future__ import annotations
from datetime import datetime, timedelta, timezone
import numpy as np
import pandas as pd
from .config import CLASSES, SEEDS
from .temporal import add_context

PROFILES = {
    "benign": ["web", "backup", "admin_fanout", "dns_burst", "legitimate_auth"],
    "port_scan": ["syn_sweep", "slow_scan", "mixed_scan"],
    "dos": ["syn_flood", "udp_flood", "request_flood"],
    "brute_force": ["ssh_passwords", "ftp_passwords", "rdp_passwords"],
}


def generate_partition(
    name: str, episodes_per_class: int, seed: int, shifted=False
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    start = datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(
        days=list(SEEDS).index(name) if name in SEEDS else 10
    )
    for label in CLASSES:
        for episode in range(episodes_per_class):
            profile = PROFILES[label][episode % len(PROFILES[label])]
            session = f"{name}-{label}-{episode:04d}"
            src = f"10.{(seed % 200) + 1}.{CLASSES.index(label) + 1}.{episode + 1}"
            service = int(rng.choice([80, 443, 445, 993]))
            if profile == "legitimate_auth":
                service = int(rng.choice([21, 22, 3389]))
            if profile in ["dns_burst", "udp_flood"]:
                service = int(rng.choice([53, 123]))
            if label == "brute_force":
                service = {
                    "ssh_passwords": 22,
                    "ftp_passwords": 21,
                    "rdp_passwords": 3389,
                }[profile]
            spacing = (
                rng.uniform(18, 45) if profile == "slow_scan" else rng.uniform(0.3, 4)
            )
            for step in range(12):
                protocol, failed = "TCP", 0
                port = service
                if profile in ["web", "legitimate_auth"]:
                    packets = int(rng.integers(8, 1500))
                    duration = rng.uniform(0.3, 60)
                    size = rng.uniform(200, 1400)
                    syn = rng.uniform(0.002, 0.12)
                    ack = rng.uniform(0.72, 0.995)
                    rst = rng.uniform(0, 0.02)
                    if profile == "legitimate_auth":
                        failed = int(rng.integers(0, 3))
                elif profile == "backup":
                    packets = int(rng.integers(1200, 18000))
                    duration = rng.uniform(0.8, 12)
                    size = rng.uniform(950, 1480)
                    syn = rng.uniform(0, 0.005)
                    ack = rng.uniform(0.92, 0.999)
                    rst = 0
                elif profile == "admin_fanout":
                    port = 1000 + step * 17
                    packets = int(rng.integers(8, 100))
                    duration = rng.uniform(0.05, 4)
                    size = rng.uniform(150, 1100)
                    syn = rng.uniform(0.02, 0.18)
                    ack = rng.uniform(0.7, 0.98)
                    rst = rng.uniform(0, 0.04)
                elif profile == "dns_burst":
                    protocol = "UDP"
                    packets = int(rng.integers(5, 9000))
                    duration = rng.uniform(1, 30)
                    size = rng.uniform(60, 250)
                    syn = ack = rst = 0
                elif label == "port_scan":
                    port = int(rng.integers(1, 65536))
                    packets = int(rng.integers(2, 80))
                    duration = rng.uniform(0.05, 5)
                    if profile == "slow_scan":
                        duration = rng.uniform(5, 45)
                    size = rng.uniform(45, 230)
                    syn = rng.uniform(0.3, 0.95)
                    ack = rng.uniform(0, 0.2)
                    rst = rng.uniform(0, 0.25)
                elif label == "dos":
                    packets = int(rng.integers(1000, 25000))
                    duration = rng.uniform(0.1, 5)
                    size = rng.uniform(60, 650)
                    syn = rng.uniform(0.4, 0.98)
                    ack = rng.uniform(0, 0.12)
                    rst = rng.uniform(0, 0.04)
                    if profile == "udp_flood":
                        protocol = "UDP"
                        syn = ack = rst = 0
                        duration = rng.uniform(0.1, 3)
                    if profile == "request_flood":
                        syn = rng.uniform(0.01, 0.15)
                        ack = rng.uniform(0.25, 0.65)
                else:
                    packets = int(rng.integers(40, 800))
                    duration = rng.uniform(2, 45)
                    size = rng.uniform(90, 750)
                    syn = rng.uniform(0.02, 0.25)
                    ack = rng.uniform(0.35, 0.9)
                    rst = rng.uniform(0, 0.1)
                    failed = int(rng.integers(3, 20))
                if shifted:
                    # The locked test domain changes scales, not labels or feature visibility.
                    duration *= rng.uniform(0.6, 1.5)
                    packets = max(1, int(packets * rng.uniform(0.7, 1.4)))
                    size *= rng.uniform(0.85, 1.12)
                auth_available = int(rng.random() >= 0.12)
                # Unknown outcomes are represented explicitly, never asserted as zero failures.
                observed_failed = failed if auth_available else 0
                now = start + timedelta(
                    seconds=episode * 800
                    + CLASSES.index(label) * 100000
                    + step * spacing
                )
                rows.append(
                    dict(
                        flow_id=f"{session}-{step:02d}",
                        session_id=session,
                        partition=name,
                        timestamp=now.isoformat(),
                        src_ip=src,
                        dst_ip="192.0.2.20",
                        src_port=40000 + step,
                        dst_port=port,
                        protocol=protocol,
                        flow_duration_s=round(duration, 6),
                        packets=packets,
                        bytes=max(packets, int(packets * size)),
                        syn_count=min(packets, int(packets * syn)),
                        ack_count=min(packets, int(packets * ack)),
                        rst_count=min(packets, int(packets * rst)),
                        failed_logins=observed_failed,
                        auth_available=auth_available,
                        label=label,
                        scenario=label,
                        scenario_subtype=profile,
                        is_ambiguous=False,
                    )
                )
    return add_context(pd.DataFrame(rows))


def make_development():
    counts = {
        "train": 80,
        "probability_calibration": 24,
        "conformal_calibration": 24,
        "validation": 24,
    }
    return {
        name: generate_partition(name, n, SEEDS[name]) for name, n in counts.items()
    }


def make_final_test():
    return generate_partition("final_test", 60, SEEDS["final_test"], shifted=True)


def make_indistinguishable_challenge():
    # Identical observable traffic can have different intent. No feature-based IDS can infer hidden authorization.
    base = generate_partition("challenge", 5, 8801)
    admin = base.loc[base.scenario_subtype == "admin_fanout"].copy()
    if admin.empty:
        raise RuntimeError("Challenge requires admin observations.")
    unauthorized = admin.copy()
    unauthorized["label"] = "port_scan"
    unauthorized["flow_id"] = unauthorized.flow_id + "-unauthorized"
    unauthorized["session_id"] = unauthorized.session_id + "-unauthorized"
    for frame in [admin, unauthorized]:
        frame["scenario"] = "ambiguous"
        frame["scenario_subtype"] = "authorization_not_observable"
        frame["is_ambiguous"] = True
    return pd.concat([admin, unauthorized], ignore_index=True)
