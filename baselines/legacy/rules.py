from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class RuleMatch:
    label: str
    severity: str
    score: float
    name: str
    reason: str


def evaluate_rules(row: pd.Series) -> list[RuleMatch]:
    matches: list[RuleMatch] = []

    if row["unique_dst_ports_60s"] >= 20 and row["syn_ratio"] >= 0.35:
        matches.append(
            RuleMatch(
                "port_scan",
                "high",
                min(0.99, 0.72 + row["unique_dst_ports_60s"] / 500),
                "R1_SYN_PORT_SWEEP",
                f"{int(row['unique_dst_ports_60s'])} destination ports in 60s with SYN ratio {row['syn_ratio']:.2f}",
            )
        )

    if row["packet_rate"] >= 800 and row["packets"] >= 1000:
        matches.append(
            RuleMatch(
                "dos",
                "critical" if row["packet_rate"] >= 2000 else "high",
                min(0.99, 0.70 + row["packet_rate"] / 10000),
                "R2_HIGH_RATE_FLOOD",
                f"packet rate {row['packet_rate']:.1f}/s across {int(row['packets'])} packets",
            )
        )

    if row["is_auth_service"] == 1 and row["failed_logins"] >= 5 and row["connections_60s"] >= 10:
        matches.append(
            RuleMatch(
                "brute_force",
                "high",
                min(0.99, 0.74 + row["failed_logins"] / 100),
                "R3_REPEATED_AUTH_FAILURE",
                f"{int(row['failed_logins'])} failed logins on port {int(row['dst_port'])} with {int(row['connections_60s'])} connections in 60s",
            )
        )

    severity_order = {'medium': 1, 'high': 2, 'critical': 3}
    return sorted(matches, key=lambda match: (severity_order[match.severity], match.score, match.name), reverse=True)

