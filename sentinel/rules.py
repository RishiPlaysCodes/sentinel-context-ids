"""Evidence rules are contextual hypotheses, not unconditional rate-based attack labels."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Evidence:
    name: str
    label: str
    strength: float
    reason: str
    severity: str = "high"


def rules(row):
    evidence = []
    if row.unique_dst_ports_60s >= 20 and row.syn_ratio >= 0.35 and row.ack_ratio < 0.4:
        evidence.append(
            Evidence(
                "R1_FAST_SCAN",
                "port_scan",
                0.92,
                f"ports60={int(row.unique_dst_ports_60s)} >=20, SYN={row.syn_ratio:.3f} >=.35, ACK={row.ack_ratio:.3f} <.4",
            )
        )
    if (
        row.temporal_available
        and row.unique_dst_ports_300s >= 8
        and row.new_port_fraction_300s >= 0.6
        and row.ack_ratio < 0.25
        and row.syn_ratio >= 0.25
    ):
        evidence.append(
            Evidence(
                "R2_PERSISTENT_SCAN",
                "port_scan",
                0.9,
                f"ports300={int(row.unique_dst_ports_300s)} >=8; new-port fraction={row.new_port_fraction_300s:.3f} >=.6; incomplete-handshake context",
            )
        )
    flood_volume = row.packet_rate >= 800 and row.packets >= 1000
    handshake_failure = row.syn_ratio >= 0.35 and row.ack_ratio < 0.3
    service_anomaly = (
        row.service_rate_ratio >= 2
        and row.connections_300s >= 8
        and row.ack_ratio < 0.65
    )
    if flood_volume and (handshake_failure or service_anomaly):
        evidence.append(
            Evidence(
                "R3_CONTEXTUAL_FLOOD",
                "dos",
                0.94,
                f"packets/s={row.packet_rate:.1f} >=800; packets={int(row.packets)} >=1000; "
                f"SYN={row.syn_ratio:.3f}, ACK={row.ack_ratio:.3f}, training-baseline ratio={row.service_rate_ratio:.2f}",
                "critical" if row.packet_rate >= 2000 else "high",
            )
        )
    if (
        row.auth_available
        and row.is_auth_service
        and row.failed_logins >= 5
        and row.connections_60s >= 3
    ):
        evidence.append(
            Evidence(
                "R4_AUTH_FAILURES",
                "brute_force",
                0.92,
                f"known authentication failures={int(row.failed_logins)} >=5; attempts60={int(row.connections_60s)} >=3",
            )
        )
    return sorted(
        evidence,
        key=lambda e: (e.severity == "critical", e.strength, e.name),
        reverse=True,
    )


def bulk_evidence(row):
    return bool(
        row.packet_rate >= 800
        and row.ack_ratio >= 0.85
        and row.avg_packet_size >= 900
        and row.unique_dst_ports_60s <= 3
        and row.failed_logins == 0
    )
