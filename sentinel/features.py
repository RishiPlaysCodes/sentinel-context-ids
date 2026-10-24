from __future__ import annotations

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = {
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
}
COUNT_COLUMNS = REQUIRED_COLUMNS - {"flow_duration_s"}


def validate_base(flows: pd.DataFrame) -> pd.DataFrame:
    """Reject invalid observations before calculating rates; never impute bad traffic as normal."""
    if flows.columns.duplicated().any():
        raise ValueError("Duplicate column names are not allowed.")
    missing = sorted((REQUIRED_COLUMNS - {"failed_logins"}) - set(flows.columns))
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")
    if flows.empty:
        raise ValueError("Input contains no flow records.")
    featured = flows.copy()
    if "failed_logins" not in featured:
        featured["failed_logins"] = 0
        featured["auth_available"] = 0
    elif "auth_available" not in featured:
        featured["auth_available"] = 1
    if not featured["auth_available"].isin([0, 1]).all():
        raise ValueError("auth_available must be 0 or 1.")
    if (
        (featured["auth_available"] == 0)
        & (pd.to_numeric(featured["failed_logins"], errors="coerce") != 0)
    ).any():
        raise ValueError(
            "Unavailable authentication evidence cannot contain asserted failure counts."
        )
    for column in sorted(REQUIRED_COLUMNS):
        values = pd.to_numeric(featured[column], errors="coerce")
        invalid = ~np.isfinite(values.to_numpy(dtype=float))
        if invalid.any():
            rows = (np.flatnonzero(invalid)[:5] + 1).tolist()
            raise ValueError(
                f"{column}: require finite numeric values; invalid data rows {rows}."
            )
        if (values < 0).any():
            raise ValueError(f"{column}: negative values are not allowed.")
        if column in COUNT_COLUMNS and (values % 1 != 0).any():
            raise ValueError(f"{column}: require integer counts or ports.")
        featured[column] = values
    if (featured["flow_duration_s"] <= 0).any():
        raise ValueError("flow_duration_s must be greater than zero.")
    if (featured["packets"] <= 0).any():
        raise ValueError("packets must be greater than zero.")
    if (featured["dst_port"] > 65535).any():
        raise ValueError("dst_port must be between 0 and 65535.")
    for column in ["syn_count", "ack_count", "rst_count"]:
        if (featured[column] > featured["packets"]).any():
            raise ValueError(f"{column} cannot exceed packets.")
    if (featured["unique_dst_ports_60s"] > 65536).any():
        raise ValueError("unique_dst_ports_60s cannot exceed 65536.")
    if (featured["unique_dst_ports_60s"] > featured["connections_60s"]).any():
        raise ValueError(
            "unique_dst_ports_60s cannot exceed connections_60s for the same source/window."
        )
    if "protocol" in featured:
        protocol = featured["protocol"].astype(str).str.upper()
        if (~protocol.isin(["TCP", "UDP"])).any():
            raise ValueError("protocol, when supplied, must be TCP or UDP.")
        udp_flags = featured[["syn_count", "ack_count", "rst_count"]].sum(axis=1)
        if ((protocol == "UDP") & (udp_flags != 0)).any():
            raise ValueError("UDP records cannot contain TCP flag counts.")
        featured["protocol"] = protocol
    duration, packets = featured["flow_duration_s"], featured["packets"]
    featured["packet_rate"] = packets / duration
    featured["byte_rate"] = featured["bytes"] / duration
    featured["avg_packet_size"] = featured["bytes"] / packets
    featured["syn_ratio"] = featured["syn_count"] / packets
    featured["rst_ratio"] = featured["rst_count"] / packets
    featured["is_auth_service"] = (
        featured["dst_port"].isin([21, 22, 23, 3389]).astype(int)
    )
    derived = ["packet_rate", "byte_rate", "avg_packet_size", "syn_ratio", "rst_ratio"]
    if not np.isfinite(featured[derived].to_numpy()).all():
        raise ValueError(
            "Derived features overflowed; check the magnitude of counters and duration."
        )
    return featured


def extract_features(
    flows: pd.DataFrame, service_baselines: dict | None = None
) -> pd.DataFrame:
    from .config import FEATURES

    featured = validate_base(flows)
    featured["ack_ratio"] = featured["ack_count"] / featured["packets"]
    featured["ports_per_connection"] = featured["unique_dst_ports_60s"] / featured[
        "connections_60s"
    ].clip(lower=1)
    featured["packets_per_connection"] = featured["packets"] / featured[
        "connections_60s"
    ].clip(lower=1)
    featured["failure_rate"] = featured["failed_logins"] / featured[
        "connections_60s"
    ].clip(lower=1)
    if "temporal_available" not in featured:
        featured["temporal_available"] = 0
    if not featured.temporal_available.isin([0, 1]).all():
        raise ValueError("temporal_available must be 0 or 1.")
    defaults = {
        "unique_dst_ports_300s": featured.unique_dst_ports_60s,
        "connections_300s": featured.connections_60s,
        "port_entropy_300s": 0.0,
        "new_port_fraction_300s": 0.0,
    }
    for column, default in defaults.items():
        if column not in featured:
            featured[column] = default
        values = pd.to_numeric(featured[column], errors="coerce")
        if not np.isfinite(values.to_numpy(dtype=float)).all() or (values < 0).any():
            raise ValueError(f"{column}: require finite nonnegative context values.")
        featured[column] = values
    if (featured.unique_dst_ports_300s > featured.connections_300s).any():
        raise ValueError("300-second unique ports cannot exceed connection attempts.")
    if (
        (featured.unique_dst_ports_300s % 1 != 0) | (featured.connections_300s % 1 != 0)
    ).any():
        raise ValueError("Temporal counts must be integers.")
    if (featured.unique_dst_ports_300s > 65536).any() or (
        featured.port_entropy_300s > 16
    ).any():
        raise ValueError("Temporal port cardinality or entropy is outside its domain.")
    if (featured.new_port_fraction_300s > 1).any():
        raise ValueError("new_port_fraction_300s must be between 0 and 1.")
    baselines = service_baselines or {}
    denominators = featured.dst_port.map(
        lambda p: baselines.get(str(int(p)), baselines.get("default", 1000.0))
    )
    featured["service_rate_ratio"] = featured.packet_rate / denominators.clip(lower=1)
    if not np.isfinite(featured[FEATURES].to_numpy(dtype=float)).all():
        raise ValueError("Feature overflow or missing numerical evidence.")
    return featured


def fit_service_baselines(training: pd.DataFrame) -> dict:
    featured = validate_base(training)
    benign = featured.loc[featured.label == "benign"]
    if benign.empty:
        raise ValueError("Benign training observations required for service baselines.")
    baselines = {
        str(int(port)): max(float(rows.packet_rate.quantile(0.99)), 1.0)
        for port, rows in benign.groupby("dst_port")
    }
    baselines["default"] = max(float(benign.packet_rate.quantile(0.99)), 1.0)
    return baselines
