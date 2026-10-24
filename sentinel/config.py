from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "results"
ARTIFACTS = ROOT / "artifacts"
CLASSES = ["benign", "port_scan", "dos", "brute_force"]
SEEDS = {
    "train": 42,
    "probability_calibration": 43,
    "conformal_calibration": 44,
    "validation": 45,
    "final_test": 20261025,
}
AUTH_PORTS = {21, 22, 23, 3389}
CORE_FEATURES = [
    "flow_duration_s",
    "packets",
    "bytes",
    "syn_count",
    "ack_count",
    "rst_count",
    "failed_logins",
    "unique_dst_ports_60s",
    "connections_60s",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "is_auth_service",
    "ports_per_connection",
    "packets_per_connection",
    "failure_rate",
    "auth_available",
]
CONTEXT_FEATURES = [
    "unique_dst_ports_300s",
    "connections_300s",
    "port_entropy_300s",
    "new_port_fraction_300s",
    "service_rate_ratio",
    "temporal_available",
]
FEATURES = CORE_FEATURES + CONTEXT_FEATURES
