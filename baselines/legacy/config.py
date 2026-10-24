from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
ARTIFACT_DIR = PROJECT_ROOT / "artifacts"
RESULTS_DIR = PROJECT_ROOT / "results"

RANDOM_SEED = 42

FEATURE_COLUMNS = [
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
    "rst_ratio",
    "is_auth_service",
]

CLASS_ORDER = ["benign", "port_scan", "dos", "brute_force"]

