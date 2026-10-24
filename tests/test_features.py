import numpy as np
import pandas as pd
import pytest
from sentinel.features import extract_features, fit_service_baselines


@pytest.mark.parametrize(
    "column,value",
    [
        ("flow_duration_s", 0),
        ("flow_duration_s", -1),
        ("packets", 0),
        ("packets", -1),
        ("bytes", -1),
        ("failed_logins", -1),
        ("packets", 1.5),
        ("dst_port", 65536),
        ("dst_port", -1),
        ("syn_count", 21),
        ("ack_count", 21),
        ("rst_count", 21),
        ("packets", np.inf),
        ("flow_duration_s", "bad"),
        ("bytes", np.nan),
        ("unique_dst_ports_60s", 2),
        ("auth_available", 3),
        ("temporal_available", 2),
        ("unique_dst_ports_300s", 2),
        ("port_entropy_300s", 17),
        ("new_port_fraction_300s", 1.01),
    ],
)
def test_invalid_values_rejected(minimal, column, value):
    minimal[column] = value
    with pytest.raises(ValueError):
        extract_features(minimal)


def test_required_and_empty_errors(minimal):
    with pytest.raises(ValueError, match="Missing required"):
        extract_features(minimal.drop(columns="packets"))
    with pytest.raises(ValueError, match="no flow records"):
        extract_features(minimal.iloc[:0])


def test_authentication_missing_is_explicit(minimal):
    frame = extract_features(minimal.drop(columns="failed_logins"))
    assert frame.auth_available.iloc[0] == 0
    assert frame.failed_logins.iloc[0] == 0


def test_unknown_authentication_cannot_assert_failures(minimal):
    minimal["auth_available"] = 0
    minimal["failed_logins"] = 8
    with pytest.raises(ValueError, match="Unavailable authentication"):
        extract_features(minimal)


def test_numeric_strings_normalize(minimal):
    row = extract_features(minimal.astype(str)).iloc[0]
    assert row.packet_rate == 10 and row.ack_ratio == 0.9 and row.is_auth_service == 0


def test_udp_flag_consistency(minimal):
    minimal["protocol"] = "UDP"
    with pytest.raises(ValueError, match="UDP"):
        extract_features(minimal)


def test_feature_values(minimal):
    row = extract_features(minimal).iloc[0]
    assert row.avg_packet_size == 100 and row.syn_ratio == 0.1 and row.failure_rate == 0


def test_service_baseline_fits_benign_only(minimal):
    normal = minimal.assign(label="benign")
    attack = minimal.assign(label="dos", packets=1000000)
    baseline = fit_service_baselines(pd.concat([normal, attack]))
    assert baseline["443"] == 10


def test_original_duplicate_csv_headers_are_rejected():
    import io
    from sentinel.io import read_flow_csv

    with pytest.raises(ValueError, match="Duplicate CSV"):
        read_flow_csv(io.StringIO("packets,packets\n1,2\n"))


def test_utf8_bom_csv_is_supported():
    import io
    from sentinel.io import read_flow_csv

    assert read_flow_csv(io.BytesIO(b"\xef\xbb\xbfpackets\n2\n")).packets.iloc[0] == 2
