import pandas as pd
import pytest
from sentinel.config import DATA, ARTIFACTS
from sentinel.model import ContextDetector


@pytest.fixture(scope="session")
def detector():
    return ContextDetector.load(ARTIFACTS / "context_ensemble.joblib")


@pytest.fixture(scope="session")
def training():
    return pd.read_csv(DATA / "train.csv")


@pytest.fixture
def minimal():
    return pd.DataFrame(
        [
            dict(
                flow_duration_s=2,
                packets=20,
                bytes=2000,
                syn_count=2,
                ack_count=18,
                rst_count=0,
                failed_logins=0,
                unique_dst_ports_60s=1,
                connections_60s=1,
                dst_port=443,
            )
        ]
    )
