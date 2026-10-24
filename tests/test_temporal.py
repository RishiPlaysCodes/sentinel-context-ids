import pandas as pd
import pytest
from sentinel.temporal import add_context


def events():
    return pd.DataFrame(
        dict(
            timestamp=[
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:30.500Z",
                "2026-01-01T00:02:00Z",
                "2026-01-01T00:06:00Z",
            ],
            src_ip=["a"] * 4,
            dst_port=[22, 80, 443, 53],
        )
    )


def test_causal_windows_and_expiry():
    out = add_context(events())
    assert out.connections_60s.tolist() == [1, 2, 1, 1]
    assert out.unique_dst_ports_300s.tolist() == [1, 2, 3, 2]
    assert out.port_entropy_300s.iloc[1] == 1


def test_future_events_do_not_change_past():
    whole = add_context(events())
    prefix = add_context(events().head(2))
    pd.testing.assert_frame_equal(whole.head(2), prefix)


def test_sorting_does_not_change_row_identity():
    frame = events().iloc[::-1].reset_index(drop=True)
    out = add_context(frame)
    assert out.timestamp.tolist() == frame.timestamp.tolist()
    assert out.connections_300s.tolist() == [2, 3, 2, 1]


def test_sources_are_separate():
    frame = events()
    frame.loc[1, "src_ip"] = "b"
    assert add_context(frame).connections_300s.iloc[1] == 1


def test_bounded_history_marks_truncation():
    out = add_context(events(), max_events_per_source=2)
    assert out.context_truncated.iloc[2]
    assert out.connections_300s.max() == 2


def test_capacity_and_invalid_timestamps():
    frame = events()
    frame.loc[1, "src_ip"] = "b"
    with pytest.raises(ValueError, match="capacity"):
        add_context(frame, max_sources=1)
    frame.loc[0, "timestamp"] = "bad"
    with pytest.raises(ValueError, match="timestamp"):
        add_context(frame)
