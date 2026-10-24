"""Causal source-window aggregation from timestamped flow observations, with bounded history."""

from collections import Counter, deque
import math
import numpy as np
import pandas as pd


def add_context(
    events: pd.DataFrame, max_events_per_source=10000, max_sources=4096
) -> pd.DataFrame:
    required = {"timestamp", "src_ip", "dst_port"}
    if not required.issubset(events):
        raise ValueError(
            "Temporal aggregation requires timestamp, src_ip and dst_port."
        )
    if events.empty:
        raise ValueError("No events to aggregate.")
    frame = events.copy().reset_index(drop=True)
    timestamps = pd.to_datetime(
        frame.timestamp, utc=True, format="ISO8601", errors="coerce"
    )
    if timestamps.isna().any():
        raise ValueError("Invalid event timestamp.")
    frame["_time"] = timestamps.astype("int64") / 1e9
    if max_events_per_source < 1:
        raise ValueError("History limit must be positive.")
    histories, output = {}, []
    for index, row in frame.sort_values("_time", kind="stable").iterrows():
        source, now, port = str(row.src_ip), float(row["_time"]), int(row.dst_port)
        if source not in histories and len(histories) >= max_sources:
            raise ValueError(
                "Source history capacity exceeded; partition the input or raise the explicit limit."
            )
        history = histories.setdefault(source, deque())
        while history and now - history[0][0] > 300:
            history.popleft()
        history.append((now, port))
        truncated = len(history) > max_events_per_source
        if truncated:
            history.popleft()
        recent = [p for t, p in history if now - t <= 60]
        counts = Counter(p for _, p in history)
        total = len(history)
        entropy = -sum((n / total) * math.log2(n / total) for n in counts.values())
        output.append(
            {
                "_index": index,
                "unique_dst_ports_60s": len(set(recent)),
                "connections_60s": len(recent),
                "unique_dst_ports_300s": len(counts),
                "connections_300s": total,
                "port_entropy_300s": entropy,
                "new_port_fraction_300s": len(counts) / total,
                "temporal_available": 1,
                "context_truncated": truncated,
            }
        )
    values = pd.DataFrame(output).set_index("_index").reindex(frame.index)
    frame = frame.drop(columns=["_time"] + [c for c in values if c in frame])
    return pd.concat([frame, values], axis=1)
