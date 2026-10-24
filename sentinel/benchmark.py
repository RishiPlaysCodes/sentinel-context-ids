from pathlib import Path
import json
import statistics
import time
import pandas as pd
from .config import DATA, RESULTS, ARTIFACTS
from .model import ContextDetector


def run_benchmark(sizes=(100, 500, 2000), repeats=3):
    if repeats < 1 or any(size < 2 for size in sizes):
        raise ValueError("Require positive repeats and batch sizes >=2.")
    model = ContextDetector.load(ARTIFACTS / "context_ensemble.joblib")
    data = pd.read_csv(DATA / "validation.csv")
    benign = data.loc[data.label == "benign"]
    dos = data.loc[data.label == "dos"]
    model.predict(benign.head(10))
    rows = []
    for size in sizes:
        for fraction in [0, 0.5, 1.0]:
            count = round(size * fraction)
            frame = pd.concat(
                [
                    benign.sample(size - count, replace=True, random_state=700),
                    dos.sample(count, replace=True, random_state=701),
                ],
                ignore_index=True,
            )
            durations = []
            for _ in range(repeats):
                start = time.perf_counter()
                model.predict(frame)
                durations.append(time.perf_counter() - start)
            median = statistics.median(durations)
            rows.append(
                dict(
                    flows=size,
                    dos_fraction=fraction,
                    repeats=repeats,
                    median_seconds=median,
                    min_seconds=min(durations),
                    max_seconds=max(durations),
                    flows_per_second=size / median,
                    amortized_ms_per_flow=median * 1000 / size,
                )
            )
    path = RESULTS / "benchmark.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    (RESULTS / "benchmark_scope.json").write_text(
        json.dumps(
            {
                "timing_includes": "CSV-frame validation, features, calibrated ensemble, novelty score, evidence rules and explanations",
                "excludes": "CSV read and temporal aggregation: supplied context is reused for this inference workload",
                "not_measured": [
                    "live packet loss",
                    "victim availability",
                    "network latency",
                    "sustained link throughput",
                ],
                "warmup_rows": 10,
                "sample_seeds": [700, 701],
                "population": "development validation; no efficacy claim from benchmark",
            },
            indent=2,
        )
    )
    return path
