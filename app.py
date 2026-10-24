from __future__ import annotations
import io
import json
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from sentinel.config import ARTIFACTS, DATA, RESULTS
from sentinel.model import ContextDetector

st.set_page_config(
    page_title="Sentinel Context IDS", page_icon=":shield:", layout="wide"
)
st.title("Sentinel Context IDS")
st.caption(
    "Context-aware detection | Evidence arbitration | Calibrated uncertainty | Reproducible research"
)


@st.cache_resource
def model(path, modified_ns):
    return ContextDetector.load(path)


def native(value):
    if pd.isna(value):
        return None
    return value.item() if hasattr(value, "item") else value


def fields(frame, columns):
    return frame[[column for column in columns if column in frame]]


with st.sidebar:
    st.header("Analysis source")
    source = st.radio(
        "Choose source",
        [
            "Locked synthetic test",
            "Historical stress diagnostic",
            "Intent ambiguity challenge",
            "Upload flow CSV",
            "Offline packet capture",
        ],
    )
    upload = st.file_uploader(
        "Traffic file",
        type=["csv", "pcap", "pcapng"],
        disabled=source not in ["Upload flow CSV", "Offline packet capture"],
    )
    aggregate = st.checkbox(
        "Reconstruct 60s/300s source history",
        value=False,
        disabled=source != "Upload flow CSV",
    )
    st.caption(
        "History requires complete timestamped source events. Authentication outcomes are optional and explicitly marked unknown when absent."
    )
    st.markdown(
        "[Working concepts and documentation](https://github.com/RishiPlaysCodes/sentinel-context-ids#documentation)"
    )
try:
    if source == "Locked synthetic test":
        predictions = pd.read_csv(RESULTS / "final_predictions.csv")
        description = "Independent synthetic sessions with changed traffic scales. All rows, including review cases, contribute to classification metrics."
    elif source == "Historical stress diagnostic":
        predictions = pd.read_csv(RESULTS / "legacy_stress_predictions.csv")
        description = "Previously observed legacy diagnostic. Improvement here is not an untouched-test or real-network accuracy claim."
    elif source == "Intent ambiguity challenge":
        predictions = pd.read_csv(RESULTS / "indistinguishable_challenge.csv")
        description = "Identical observable administrative traffic with different hidden authorization. A flow-only classifier cannot know intent; investigate the review queue."
    else:
        if upload is None:
            st.info("Upload a compatible flow CSV or an offline PCAP/PCAPNG file.")
            st.stop()
        path = ARTIFACTS / "context_ensemble.joblib"
        detector = model(str(path), path.stat().st_mtime_ns)
        if source == "Offline packet capture":
            from sentinel.capture import read_capture

            with tempfile.TemporaryDirectory(prefix="sentinel-upload-") as directory:
                capture = Path(directory) / "traffic.pcap"
                capture.write_bytes(upload.getvalue())
                frame, quality = read_capture(capture)
            st.json(quality)
        else:
            from sentinel.io import read_flow_csv

            frame = read_flow_csv(upload)
            if aggregate:
                from sentinel.temporal import add_context

                frame = add_context(frame)
        predictions = detector.predict(frame)
        description = "User-supplied observations. Saved benchmark metrics below do not evaluate this input."
    if "flow_id" not in predictions:
        predictions.insert(
            0, "flow_id", [f"upload-{i+1:06d}" for i in range(len(predictions))]
        )
except (ValueError, OSError, KeyError) as exc:
    st.error(f"Input could not be analysed: {exc}")
    st.info(
        "Check docs/DATA_CONTRACT.md. Build missing artifacts with python run_ids.py build."
    )
    st.stop()

st.info(description)
columns = st.columns(4)
for column, label, value in zip(
    columns,
    ["Flows analysed", "Security alerts", "Review items", "Cleared"],
    [
        len(predictions),
        int((predictions.queue == "alert").sum()),
        int((predictions.queue == "review").sum()),
        int((predictions.queue == "clear").sum()),
    ],
):
    column.metric(label, f"{value:,}")
st.caption(
    "Final-class confidence is model support, not certainty of malicious intent. Review items are kept separate from confident security alerts."
)
overview, workbench, scenarios, lab, research = st.tabs(
    [
        "Overview",
        "Evidence workbench",
        "Mandatory scenarios",
        "Research experiments",
        "Working concept",
    ]
)
with overview:
    left, right = st.columns(2)
    with left:
        st.subheader("Predicted classes")
        st.bar_chart(predictions.predicted_label.value_counts())
    with right:
        st.subheader("Decision queues")
        st.bar_chart(predictions.queue.value_counts())
    st.dataframe(
        fields(
            predictions,
            [
                "flow_id",
                "src_ip",
                "dst_ip",
                "dst_port",
                "predicted_label",
                "confidence",
                "queue",
                "review_reasons",
            ],
        ).head(100),
        hide_index=True,
        width="stretch",
    )
with workbench:
    queue = st.selectbox("Decision queue", ["All", "alert", "review", "clear"])
    visible = (
        predictions if queue == "All" else predictions.loc[predictions.queue == queue]
    )
    st.dataframe(
        fields(
            visible,
            ["flow_id", "predicted_label", "confidence", "severity", "queue", "method"],
        ),
        hide_index=True,
        width="stretch",
    )
    if not visible.empty:
        position = st.selectbox(
            "Inspect event",
            list(range(len(visible))),
            format_func=lambda i: str(visible.iloc[i].flow_id),
        )
        row = visible.iloc[position]
        st.write(row.explanation)
        st.json(
            {
                column: native(row[column])
                for column in [
                    "predicted_label",
                    "ml_label",
                    "confidence",
                    "ml_confidence",
                    "prediction_set",
                    "novelty_score",
                    "controlling_rule",
                    "needs_review",
                    "review_reasons",
                    "queue",
                ]
            }
        )
        st.dataframe(
            fields(
                visible.iloc[[position]],
                [
                    "flow_duration_s",
                    "packets",
                    "packet_rate",
                    "ack_ratio",
                    "syn_ratio",
                    "avg_packet_size",
                    "failed_logins",
                    "auth_available",
                    "unique_dst_ports_60s",
                    "unique_dst_ports_300s",
                    "port_entropy_300s",
                    "service_rate_ratio",
                    "temporal_available",
                ],
            ),
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("This queue is empty for the selected source.")
    st.download_button(
        "Download current queue",
        visible.to_csv(index=False),
        "sentinel_queue.csv",
        "text/csv",
    )
with scenarios:
    if not {"label", "scenario"}.issubset(predictions):
        st.info(
            "Ground truth is unavailable for this input. Use the evidence workbench; labels are not invented for uploads."
        )
    else:
        selected = st.selectbox(
            "Scenario", ["benign", "port_scan", "dos", "brute_force", "ambiguous"]
        )
        if selected == "ambiguous":
            subset = predictions.loc[
                (predictions.needs_review)
                | (predictions.label != predictions.predicted_label)
                | (predictions.scenario == "ambiguous")
            ]
        else:
            subset = predictions.loc[predictions.scenario == selected]
        if "scenario_subtype" in subset and not subset.empty:
            subtype = st.selectbox(
                "Traffic profile", ["All"] + sorted(subset.scenario_subtype.unique())
            )
            if subtype != "All":
                subset = subset.loc[subset.scenario_subtype == subtype]
        st.caption(
            f"{len(subset):,} records from the selected analysis source. Ambiguous means a review item, class error, or explicitly labeled challenge."
        )
        counts = (
            pd.concat(
                [
                    subset.label.value_counts().rename("actual"),
                    subset.predicted_label.value_counts().rename("predicted"),
                ],
                axis=1,
            )
            .fillna(0)
            .astype(int)
        )
        st.dataframe(counts, width="stretch")
        st.dataframe(
            fields(
                subset,
                [
                    "flow_id",
                    "scenario_subtype",
                    "label",
                    "predicted_label",
                    "queue",
                    "explanation",
                ],
            ),
            hide_index=True,
            width="stretch",
        )
        if not subset.empty:
            position = st.selectbox(
                "Inspect scenario event",
                list(range(len(subset))),
                format_func=lambda i: str(subset.iloc[i].flow_id),
            )
            st.write(subset.iloc[position].explanation)
with lab:
    st.subheader("Saved research evaluation")
    st.caption(
        "These are reproducible synthetic experiments, regardless of the selected upload/source. Historical stress is a separate known diagnostic."
    )
    try:
        metrics = json.loads((RESULTS / "metrics.json").read_text())
        main = metrics["locked_test"]["sentinel_full"]
        stat = st.columns(4)
        stat[0].metric("All-row accuracy", f'{main["accuracy"]:.2%}')
        stat[1].metric("Macro F1", f'{main["macro_f1"]:.2%}')
        stat[2].metric("Review rate", f'{main["review_rate"]:.2%}')
        stat[3].metric("Accepted coverage", f'{main["accepted_coverage"]:.2%}')
        st.write(
            "Episode-bootstrap 95% accuracy interval:",
            [round(x, 4) for x in main["accuracy_episode_bootstrap_95ci"]],
        )
        comparison = pd.read_csv(RESULTS / "comparison.csv")
        st.dataframe(
            comparison[
                [
                    "experiment",
                    "method",
                    "support",
                    "accuracy",
                    "macro_f1",
                    "class_false_positive_rate",
                    "false_positive_rate",
                    "alert_recall",
                    "investigation_recall",
                    "review_rate",
                    "accepted_coverage",
                    "accepted_accuracy",
                ]
            ],
            hide_index=True,
            width="stretch",
        )
        st.image(
            str(RESULTS / "confusion_matrix.png"),
            caption="All locked-test rows: review cases are not removed from the confusion matrix.",
        )
        st.subheader("Probability diagnostics")
        st.dataframe(pd.DataFrame(metrics["probability_quality"]).T, width="stretch")
        st.caption(
            "Brier/ECE are measured, not assumed to improve after calibration. Calibration does not guarantee real-network probabilities."
        )
        if (RESULTS / "benchmark.csv").exists():
            st.subheader("DoS mixture / batch processing cost")
            st.dataframe(
                pd.read_csv(RESULTS / "benchmark.csv"), hide_index=True, width="stretch"
            )
            st.caption(
                "Three repetitions per mixture; measures inference cost, not victim availability or live link capacity."
            )
    except (OSError, ValueError, KeyError) as exc:
        st.warning(f"Research output unavailable: {exc}")
with research:
    st.subheader("What the system does")
    st.markdown(
        "**Flow evidence -> validation -> causal 60s/300s history -> contextual features -> calibrated tree ensemble + evidence rules -> prediction sets + novelty checks -> alert / review / clear.**"
    )
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Failure mode": "High-rate backup falsely called DoS",
                    "Response": "Corroborate rate with handshake/service evidence; learn broad benign bulk profiles.",
                },
                {
                    "Failure mode": "Slow scan evades short windows",
                    "Response": "Source history across 60 and 300 seconds, port diversity and entropy.",
                },
                {
                    "Failure mode": "Unknown traffic gets confident class",
                    "Response": "Novelty score, calibrated model support and episode-level prediction sets.",
                },
                {
                    "Failure mode": "Missing authentication outcomes treated as success",
                    "Response": "Explicit auth_available flag; review suspected brute force without outcomes.",
                },
                {
                    "Failure mode": "Hidden authorization cannot be inferred",
                    "Response": "Keep fanout intent in review instead of pretending flow counters prove permission.",
                },
                {
                    "Failure mode": "Leakage makes accuracy look perfect",
                    "Response": "Disjoint session/source partitions, development freeze, all-row metrics and baselines.",
                },
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    st.warning(
        "A research integration of established methods; no claim of a world-first algorithm or universal superiority to Suricata/Zeek."
    )
    st.markdown(
        "[Research basis](https://arxiv.org/abs/2402.10974)  |  [Suricata thresholding](https://docs.suricata.io/en/latest/rules/thresholding.html)  |  [Probability calibration](https://scikit-learn.org/1.7/modules/calibration.html)"
    )
