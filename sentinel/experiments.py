from __future__ import annotations
import hashlib
import importlib.metadata
import json
import platform
import time
from pathlib import Path
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from .config import ROOT, DATA, RESULTS, ARTIFACTS, CLASSES, FEATURES
from .data import make_development, make_final_test, make_indistinguishable_challenge
from .model import ContextDetector
from .features import extract_features


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def report_metrics(predictions):
    actual = predictions.label
    predicted = predictions.predicted_label
    precision, recall, f1, _ = precision_recall_fscore_support(
        actual, predicted, average="macro", zero_division=0
    )
    _, _, wf1, _ = precision_recall_fscore_support(
        actual, predicted, average="weighted", zero_division=0
    )
    attack = actual != "benign"
    alert = predictions.is_alert.astype(bool)
    review = (
        predictions.needs_review.astype(bool)
        if "needs_review" in predictions
        else pd.Series(False, index=predictions.index)
    )
    accepted = ~review
    tp = int((attack & alert).sum())
    fp = int((~attack & alert).sum())
    tn = int((~attack & ~alert).sum())
    fn = int((attack & ~alert).sum())
    raw_attack = predicted != "benign"
    investigated = alert | review
    metrics = {
        "class_false_positive_rate": float(
            (~attack & raw_attack).sum() / max((~attack).sum(), 1)
        ),
        "class_attack_recall": float(
            (attack & raw_attack).sum() / max(attack.sum(), 1)
        ),
        "investigation_recall": float(
            (attack & investigated).sum() / max(attack.sum(), 1)
        ),
        "benign_investigation_rate": float(
            (~attack & investigated).sum() / max((~attack).sum(), 1)
        ),
        "support": len(predictions),
        "accuracy": float(accuracy_score(actual, predicted)),
        "macro_precision": float(precision),
        "macro_recall": float(recall),
        "macro_f1": float(f1),
        "weighted_f1": float(wf1),
        "alert_precision": tp / max(tp + fp, 1),
        "alert_recall": tp / max(tp + fn, 1),
        "false_positive_rate": fp / max(fp + tn, 1),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "review_rate": float(review.mean()),
        "accepted_coverage": float(accepted.mean()),
        "accepted_accuracy": (
            float((actual[accepted] == predicted[accepted]).mean())
            if accepted.any()
            else None
        ),
        "classification_report": classification_report(
            actual,
            predicted,
            labels=sorted(set(actual) | set(predicted)),
            output_dict=True,
            zero_division=0,
        ),
    }
    if "prediction_set" in predictions:
        metrics["prediction_set_coverage"] = float(
            np.mean(
                [
                    label in str(values).split("; ")
                    for label, values in zip(actual, predictions.prediction_set)
                ]
            )
        )
    if "session_id" in predictions and predictions.session_id.nunique() > 1:
        episode_accuracy = (
            predictions.assign(correct=actual == predicted)
            .groupby("session_id")
            .correct.mean()
        ).to_numpy()
        rng = np.random.default_rng(700)
        means = rng.choice(
            episode_accuracy, size=(1000, len(episode_accuracy)), replace=True
        ).mean(axis=1)
        metrics["accuracy_episode_bootstrap_95ci"] = [
            float(x) for x in np.quantile(means, [0.025, 0.975])
        ]
    return metrics


def score_legacy(frame):
    from baselines.legacy.detector import HybridDetector

    detector = HybridDetector.load(ROOT / "baselines/legacy_model.joblib")
    result = detector.predict(frame)
    # Preserve its original alert/review policy for a fair frozen baseline.
    return result


def probability_metrics(actual, probabilities, classes):
    target = np.array([[int(label == c) for c in classes] for label in actual])
    top = probabilities.max(axis=1)
    correct = np.array(classes)[probabilities.argmax(axis=1)] == np.asarray(actual)
    ece = 0.0
    for lower in np.linspace(0, 0.9, 10):
        mask = (top >= lower) & (top < lower + 0.1 if lower < 0.9 else top <= 1.0)
        if mask.any():
            ece += float(mask.mean() * abs(correct[mask].mean() - top[mask].mean()))
    return {
        "multiclass_brier": float(
            np.mean(np.sum((probabilities - target) ** 2, axis=1))
        ),
        "top_label_ece_10bins": ece,
    }


def build_development():
    for directory in [DATA, RESULTS, ARTIFACTS]:
        directory.mkdir(exist_ok=True)
    if not (DATA / "legacy_flows.csv").exists():
        from baselines.legacy.data_generation import generate_dataset

        generate_dataset().to_csv(DATA / "legacy_flows.csv", index=False)
    if not (ROOT / "baselines/legacy_model.joblib").exists():
        from baselines.legacy.detector import HybridDetector

        legacy = pd.read_csv(DATA / "legacy_flows.csv")
        clear = legacy.loc[~legacy.is_ambiguous]
        baseline_train, _ = train_test_split(
            clear, test_size=0.25, stratify=clear.label, random_state=42
        )
        HybridDetector.train(baseline_train).save(
            ROOT / "baselines/legacy_model.joblib"
        )
    partitions = make_development()
    for name, frame in partitions.items():
        frame.to_csv(DATA / f"{name}.csv", index=False)
    models = {}
    for name, contextual in [("core_ensemble", False), ("context_ensemble", True)]:
        model = ContextDetector.train(
            *(
                partitions[key]
                for key in [
                    "train",
                    "probability_calibration",
                    "conformal_calibration",
                    "validation",
                ]
            ),
            contextual=contextual,
        )
        model.save(ARTIFACTS / f"{name}.joblib")
        models[name] = model
    validation = models["context_ensemble"].predict(partitions["validation"])
    validation.to_csv(RESULTS / "validation_predictions.csv", index=False)
    validation_metrics = report_metrics(validation)
    (RESULTS / "validation_metrics.json").write_text(
        json.dumps(validation_metrics, indent=2), encoding="utf-8"
    )
    manifest = pd.concat(
        [
            frame[["flow_id", "session_id", "partition"]]
            for frame in partitions.values()
        ],
        ignore_index=True,
    )
    manifest.to_csv(RESULTS / "development_manifest.csv", index=False)
    frozen = {
        "study_plan_sha256": file_hash(ROOT / "docs/STUDY_PLAN.json"),
        "development_data_sha256": {
            name: file_hash(DATA / f"{name}.csv") for name in partitions
        },
        "models": {
            name: {
                "sha256": file_hash(ARTIFACTS / f"{name}.joblib"),
                "parameters": model.metadata,
            }
            for name, model in models.items()
        },
        "decision_code_sha256": {
            name: file_hash(ROOT / "sentinel" / name)
            for name in [
                "data.py",
                "features.py",
                "model.py",
                "rules.py",
                "temporal.py",
            ]
        },
        "final_data_generated_in_this_step": False,
    }
    (RESULTS / "frozen_development.json").write_text(
        json.dumps(frozen, indent=2), encoding="utf-8"
    )
    return validation_metrics


def evaluate_final():
    frozen = json.loads((RESULTS / "frozen_development.json").read_text())
    if file_hash(ROOT / "docs/STUDY_PLAN.json") != frozen["study_plan_sha256"]:
        raise ValueError("Study plan changed after development freeze.")
    for name, record in frozen["models"].items():
        if file_hash(ARTIFACTS / f"{name}.joblib") != record["sha256"]:
            raise ValueError("Model changed after development freeze.")
    for name, digest in frozen["decision_code_sha256"].items():
        if file_hash(ROOT / "sentinel" / name) != digest:
            raise ValueError("Decision code changed after development freeze.")
    model = ContextDetector.load(ARTIFACTS / "context_ensemble.joblib")
    core = ContextDetector.load(ARTIFACTS / "core_ensemble.joblib")
    test = make_final_test()
    development = pd.read_csv(RESULTS / "development_manifest.csv")
    if set(test.session_id) & set(development.session_id):
        raise ValueError("Final sessions overlap development.")
    if set(test.src_ip) & set(
        pd.concat(
            [
                pd.read_csv(DATA / f"{name}.csv")
                for name in [
                    "train",
                    "probability_calibration",
                    "conformal_calibration",
                    "validation",
                ]
            ]
        ).src_ip
    ):
        raise ValueError("Final source identities overlap development.")
    test.to_csv(DATA / "final_test.csv", index=False)
    comparisons = []
    evaluations = {}
    full = None
    for name, method in [
        ("frozen_v2", lambda f: score_legacy(f)),
        ("core_ensemble", lambda f: core.predict(f, policy=False)),
        ("context_ensemble", lambda f: model.predict(f, policy=False)),
        ("sentinel_full", lambda f: model.predict(f, policy=True)),
    ]:
        start = time.perf_counter()
        pred = method(test)
        elapsed = time.perf_counter() - start
        block = report_metrics(pred)
        block["inference_seconds"] = elapsed
        block["flows_per_second"] = len(test) / elapsed
        evaluations[name] = block
        comparisons.append(
            {
                "experiment": "locked_synthetic_test",
                "method": name,
                **{k: v for k, v in block.items() if not isinstance(v, (dict, list))},
            }
        )
        if name == "sentinel_full":
            full = pred
    full.to_csv(RESULTS / "final_predictions.csv", index=False)
    full.loc[full.queue == "alert"].to_csv(RESULTS / "alerts.csv", index=False)
    full.loc[full.queue == "review"].to_csv(RESULTS / "review_queue.csv", index=False)
    full.groupby(
        ["scenario", "scenario_subtype", "label", "predicted_label", "queue"]
    ).size().reset_index(name="count").to_csv(
        RESULTS / "scenario_summary.csv", index=False
    )
    # Known historical data is reported separately and is never called untouched validation.
    legacy = pd.read_csv(DATA / "legacy_flows.csv")
    clear = legacy.loc[~legacy.is_ambiguous]
    _, holdout = train_test_split(
        clear, test_size=0.25, stratify=clear.label, random_state=42
    )
    historical = {}
    for population, frame in [
        ("legacy_clear", holdout),
        ("legacy_stress", legacy.loc[legacy.is_ambiguous]),
    ]:
        for name, method in [
            ("frozen_v2", score_legacy),
            ("sentinel_full", model.predict),
        ]:
            pred = method(frame)
            block = report_metrics(pred)
            historical[f"{population}/{name}"] = block
            comparisons.append(
                {
                    "experiment": population,
                    "method": name,
                    **{
                        k: v
                        for k, v in block.items()
                        if not isinstance(v, (dict, list))
                    },
                }
            )
            if population == "legacy_stress" and name == "sentinel_full":
                pred.to_csv(RESULTS / "legacy_stress_predictions.csv", index=False)
    challenge = model.predict(make_indistinguishable_challenge())
    challenge.to_csv(RESULTS / "indistinguishable_challenge.csv", index=False)
    challenge_metrics = report_metrics(challenge)
    # Exact same observable feature vectors have contradictory labels; do not optimize this to a fabricated 100%.
    matrix = confusion_matrix(full.label, full.predicted_label, labels=CLASSES)
    fig, ax = plt.subplots(figsize=(7.2, 5.4))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=CLASSES,
        yticklabels=CLASSES,
        ax=ax,
    )
    ax.set(
        title="Locked synthetic test: all rows, including review items",
        xlabel="Predicted class",
        ylabel="Actual class",
    )
    fig.tight_layout()
    fig.savefig(RESULTS / "confusion_matrix.png", dpi=180)
    plt.close(fig)
    pd.DataFrame(comparisons).to_csv(RESULTS / "comparison.csv", index=False)
    x = extract_features(test, model.service_baselines)[model.feature_columns]
    calibrated = model.estimator.predict_proba(x)
    uncalibrated = model.estimator.estimator.estimator.predict_proba(x)
    probability_quality = {
        "uncalibrated": probability_metrics(
            test.label, uncalibrated, list(model.estimator.classes_)
        ),
        "calibrated": probability_metrics(
            test.label, calibrated, list(model.estimator.classes_)
        ),
    }
    package_names = [
        "numpy",
        "pandas",
        "scikit-learn",
        "scipy",
        "streamlit",
        "scapy",
        "joblib",
    ]
    metrics = {
        "scope": "Independent synthetic sessions and a scale-shifted domain, not a public real-network benchmark.",
        "locked_test_sha256": file_hash(DATA / "final_test.csv"),
        "development_freeze_sha256": file_hash(RESULTS / "frozen_development.json"),
        "locked_test": evaluations,
        "probability_quality": probability_quality,
        "historical_diagnostic": historical,
        "indistinguishable_challenge": challenge_metrics,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "packages": {p: importlib.metadata.version(p) for p in package_names},
        },
    }
    (RESULTS / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    return metrics
