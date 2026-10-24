from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import (
    ExtraTreesClassifier,
    RandomForestClassifier,
    VotingClassifier,
    IsolationForest,
)
from sklearn.frozen import FrozenEstimator
from .config import CLASSES, FEATURES, CORE_FEATURES
from .features import extract_features, fit_service_baselines
from .rules import rules, bulk_evidence

FORMAT_VERSION = 3


def group_conformal_limits(calibration, probabilities, classes, alpha=0.1):
    """One nonconformity score per independent episode: worst member probability."""
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between zero and one.")
    scores = []
    for i, (_, row) in enumerate(calibration.iterrows()):
        scores.append(
            {
                "session_id": row.session_id,
                "label": row.label,
                "score": 1 - float(probabilities[i, classes.index(row.label)]),
            }
        )
    groups = (
        pd.DataFrame(scores).groupby(["session_id", "label"]).score.max().reset_index()
    )
    limits = {}
    for label in classes:
        values = np.sort(groups.loc[groups.label == label, "score"].to_numpy())
        rank = int(np.ceil((len(values) + 1) * (1 - alpha)))
        limits[label] = float(values[rank - 1]) if rank <= len(values) else 1.0
    return limits


@dataclass
class ContextDetector:
    estimator: object
    service_baselines: dict
    conformal_limits: dict
    novelty: object
    novelty_cutoff: float
    review_threshold: float
    class_medians: dict
    feature_columns: list = field(default_factory=lambda: list(FEATURES))
    metadata: dict = field(default_factory=dict)

    @classmethod
    def train(
        cls,
        training,
        probability_calibration,
        conformal_calibration,
        validation,
        contextual=True,
    ):
        frames = [training, probability_calibration, conformal_calibration, validation]
        seen = set()
        for frame in frames:
            if set(frame.label) != set(CLASSES):
                raise ValueError(
                    "Every development partition requires all four classes."
                )
            ids = set(frame.session_id)
            if seen.intersection(ids):
                raise ValueError("Session leakage across development partitions.")
            seen.update(ids)
        baselines = fit_service_baselines(training)
        columns = list(FEATURES if contextual else CORE_FEATURES)
        transformed = [extract_features(frame, baselines) for frame in frames]
        xtrain, xprob, xconf, xvalid = [frame[columns] for frame in transformed]
        forest = RandomForestClassifier(
            n_estimators=220,
            max_depth=16,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=1,
        )
        extra = ExtraTreesClassifier(
            n_estimators=220,
            max_depth=18,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=43,
            n_jobs=1,
        )
        ensemble = VotingClassifier(
            [("forest", forest), ("extra", extra)], voting="soft", n_jobs=1
        )
        ensemble.fit(xtrain, training.label)
        calibrated = CalibratedClassifierCV(FrozenEstimator(ensemble), method="sigmoid")
        calibrated.fit(xprob, probability_calibration.label)
        classes = list(calibrated.classes_)
        limits = group_conformal_limits(
            conformal_calibration, calibrated.predict_proba(xconf), classes
        )
        novelty = IsolationForest(
            n_estimators=160, contamination="auto", random_state=44, n_jobs=1
        )
        novelty.fit(np.log1p(xtrain.to_numpy(dtype=float)))
        cutoff = float(
            np.quantile(
                novelty.score_samples(np.log1p(xconf.to_numpy(dtype=float))), 0.005
            )
        )
        p = calibrated.predict_proba(xvalid)
        correct = np.asarray(classes)[p.argmax(axis=1)] == validation.label.to_numpy()
        threshold = 0.9
        for candidate in [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]:
            accepted = p.max(axis=1) >= candidate
            if accepted.mean() >= 0.5 and correct[accepted].mean() >= 0.98:
                threshold = candidate
                break
        medians = {
            label: transformed[0]
            .loc[training.label == label, columns]
            .median()
            .to_dict()
            for label in classes
        }
        metadata = {
            "model_format": FORMAT_VERSION,
            "classes": classes,
            "features": columns,
            "training_sessions": len(set(training.session_id)),
            "training_rows": len(training),
            "probability_calibration_rows": len(probability_calibration),
            "conformal_calibration_sessions": len(
                set(conformal_calibration.session_id)
            ),
            "validation_rows": len(validation),
            "conformal_alpha": 0.1,
            "review_threshold": threshold,
            "novelty_cutoff": cutoff,
            "hyperparameters": {
                "forest_trees": 220,
                "extra_trees": 220,
                "novelty_trees": 160,
            },
            "final_test_used_for_fitting": False,
        }
        return cls(
            calibrated,
            baselines,
            limits,
            novelty,
            cutoff,
            threshold,
            medians,
            columns,
            metadata,
        )

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"format_version": FORMAT_VERSION, "detector": self}, path)
        return path

    @classmethod
    def load(cls, path):
        payload = joblib.load(path)
        if payload.get("format_version") != FORMAT_VERSION:
            raise ValueError("Unsupported artifact; rebuild this project.")
        return payload["detector"]

    def predict(self, flows, policy=True):
        frame = extract_features(flows, self.service_baselines)
        x = frame[self.feature_columns]
        probabilities = self.estimator.predict_proba(x)
        classes = list(self.estimator.classes_)
        novelty_scores = self.novelty.score_samples(np.log1p(x.to_numpy(dtype=float)))
        output = []
        for i, (_, row) in enumerate(frame.iterrows()):
            distribution = probabilities[i]
            ml = classes[int(np.argmax(distribution))]
            top = float(np.max(distribution))
            predicted = ml
            matched = rules(row) if policy else []
            conformal = [
                label
                for j, label in enumerate(classes)
                if 1 - distribution[j] <= self.conformal_limits[label]
            ]
            reasons = []
            method = "calibrated_ensemble"
            control = "none"
            if top < self.review_threshold:
                reasons.append("low_probability")
            if len(conformal) != 1:
                reasons.append(
                    "ambiguous_prediction_set" if conformal else "empty_prediction_set"
                )
            if novelty_scores[i] < self.novelty_cutoff:
                reasons.append("unfamiliar_feature_distribution")
            if row.get("context_truncated", False):
                reasons.append("truncated_temporal_context")
            if row.get("capture_incomplete", False):
                reasons.append("capture_incomplete")
            if matched:
                selected = matched[0]
                if selected.label == ml:
                    method = "context_rule+ensemble"
                    control = selected.name
                elif top < 0.85:
                    predicted = selected.label
                    method = "context_rule_override"
                    control = selected.name
                    reasons.append("rule_model_disagreement")
                else:
                    method = "conflicting_evidence_review"
                    reasons.append("rule_model_disagreement")
            if (
                row.temporal_available
                and row.unique_dst_ports_300s >= 8
                and row.ack_ratio >= 0.65
                and predicted == "benign"
            ):
                reasons.append("fanout_authorization_not_observable")
            if predicted == "brute_force" and not row.auth_available:
                reasons.append("authentication_outcomes_unavailable")
            if not row.temporal_available and predicted == "port_scan":
                reasons.append("temporal_context_unavailable")
            final_probability = float(distribution[classes.index(predicted)])
            needs_review = bool(reasons)
            # Review is a distinct work queue; do not present reviewed cases as confident security alerts.
            queue = (
                "review"
                if needs_review
                else ("clear" if predicted == "benign" else "alert")
            )
            severity = (
                "medium"
                if needs_review
                else ("none" if predicted == "benign" else "high")
            )
            if queue == "alert" and any(
                e.severity == "critical" and e.label == predicted for e in matched
            ):
                severity = "critical"
            evidence = [f"{e.name}: {e.reason}" for e in matched]
            if bulk_evidence(row):
                evidence.append(
                    "G1_BULK_CONTEXT: high ACK ratio and large packets on few ports; high rate alone does not prove DoS."
                )
            evidence.append(
                f"Calibrated ensemble: {ml} at {top:.1%}; final={predicted}; decision={method}; controlling rule={control}."
            )
            evidence.append(
                "Class-conditional episode-calibrated prediction set: "
                + (", ".join(conformal) or "empty")
                + "."
            )
            if reasons:
                evidence.append("Review reasons: " + ", ".join(reasons) + ".")
            if not row.auth_available:
                evidence.append(
                    "Authentication outcome is unknown, not a confirmed zero-failure observation."
                )
            record = row.to_dict()
            record.update(
                predicted_label=predicted,
                ml_label=ml,
                ml_confidence=round(top, 6),
                confidence=round(final_probability, 6),
                benign_probability=round(
                    float(distribution[classes.index("benign")]), 6
                ),
                method=method,
                controlling_rule=control,
                rule_matches="; ".join(e.name for e in matched) or "none",
                prediction_set="; ".join(conformal),
                novelty_score=float(novelty_scores[i]),
                needs_review=needs_review,
                review_reasons="; ".join(reasons),
                queue=queue,
                severity=severity,
                is_alert=queue == "alert",
                explanation=" | ".join(evidence),
            )
            output.append(record)
        return pd.DataFrame(output)
