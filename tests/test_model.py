import hashlib
import json
import numpy as np
import pandas as pd
import pytest
from sentinel.config import DATA, RESULTS, ROOT, FEATURES, CLASSES
from sentinel.features import extract_features
from sentinel.model import ContextDetector, group_conformal_limits
from sentinel.rules import rules, bulk_evidence


def test_serialization_round_trip(detector, minimal, tmp_path):
    before = detector.predict(minimal)
    restored = ContextDetector.load(detector.save(tmp_path / "model.joblib"))
    pd.testing.assert_frame_equal(before, restored.predict(minimal))


def test_ground_truth_and_metadata_do_not_affect_prediction(detector, minimal):
    first = detector.predict(minimal)
    second = detector.predict(
        minimal.assign(label="dos", scenario="dos", session_id="attacker")
    )
    assert first.predicted_label.tolist() == second.predicted_label.tolist()
    assert first.confidence.tolist() == second.confidence.tolist()


def test_review_and_alert_queues_have_consistent_semantics(detector, training):
    out = detector.predict(training.groupby("label").head(12))
    assert not (out.needs_review & out.is_alert).any()
    assert out.confidence.between(0, 1).all()
    assert set(out.queue).issubset({"clear", "alert", "review"})
    assert (out.loc[out.is_alert, "predicted_label"] != "benign").all()


def test_missing_auth_for_suspected_brute_force_is_reviewed(detector, training):
    rows = (
        training.loc[(training.label == "brute_force") & (training.auth_available == 1)]
        .head(12)
        .copy()
    )
    rows["auth_available"] = 0
    rows["failed_logins"] = 0
    out = detector.predict(rows)
    suspected = out.loc[out.predicted_label == "brute_force"]
    assert len(suspected) > 0
    assert suspected.review_reasons.str.contains(
        "authentication_outcomes_unavailable"
    ).all()


def test_high_rate_alone_is_not_flood_evidence(minimal):
    minimal["packets"] = 5000
    minimal["flow_duration_s"] = 1
    minimal["bytes"] = 6500000
    minimal["syn_count"] = 2
    minimal["ack_count"] = 4990
    row = extract_features(minimal).iloc[0]
    assert bulk_evidence(row)
    assert not any(e.label == "dos" for e in rules(row))


def test_persistent_scan_rule_uses_long_window(minimal):
    minimal["unique_dst_ports_300s"] = 10
    minimal["connections_300s"] = 10
    minimal["new_port_fraction_300s"] = 1
    minimal["port_entropy_300s"] = 3.3
    minimal["temporal_available"] = 1
    minimal["ack_count"] = 0
    minimal["syn_count"] = 15
    assert any(
        e.name == "R2_PERSISTENT_SCAN" for e in rules(extract_features(minimal).iloc[0])
    )


def test_training_partitions_reject_leakage(training):
    with pytest.raises(ValueError, match="Session leakage"):
        ContextDetector.train(training, training, training, training)


def test_conformal_scores_use_episode_maximum():
    frame = pd.DataFrame({"session_id": ["a", "a", "b", "b"], "label": ["benign"] * 4})
    probabilities = np.array([[0.9, 0.1], [0.5, 0.5], [0.8, 0.2], [0.7, 0.3]])
    limits = group_conformal_limits(frame, probabilities, ["benign"], alpha=0.5)
    assert limits["benign"] == 0.5


def test_models_and_decision_code_match_frozen_development():
    frozen = json.loads((RESULTS / "frozen_development.json").read_text())
    for name, digest in frozen["decision_code_sha256"].items():
        assert (
            hashlib.sha256((ROOT / "sentinel" / name).read_bytes()).hexdigest()
            == digest
        )
    for name, record in frozen["models"].items():
        assert (
            hashlib.sha256(
                (ROOT / "artifacts" / f"{name}.joblib").read_bytes()
            ).hexdigest()
            == record["sha256"]
        )


def test_final_sources_and_sessions_are_independent(training):
    test = pd.read_csv(DATA / "final_test.csv")
    assert set(test.src_ip).isdisjoint(training.src_ip)
    development = pd.read_csv(RESULTS / "development_manifest.csv")
    assert set(test.session_id).isdisjoint(development.session_id)
    assert not set(FEATURES) & {
        "label",
        "scenario",
        "src_ip",
        "session_id",
        "partition",
    }


def test_observable_challenge_is_not_falsely_perfect():
    out = pd.read_csv(RESULTS / "indistinguishable_challenge.csv")
    assert (out.label == out.predicted_label).mean() <= 0.5
    assert len(out) == 24


def test_unfamiliar_extreme_observation_is_reviewed(detector, minimal):
    minimal["packets"] = 1000000000
    minimal["bytes"] = 1000000000000000
    minimal["flow_duration_s"] = 0.000000001
    minimal["connections_60s"] = 1000000
    minimal["unique_dst_ports_60s"] = 65536
    minimal["syn_count"] = 100000000
    minimal["ack_count"] = 800000000
    out = detector.predict(minimal).iloc[0]
    assert out.needs_review and "unfamiliar_feature_distribution" in out.review_reasons
