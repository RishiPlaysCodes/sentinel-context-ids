from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from .config import CLASS_ORDER, FEATURE_COLUMNS, RANDOM_SEED
from .features import extract_features
from .rules import evaluate_rules

MODEL_FORMAT_VERSION = 2
ML_REVIEW_THRESHOLD = 0.60


@dataclass
class HybridDetector:
    model: RandomForestClassifier
    class_medians: dict[str, dict[str, float]]

    @classmethod
    def train(cls, flows: pd.DataFrame) -> 'HybridDetector':
        if 'label' not in flows:
            raise ValueError('Training requires a label column.')
        featured = extract_features(flows)
        if 'is_ambiguous' in featured:
            if not featured['is_ambiguous'].isin([True, False]).all():
                raise ValueError('is_ambiguous must contain boolean values.')
            clear = featured.loc[~featured['is_ambiguous'].astype(bool)].copy()
        else:
            clear = featured
        if set(clear['label']) != set(CLASS_ORDER):
            raise ValueError(f'Training requires all four labels: {CLASS_ORDER}.')
        model = RandomForestClassifier(
            n_estimators=240, max_depth=12, min_samples_leaf=2,
            class_weight='balanced_subsample', random_state=RANDOM_SEED, n_jobs=1,
        )
        model.fit(clear[FEATURE_COLUMNS], clear['label'])
        medians = {
            label: clear.loc[clear['label'] == label, FEATURE_COLUMNS].median().to_dict()
            for label in CLASS_ORDER
        }
        return cls(model, medians)

    @classmethod
    def load(cls, path: str | Path) -> 'HybridDetector':
        # Joblib is pickle-based. Only load this project's locally built/trusted artifacts.
        payload = joblib.load(path)
        if payload.get('format_version') != MODEL_FORMAT_VERSION:
            raise ValueError('Unsupported model artifact. Run python run_ids.py build.')
        if payload.get('feature_columns') != FEATURE_COLUMNS:
            raise ValueError('Model feature schema mismatch. Rebuild the model.')
        return cls(payload['model'], payload['class_medians'])

    def save(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            'format_version': MODEL_FORMAT_VERSION, 'feature_columns': FEATURE_COLUMNS,
            'model': self.model, 'class_medians': self.class_medians,
        }, output)
        return output

    def _ml_explanation(self, row: pd.Series, label: str, probability: float) -> str:
        medians = self.class_medians[label]
        # A unit floor avoids an arbitrarily large ratio for a near-zero median.
        ranked = sorted(
            ((abs(float(row[f]) - medians[f]) / max(abs(medians[f]), 1.0), f)
             for f in FEATURE_COLUMNS), reverse=True,
        )
        values = ', '.join(f'{f}={float(row[f]):.2f}' for _, f in ranked[:3])
        return (f'ML top class {label} at {probability:.1%}; largest normalized deviations '
                f'from that class median: {values}. These are descriptive values, not model attributions.')

    def predict(self, flows: pd.DataFrame) -> pd.DataFrame:
        featured = extract_features(flows)
        probabilities = self.model.predict_proba(featured[FEATURE_COLUMNS])
        classes = list(self.model.classes_)
        records = []
        for position, (_, row) in enumerate(featured.iterrows()):
            distribution = probabilities[position]
            ml_label = classes[int(np.argmax(distribution))]
            ml_confidence = float(np.max(distribution))
            matches = evaluate_rules(row)
            controlling = matches[0] if matches else None
            if controlling:
                predicted = controlling.label
                method = 'rule+ml_agreement' if predicted == ml_label else 'rule_override'
                severity = controlling.severity
                needs_review = predicted != ml_label or ml_confidence < ML_REVIEW_THRESHOLD
                decision = (f'Rule {controlling.name} controls the final label {predicted}; '
                            f'ML {"agrees" if predicted == ml_label else "disagrees"}.')
            else:
                predicted = ml_label
                needs_review = ml_confidence < ML_REVIEW_THRESHOLD
                method = 'low_confidence_review' if needs_review else 'ml'
                severity = 'medium' if needs_review else ('none' if predicted == 'benign' else 'high')
                decision = ('Provisional ML label; analyst review required because top probability is below 60%.'
                            if needs_review else 'No rule matched; the ML top class determines the final label.')
            # Confidence is always the forest probability of the FINAL label, never 1 - max(p).
            final_probability = float(distribution[classes.index(predicted)])
            evidence = [f'Rule {m.name}: {m.reason} (heuristic score {m.score:.2f})' for m in matches]
            evidence += [self._ml_explanation(row, ml_label, ml_confidence), decision]
            record = row.to_dict()
            record.update({
                'predicted_label': predicted, 'method': method,
                'confidence': round(final_probability, 4),
                'ml_label': ml_label, 'ml_confidence': round(ml_confidence, 4),
                'benign_probability': round(float(distribution[classes.index('benign')]), 4),
                'rule_score': controlling.score if controlling else None,
                'controlling_rule': controlling.name if controlling else 'none',
                'severity': severity, 'needs_review': needs_review,
                'rule_matches': '; '.join(m.name for m in matches) or 'none',
                'explanation': ' | '.join(evidence),
                'is_alert': predicted != 'benign' or needs_review,
            })
            records.append(record)
        return pd.DataFrame(records)
