# Model card: Sentinel Context IDS 3.0

## Intended use

Offline assessment, controlled research, teaching and analyst-assisted investigation of aggregate network observations. Four known classes: benign, port_scan, dos and brute_force. Not an autonomous blocking policy, malware classifier or proof of administrative intent.

## Models and fitting

Equal-weight Random Forest/Extra Trees soft voting with sigmoid calibration on independent sessions. A log-feature Isolation Forest supplies novelty evidence. Class-conditional episode-max calibration supplies prediction sets. Service-rate baselines use benign training observations only. Metadata and labels are excluded from supervised inputs.

Training: 3,840 synthetic observations / 320 sessions. Separate probability calibration: 1,152 /96. Separate prediction-set calibration: 1,152 /96. Validation: 1,152 /96. Final test: 2,880 /240, with changed traffic scales and unseen source identities. Study plan, manifests and development freeze record the process. A later Black formatting pass preserved syntax trees and fitted artifacts.

## Measured efficacy

All-row locked-test accuracy/macro F1: 99.34%/99.34%. Episode-bootstrap accuracy interval: 98.96%-99.69%. Accepted coverage/accuracy: 91.32%/99.54%. Review rate: 8.68%. Raw class false-positive rate: 1.39%. Confident-alert false-positive rate: 0.42%. Confident-alert precision/recall: 99.85%/91.30%. Reviewed rows are retained in primary classification metrics.

Historical known stress accuracy: 88.33%, up from 15%. Historical clear accuracy: 96.21%, down from 100%. Legacy stress recognized scans require review due missing temporal history, so confident-alert recall is zero there. Intent challenge: 50% class accuracy and 41.67% review. These are material limits, not excluded failures.

## Uncertainty

Final-class confidence is a calibrated model output for this development setup, not a field-validated risk probability. Locked-test Brier/ECE improve after calibration; historical shift reduces prediction-set coverage to 50%. Empty/non-singleton sets, low support, novelty, disagreement and evidence-quality flags generate review. Novelty is not proof of a novel attack.

## Data and fairness of comparison

No representative real capture or public dataset has established efficacy. The frozen predecessor was trained with narrower/smaller data. Most gain appears from broader training and the new core ensemble; context adds a small incremental improvement. Rules do not change locked-test class accuracy. Do not interpret the complete-system comparison as a controlled proof of algorithmic novelty.

## Input limitations

PCAP counts directional flow buckets, not reconstructed authenticated sessions. Authentication outcomes are unavailable unless logs supply them. Missing temporal context is a degraded mode and can increase review or error. Upstream identity normalization, capture completeness and trusted transport are outside the model. NAT, distributed activity, spoofing, very slow scans, encryption and previously unseen attack families remain limitations.

## Security and maintenance

Joblib artifacts are executable pickle-based files: load only trusted locally built artifacts. Uploading models is not supported. Use synthetic fixtures or authorized observations. Before field use: independent validation, drift/sensor monitoring, model/rule versioning, a privacy/retention policy, protected ingestion and an analyst-controlled response process.

## Ownership and AI use

Prepared for the user's individual technical assessment. AI tools assisted development, research and review. The candidate remains responsible for understanding, validating and explaining the implementation and for meeting submission requirements. No third-party security certification is claimed.
