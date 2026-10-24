# Sentinel Context IDS: Context-Aware, Uncertainty-Aware Network Intrusion Detection

## Problem Overview and Objectives

An intrusion detector must identify suspicious traffic without confusing legitimate work with attacks or presenting missing evidence as certainty. The earlier prototype used narrow synthetic classes and global rate thresholds. It missed quieter scans and falsely classified legitimate backups as denial of service. The research question is whether broader traffic coverage, causal context and explicit uncertainty can improve this behavior in a reproducible analyst-facing system.

The objectives are to ingest traffic, validate observations, extract meaningful features, classify benign traffic, reconnaissance, DoS and brute force, explain each decision and measure both errors and review workload. Sentinel is an offline research prototype, not an enforcement product. Its contribution is an inspectable integration and controlled comparisons; the underlying algorithms and temporal monitoring ideas are established methods.

## Traffic Data and Environment

The generator creates complete timestamped observation episodes rather than independently inventing window counters. Each episode has twelve observations. Benign profiles include web traffic, high-volume backups, administrative fanout, DNS bursts and legitimate authentication. Attack profiles include fast/slow/mixed scanning, SYN/UDP/request floods, and SSH/FTP/RDP-like password failures. Twelve percent of outcomes are hidden to exercise explicit missing-authentication handling.

Training uses 3,840 rows in 320 sessions. Independent probability calibration, prediction-set calibration and validation each use 1,152 rows in 96 sessions. The final test contains 2,880 rows in 240 new sessions and source identities. Its duration, packet-count and packet-size scales are perturbed. Separate seeds and a fixed study plan make these populations reproducible. No labels, addresses, scenario strings or partition identifiers enter the model vector.

These are synthetic aggregate observations, not captures of actual attacks. A separate offline PCAP/PCAPNG adapter measures supported IPv4/IPv6 TCP/UDP packet counters and aggregates directional five-tuples within sixty-second buckets. Its counter tests use constructed packets. File-format support is not evidence of detection efficacy on operational captures, and no public-dataset accuracy has been established.

## Architecture and Feature Extraction

The pipeline comprises validation, causal source-history aggregation, feature derivation, calibrated classification, contextual evidence, uncertainty checks and queue selection. A CLI exposes develop, evaluate, build, detect, pcap and benchmark. Streamlit supplies Overview, Evidence Workbench, Mandatory Scenarios, Research Experiments and Working Concept views. Uploads do not require ground truth or optional endpoints.

Validation rejects empty records, nonnumeric or infinite values, negative/fractional counters, invalid ports, impossible flag counts and inconsistent port cardinality. Protocol-aware checks reject TCP flags on UDP. Invalid measurements are not silently converted into normal-looking zero features. Authentication outcomes may be absent, but an availability indicator distinguishes unknown from measured zero failures.

Twenty core features cover duration, packets, bytes, flags, failures, short-window counts, rates, average packet size, ratios, service context and evidence availability. Six additional features provide 300-second diversity, count, entropy, port novelty, service-relative rate and temporal availability. Packet rate is packets divided by duration; SYN/ACK ratios divide corresponding flags by packets. Port entropy summarizes spread across destination ports.

A source deque calculates inclusive sixty- and 300-second windows using only available observations, preserving original output order. History truncation is visible, and source-capacity overflow raises an error. Baseline service rates use benign training data only. Missing long-window context receives explicitly marked compatibility placeholders rather than being claimed as measured history.

## Detection Methodology

The supervised model equally averages Random Forest and Extra Trees probabilities. Each contains 220 trees with fixed seeds, bounded depth and minimum leaf size two. Balanced class weighting supports tabular multiclass learning. A separate probability-calibration population fits sigmoid mappings around the frozen ensemble. The core-only and contextual variants permit an incremental ablation using the same development process.

Rules express contextual security hypotheses. Fast scanning requires at least twenty ports, elevated SYN ratio and low ACK ratio. Persistent scanning uses at least eight ports over 300 seconds, high diversity and incomplete-handshake evidence. Flooding requires packet rate of at least 800 per second and 1,000 packets plus corroborating handshake failure or service-relative load context. High rate alone is insufficient. Brute force requires known authentication failures on a relevant service with repeated observations.

All matches remain visible. Agreement records rule-plus-model evidence. A conflicting rule may supply a provisional class when model support is below 0.85, but disagreement always requires review. Confident disagreement preserves the model class and also requires review. The final confidence remains the calibrated probability of the final class; a heuristic rule strength never replaces it.

## Uncertainty and Analyst Output

Prediction sets use separate calibration episodes. For each episode, the maximum nonconformity score, one minus true-class probability, represents its worst observation. Class-conditional order statistics form thresholds at alpha 0.10. Empty or non-singleton sets require review. This avoids treating correlated rows as independent calibration episodes, but exchangeability and distribution stability still matter.

A log-feature Isolation Forest flags unfamiliar observations using a cutoff determined before final testing. Low model support, novelty, missing evidence, truncated capture/history, rule disagreement and unobservable fanout authorization can also require review. Novelty is not proof of a new attack type.

Output separates security alerts, review items and cleared predictions. Each event preserves measured features, provisional and ML classes, probabilities, prediction set, novelty score, controlling rule, review reasons and a decision trace. The dashboard exposes one complete event and exports queues. It does not invent missing ground truth or hide uncertain rows from classification metrics.

## Experimental Design and Testing

The study plan fixes development/final seeds, the scale shift, comparators and metrics. Development persists model and decision-code hashes before generating the final test. Source/session disjointness is checked. A later formatting pass preserves syntax trees and fitted models, with provenance recorded. Metric-reporting clarification separates classification from queue policy without changing model decisions.

Primary accuracy and macro F1 include every final row, including reviews. Accepted accuracy is reported with accepted coverage. Binary security-alert metrics exclude review items, while investigation recall includes them. A thousand episode-level bootstrap resamples provide an empirical accuracy interval. This interval concerns generated episodes, not all future real networks.

Regression tests cover invalid inputs, feature arithmetic, unknown authentication, exact window expiry, future-event isolation, source separation, history bounds, evidence rules, model serialization, leakage/freeze checks, packet counts and all dashboard scenarios. The packet fixtures use explicit offline addresses and require no packet transmission or capture driver. Setup uses pinned dependencies and a source-first reproducible build.

## Results and Interpretation

On the 2,880-row locked synthetic test, Sentinel achieves 99.34 percent accuracy and 99.34 percent macro F1. The episode-bootstrap accuracy interval is 98.96 to 99.69 percent. The frozen predecessor reaches 62.08 percent accuracy and 54.22 percent macro F1 on the same rows. Raw classification false-positive rate decreases from 50.28 to 1.39 percent.

This is a complete-system comparison with a training-data confounder: the new system sees broader and more numerous development examples. The new core ensemble already reaches 99.31 percent accuracy; context adds one correctly classified flow. Adding the rules does not change final class accuracy in this experiment. Therefore the evidence does not establish that temporal features or rule fusion caused the large baseline improvement.

Sentinel reviews 8.68 percent of final observations. Accepted coverage is 91.32 percent with 99.54 percent accepted accuracy. Confident-alert precision is 99.85 percent and recall is 91.30 percent; three benign rows generate confident security alerts. Some malicious observations remain unalerted or reviewed, so operational value cannot be assessed from precision alone.

The known historical stress diagnostic improves from 15 to 88.33 percent class accuracy: all 150 backups receive benign classes, and 115 of 150 slow scans receive scan classes. Its missing temporal history routes recognized scans to review, giving zero confident-alert recall in that diagnostic. Historical clear accuracy declines from 100 to 96.21 percent. Both trade-offs are retained.

Calibration improves measured Brier score from 0.01623 to 0.01034 and ten-bin top-label calibration error from 0.03232 to 0.00567. Prediction-set row coverage is 95.94 percent on the final test but falls to fifty percent on historical stress. A paired hidden-authorization challenge reaches fifty-percent accuracy because identical features have conflicting labels. Only 41.67 percent is reviewed after sufficient fanout; earlier observations remain a blind spot.

## Performance and Network Security Considerations

The benchmark compares 100, 500 and 2,000 observations at zero, fifty and one hundred percent DoS content, with warm-up and three repetitions. It records median/minimum/maximum batch time, throughput and amortized per-row cost. Timing includes validation, derived features, calibrated inference, novelty, rules and explanations, but excludes file reading and temporal aggregation in that workload.

This is not a live flood-impact or inline-latency experiment. Production capture would require bounded queues, resource budgets, overload behavior, sensor-health monitoring and p95/p99 latency measurement. Packet loss, asymmetric routing, NAT, clock errors, encryption and retransmissions affect completeness. Authentication outcomes need correlated logs, not packet-header guesses.

The validator cannot authenticate plausible forged telemetry. Trusted sensor transport, protected artifacts, versioning and an analyst-controlled response process are necessary. Joblib is pickle-based and only trusted locally built artifacts should be loaded. No automatic blocking or live attack generation is implemented.

## Limitations, Future Work and Conclusion

Synthetic generator shortcuts and limited traffic diversity remain the largest threat to validity. Modest scale perturbations do not substitute for a different network. Missing context can reduce coverage or accuracy, and review can burden analysts. Distributed or slower-than-window activity and hidden authorization remain unresolved. Neither calibration nor novelty detection guarantees resilience to arbitrary shift.

Future work should evaluate representative public and controlled traffic with documented feature provenance, chronological/source-group splits and a predeclared alert budget. Fresh untouched populations are required after error-driven tuning. Reliable authentication/asset enrichment, streaming aggregation, drift checks and analyst feedback would strengthen operational usefulness.

Sentinel provides a materially improved, reproducible research prototype with all required local scenarios, packet-file ingestion, inspectable decisions, measured uncertainty and honest negative results. Its contribution is this implementation and evidence, not a world-first claim or universal IDS superiority. AI tools assisted development and review; the individual candidate remains responsible for understanding and explaining the submitted work.

## References

Cantone, M., Marrocco, C., and Bria, A. On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection. IEEE Access, 2024. arXiv:2402.10974.

Angelopoulos, A. N., and Bates, S. A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification. arXiv:2107.07511, 2021-2022.

Suricata thresholding documentation; Zeek scan-policy documentation; scikit-learn calibration and novelty documentation. Exact primary-source links and claim boundaries appear in RESEARCH_AND_PRIOR_ART.md.
