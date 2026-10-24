# Experiments and how to interpret them

## Predeclared process

`docs/STUDY_PLAN.json` specifies seeds, final scale perturbations, comparators and metrics. `develop` generates development data, trains the twenty- and twenty-six-feature models, calibrates probabilities and sets, selects a review threshold on validation, and persists hashes. `evaluate` checks model, decision-code and plan integrity, then generates and scores the final test. No final labels fit trees, baselines, calibration or review threshold.

A formatting-only pass after initial evaluation preserved syntax trees and model files; its before/after hashes are recorded. Later metric-reporting clarification separated class errors from alert-queue policy without changing predictions or thresholds. The final data was re-evaluated to publish those diagnostic fields, not to choose a different detector. Historical stress was known beforehand and is explicitly diagnostic.

## Locked test

2,880 observations, 240 unseen sessions/source identities, 720 rows per class. Duration, packet count and packet size change scales. There are still generator-specific patterns; this is not an independent enterprise or public benchmark.

| Method | All-row accuracy | Macro F1 | Raw class FPR | Review rate | Accepted coverage |
| --- | ---: | ---: | ---: | ---: | ---: |
| frozen_v2 | 62.08% | 54.22% | 50.28% | 52.71% | 47.29% |
| core_ensemble | 99.31% | 99.31% | 1.25% | 7.53% | 92.47% |
| context_ensemble | 99.34% | 99.34% | 1.39% | 8.68% | 91.32% |
| sentinel_full | 99.34% | 99.34% | 1.39% | 8.68% | 91.32% |

The frozen v2 model used 2,212 narrow training rows. The new core ensemble uses 3,840 broader training rows plus separate calibration. Thus the large baseline gain is a complete-system improvement, confounded by training coverage/size. Context's incremental gain over the new core is one flow, and adding the rules changes no final class in this locked test. Rules provide inspectable evidence and review handling; this experiment does not show a class-accuracy advantage from rule fusion.

## Queue policy and error accounting

- Class accuracy and macro F1 include every row, including reviews.
- Raw class FPR counts benign rows assigned any attack class, irrespective of queue.
- Security-alert precision/recall/FPR count only queue=alert.
- Review rate reports abstained/uncertain work, including both benign and malicious observations.
- Investigation recall counts alert OR review. Benign investigation rate reports corresponding analyst workload.
- Accepted accuracy is conditional on non-review rows and must always be paired with accepted coverage.

For Sentinel, there are 1,972 true positive security alerts, three false positives, 717 non-alerted benign rows and 188 malicious rows without a confident alert. Some unalerted malicious rows are reviewed; they are not silently removed from the denominator. Raw class FPR is 1.39%, while alert FPR is 0.42% partly because the system abstains. Read the complete JSON for investigation recall and benign review workload.

## Uncertainty diagnostics

The 95% episode-bootstrap interval for all-row accuracy is 98.96%-99.69%, based on one thousand resamples of episode-level accuracy. It quantifies generated-episode variability, not all possible operational environments.

Uncalibrated versus calibrated multiclass Brier is 0.01623 versus 0.01034; top-label ten-bin ECE is 0.03232 versus 0.00567. Lower is better for these measured diagnostics, but Brier also reflects discrimination and ECE depends on binning. Calibration is not assumed to fix arbitrary shift.

Prediction-set row coverage is 95.94% on the final synthetic test and 50% on historical stress. A nominal alpha of 0.10 does not provide field guarantees under changed distributions/episode definitions. Empty/non-singleton sets trigger review; a wrong singleton remains possible.

## Known historical diagnostic

The same 300 legacy stress rows go from 15% old class accuracy to 88.33% new class accuracy. All 150 backups receive benign classes, and 115/150 slow scans receive scan classes; 35 remain benign. This is a known problem set, not a blinded independent test. Its source-window metadata differs from the new event-based generator and lacks long-history availability, so recognized scans go to review. Confident-alert recall is zero in this diagnostic even though class recognition improves. Its accepted accuracy is only 81.52%.

On the old clear holdout, class accuracy drops from 100% to 96.21%; this regression is included rather than concealed. A field acceptance decision needs representative workloads and a review budget, not only the improved stress number.

## Identical observations, different intent

The 24-row authorization challenge pairs administrative traffic with an identical unauthorized copy. Observed features are identical; labels differ. A deterministic feature-only classifier cannot exceed 50% on exact paired observations. Sentinel reaches 50%, and 41.67% of events are reviewed once fanout exceeds its context threshold. Earlier observations remain a blind spot. The challenge prevents a false claim that network counters reveal permission.

## Performance

`python run_ids.py benchmark` produces nine conditions, three repeats each, from development validation observations. Columns include median/min/max batch seconds, throughput and amortized milliseconds per flow. The scope file states that temporal aggregation, capture loss, victim availability and live network delay are not measured. Hardware and package versions appear in metrics.json.

## Reproduction and future work

Run `python run_ids.py build`, tests and `benchmark`. Build overwrites generated data/model/evaluation; benchmark separately replaces timing outputs. The source-first repository reconstructs its baseline and synthetic data, so a clone should build before opening the dashboard. The local ZIP includes the already generated outputs.

The next efficacy test should use a representative public or controlled dataset with a documented feature mapping, followed by another network or later time period. Missing fields must be modeled as missing, not fabricated to make a schema fit. Freeze decisions before that evaluation and keep an explicit record of any subsequent tuning.
