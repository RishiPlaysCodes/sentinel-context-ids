# Research question, prior art and contribution boundaries

## Research question

Can a reproducible flow-analysis prototype reduce the earlier system's backup false positives and slow-scan misses while explicitly exposing uncertainty, missing evidence and review workload?

The hypotheses concern this implementation and its controlled experiments. They do not assert that established IDS products contain newly discovered vulnerabilities or that context-aware detection has never existed.

## Existing work and what it establishes

Suricata documents configurable thresholds, tracking and alert-frequency control. Zeek's documented scan policy uses connection-failure history and configurable intervals; its five-minute history already illustrates the benefit and false-positive trade-off of longer windows. Therefore neither threshold tracking nor a five-minute scan horizon is a world-first contribution here. [Suricata documentation](https://docs.suricata.io/en/latest/rules/thresholding.html), [Zeek scan policy, version 4.0.9](https://docs.zeek.org/en/v4.0.9/scripts/policy/misc/scan.zeek.html).

Cantone, Marrocco and Bria evaluate cross-dataset NIDS generalization and report a gap between within-dataset performance and transfer to other datasets. This motivates reporting independent populations and refusing to equate synthetic accuracy with field efficacy. Our modest synthetic scale shift is not equivalent to their cross-network study. [Primary paper](https://arxiv.org/abs/2402.10974).

Probability calibration and conformal prediction are established methods. We use a separate sigmoid calibration partition and an episode-max, class-conditional score construction. Their inclusion is an engineering/research integration, not a new statistical theorem. Distribution assumptions remain essential. [Scikit-learn calibration](https://scikit-learn.org/1.7/modules/calibration.html), [Angelopoulos and Bates introduction](https://arxiv.org/abs/2107.07511).

Isolation Forest is an existing novelty/outlier method. Our choice is to expose unfamiliarity as review evidence, not to equate it with an attack label. [Scikit-learn outlier/novelty guide](https://scikit-learn.org/1.7/modules/outlier_detection.html).

The CICIDS2017 creators provide public labeled flows and captures intended for IDS research. No such public-dataset efficacy test has been completed in this project. That absence is a stated limitation and a next experiment, not silently replaced with a synthetic claim. [Official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html).

## What is specific to this project

| Local baseline weakness | Implemented response | Evidence / qualification |
| --- | --- | --- |
| Narrow training excludes legitimate bulk traffic | Broader benign profiles and multiple attack variants | Most accuracy gain already appears in core-only ensemble |
| Global packet-rate override | Require contextual corroboration and preserve rule/model conflicts | Backup recognition improves; not universal DoS immunity |
| Quiet probing below one window | Causal 60/300-second diversity and entropy | Small measured incremental class-accuracy gain; very slow/distributed scans remain |
| Forced confident benign fallback | Provisional predictions plus a separate review queue | Coverage and missed-alert trade-off reported |
| Missing outcomes look like zero failures | Evidence-availability indicators | No password correctness inferred from packet headers |
| Hidden train/test mixing | Independent sessions/sources, frozen artifacts, all-row metrics | Generator shortcuts can still exist |
| Intent not present in network features | Paired indistinguishable-traffic challenge | 50% accuracy; partial later review; early blind spot disclosed |

The research contribution is the inspectable implementation, end-to-end evidence policy and documented measurements against its own frozen predecessor. It is suitable for a research-internship discussion precisely because negative results and attribution limits are visible.

## Negative results and confounders

The full contextual policy and contextual ML have identical class accuracy in the locked test. Rules should therefore be credited with explicit evidence/conflict handling, not an invented accuracy gain. Context beats the core ensemble by one flow. The baseline/new comparison is confounded by different training breadth and size; it does not prove the architecture alone caused a 37-point gain.

Historical stress was already observed and informed problem selection. Its improvement is a diagnostic, not independent validation. Some legacy clear accuracy is lost. Missing history routes recognized legacy scans to review, reducing confident-alert recall. Prediction-set coverage falls under that distribution shift. These outcomes are included in the model card and report.

## Claims this evidence does not support

World-first method; universal best accuracy; superiority to Zeek/Suricata; zero-day detection guarantees; real-enterprise accuracy of 99.34%; safe autonomous blocking; proof of authorization; guaranteed conformal coverage after arbitrary shift; or resilience to every poisoning/evasion attack.

## Next falsifiable experiment

Fit on one representative public or controlled network population, reserve a chronologically later network/source group, predeclare alert-budget and coverage targets, and measure classification, event-level recall, operational false alarms and calibration. Tune only on development data. Then test on a different network without adapting to its labels. That would provide stronger evidence than another increase in this generator's score.
