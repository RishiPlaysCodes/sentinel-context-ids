# Demonstration storyboard - Sentinel Context IDS

Target: 8-10 minutes. This is a recording guide, not a recorded video. Use the running system, not a source-only walkthrough. Add your name to the opening. Read current result files after rebuilding.

## Preparation

Run `python run_ids.py build`, `python -m pytest -q`, `python run_ids.py benchmark` and `python -m streamlit run app.py`. Keep the README, report, results/comparison.csv and results/metrics.json open. Default to Locked synthetic test. Rehearse to confirm the final runtime.

## 0:00-0:45 - Problem and honest contribution

Screen: README and dashboard title.

Explain: Network IDS work must distinguish suspicious behavior from legitimate bulk activity and expose missing evidence. The previous prototype missed slow scans and flagged backups. Sentinel integrates causal history, broader data, calibrated models and review queues. It is a specific research implementation, not a world-first algorithm claim. All headline efficacy numbers are synthetic.

## 0:45-1:35 - Architecture

Screen: README diagram, then Working concept view.

Explain the path from observation and validation to temporal context, twenty-six features, Random Forest/Extra Trees, probability calibration, rules, prediction sets and novelty. End at alert/review/clear. Explain that a review item is not silently counted as a correct or confirmed malicious classification. Source files support the presentation, but the recording primarily shows the running tool.

## 1:35-2:25 - Data and causal context

Screen: DATA_CONTRACT.md, study plan and dashboard source selector.

Explain 3,840 training rows, three distinct 1,152-row calibration/validation populations and 2,880 final rows across unseen sessions/sources. Twelve observations form an episode. Explain timestamp completion semantics, sixty-/300-second windows, diversity, entropy and no future-event leakage. State that the generator is synthetic and the final domain shift is modest. Show that authentication may be unknown rather than successful.

## 2:25-3:15 - One full decision

Screen: Evidence workbench. Inspect a supported attack and a review item.

Point out final class, ML top class, final-class support, controlling rule, prediction set, novelty and review reasons. Explain a rate threshold with contextual corroboration. Explain that class support is not a universal operational-risk probability. If a rule and model disagree, show how that conflict is preserved.

## 3:15-3:55 - Scenario 1: benign baseline

Screen: Mandatory scenarios -> benign, 720 rows. Compare backup and DNS profiles.

Explain the actual and predicted counts honestly: the broader benign test is not perfect. There are ten benign class errors overall and three confident security false alerts; additional cases are reviewed. Contrast a high-ACK large-packet backup with a high-rate attack. Do not claim zero false alarms.

## 3:55-4:35 - Scenario 2: reconnaissance

Screen: port_scan, 720 rows, then slow_scan profile.

Explain that all final scan classes are correct in this generated population. Show long-window port diversity and the evidence rule where applicable. Explain why sixty seconds can miss slower behavior and why three hundred seconds still cannot cover indefinitely slow or distributed campaigns.

## 4:35-5:25 - Scenario 3: DoS and performance

Screen: dos profile and Research experiments benchmark table.

Inspect SYN/ACK/rate/service-baseline evidence. Explain that rate alone is insufficient. Compare the current 2,000-row zero-percent and one-hundred-percent DoS timing rows, reading actual measurements. State warm-up, three repetitions and timing scope. It measures inference cost, excluding file read and aggregation in that workload; it does not measure victim availability, packet loss or live network throughput.

## 5:25-6:05 - Scenario 4: brute force

Screen: brute_force profile and one unknown-authentication review item.

Explain the authentication service, failed-log evidence and repeated observations. The PCAP reader cannot infer encrypted password outcomes. When evidence is absent, the availability field and review reason make that limitation explicit. No password-attack tool is being executed.

## 6:05-7:15 - Scenario 5: ambiguous or missed case

Screen: ambiguous filter, then Historical stress diagnostic and Intent ambiguity challenge.

Show a real error/review case. Historical class accuracy improves from fifteen to 88.33 percent, but thirty-five slow scans remain benign and missing history sends recognized scans to review. Its confident-alert recall is zero; do not describe class recognition as automatic alert success.

Then show identical traffic with different hidden authorization. Accuracy remains fifty percent and 41.67 percent is reviewed after enough fanout. Explain why features cannot reveal hidden permission and why early events remain a blind spot. This is a research limitation, not a score to conceal.

## 7:15-8:20 - Evaluation, attribution and tests

Screen: Research experiments table, all-row matrix, calibration diagnostics and final test output.

State final accuracy/macro F1 of 99.34/99.34 percent across 2,880 rows. The old system reaches 62.08 percent on those rows, but its training coverage differs. Core-only new accuracy is already 99.31 percent; context adds one flow, and rules change no final class here. Give credit to better data coverage rather than inventing a rule-fusion breakthrough.

State review rate 8.68 percent and accepted coverage 91.32 percent before accepted accuracy. Confident-alert recall is 91.30 percent, so precision alone is incomplete. Show calibration diagnostics and the actual passing test summary. Explain that all-row metrics include reviews.

## 8:20-9:15 - Usefulness, limits and next work

Screen: model card / deployment guide, then Overview.

Explain the analyst workflow: inspect evidence, investigate review items, export queues and reproduce results. Mention capture loss, NAT, asymmetric routing, source identity, training poisoning, drift and bounded resources. No automatic blocking, real-network accuracy or universal novelty is claimed. Next work is representative public/controlled data, independent cross-network evaluation and verified context enrichment. Disclose AI assistance and explain your own review/understanding. Thank the reviewer.

## Recording acceptance

Check 8-10 minutes, all five scenarios, one complete explanation, actual benchmark values, honest error discussion, precise scope and accessible video permissions. A GitHub repository or storyboard does not replace the recording.
