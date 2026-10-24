# Sentinel Context IDS - Complete Working-Concept Handbook

## 1. The problem in everyday language

A network produces many connections. Most are useful: opening a website, resolving a name, copying a file or signing in. An intrusion detector looks for observations that deserve investigation. The difficult part is not noticing high traffic; it is distinguishing harmful behavior from legitimate work and recognizing when available evidence cannot answer the question.

The previous prototype learned narrow synthetic ranges and let a packet-rate rule override context. This made a backup look like a flood and let quieter scans resemble normal traffic. Sentinel broadens training examples, carries history across two time horizons, calibrates model outputs and makes uncertainty visible. It assists an analyst; it does not block devices or prove an operator's intent.

A useful way to understand the output is three work queues. An **alert** is a sufficiently supported malicious classification without an unresolved review reason. **Review** means the system has uncertainty, conflicting evidence, unfamiliar inputs or missing context. **Clear** means a benign classification with no configured review trigger. Clear is a model decision, not proof of safety.

## 2. Networking concepts needed to understand the project

A packet is an individual network message. Its source/destination addresses identify endpoints, and transport ports identify applications or temporary conversation endpoints. TCP uses connection state and flags; UDP does not have TCP SYN, ACK or RST flags. A flow combines packets belonging to a conversation or observation interval so a detector can reason about counts and rates.

A five-tuple is source address, destination address, source port, destination port and protocol. Sentinel's offline packet adapter uses **directional** five-tuples and sixty-second buckets. The reverse direction is a different record. It does not perform full TCP stream reconstruction, so an observed flow-record count is not necessarily the number of distinct authenticated connections.

A TCP SYN commonly requests connection establishment. ACK acknowledges traffic. RST resets a connection. Many SYNs with few ACKs can suggest incomplete connections, but retransmission, capture loss and directionality can produce similar evidence. Flags can overlap on a packet, so individual flag counts are bounded by packet count but their sum need not be.

Port scanning explores destination ports. Fast scans may touch many ports quickly; slow scans distribute that exploration over time. Denial of service attempts to exhaust resources, but legitimate backups can also send many packets. Brute force repeatedly tries authentication; a network-flow record usually cannot reveal whether an encrypted password attempt succeeded. Sentinel therefore treats authentication outcomes as a separately supplied observation.

## 3. Inputs and evidence provenance

There are two ingestion paths. The CSV path accepts aggregate counters, optional identifiers, optional authentication evidence and optional historical context. The capture path reads stored PCAP/PCAPNG files, counts supported TCP/UDP observations, aggregates directional records and calculates source history. Neither path sends packets or starts an attack.

The minimum CSV requires duration, packets, bytes, SYN/ACK/RST counts, unique destination ports in sixty seconds, observation count in sixty seconds and destination port. Authentication failures may be omitted. When omitted, the implementation stores a numerical placeholder zero together with `auth_available=0`; that combination means **unknown**, not observed success. A positive failure count with unavailable authentication is rejected as contradictory evidence.

`temporal_available=1` means genuine 60/300-second source history was supplied or calculated from the input event sequence. Without it, longer-window columns receive compatibility placeholders and are not asserted to be measured history. This is a degraded observation mode, not the same distribution as the primary test. Recognized scans without temporal context are routed to review.

Labels, scenario names and session IDs are used for evaluation and filtering only. Source/destination addresses support grouping and investigation, not supervised classification. This avoids directly learning an attack label from a synthetic scenario string or address range.

## 4. Validation before mathematics

A detector should not turn corrupt evidence into normal traffic. Sentinel converts numeric strings, rejects missing/nonnumeric/infinite required values, and checks counter domains. Duration and packets must be positive. Counts must be nonnegative integers. Destination ports must be in 0-65535. Each TCP flag count must be no larger than packet count. Port cardinality must not exceed observation count for the same window.

When protocol is provided it is TCP or UDP, and UDP must have zero TCP flags. Temporal entropy and fractions have bounded domains. Empty data receives an explanatory validation error. Derived features are checked for overflow rather than silently filled with zero.

These checks establish internal consistency, not authenticity. A malicious or broken sensor could submit plausible invented counters. A real deployment needs trusted sensors, protected transport, schema/version checks, clock monitoring and provenance outside this prototype. Optional IP metadata is treated as a grouping identifier; normalization and validation should occur at the sensor boundary.

## 5. Causal temporal aggregation

The raw generator and `--aggregate-context` path use timestamped observations. Timestamps represent when a completed observation becomes available. Rows are sorted by time for calculation and then returned in their input order. For each source, a deque retains records from the last 300 seconds. The current record is appended before calculating its windows; later records never contribute to an earlier row.

The sixty-second view counts recent observations and unique destination ports. The 300-second view does the same across a longer horizon and calculates port entropy and port novelty. A source with one port repeated many times has low port entropy. A source contacting many different ports has higher entropy. Diversity alone is insufficient: an authorized administrative service can also contact many ports.

For counts n_i for each destination port and N total records, the port probability is p_i = n_i / N. Entropy is H = -sum(p_i * log2(p_i)). The new-port fraction is unique_ports / N. This is a diversity measure over the current window, not a claim that every port is globally new to the source.

History is bounded per source at 10,000 records. If that bound truncates observations, the row is marked incomplete and routed to review. At most 4,096 source histories are admitted per batch; exceeding that capacity raises an explicit error. A caller can partition data or change the explicit limit. This bounds aggregation state but not total input/output memory, because the current implementation still uses DataFrames for a batch.

Fixed horizons remain a limitation. Activity slower than 300 seconds, distributed across source identities or obscured by NAT can evade or distort the context. Host identity changes and duplicate/missing events also matter. The prototype does not claim to solve distributed campaign attribution.

## 6. All model features and their purpose

| Feature | Calculation or origin | Interpretation |
| --- | --- | --- |
| flow_duration_s | Observation duration | Short bursts versus sustained work |
| packets | Measured packet count | Traffic volume |
| bytes | Measured byte count | Traffic volume and packet-size context |
| syn_count | TCP SYN observations | Connection-attempt evidence |
| ack_count | TCP ACK observations | Completion/acknowledgement context |
| rst_count | TCP RST observations | Reset context |
| failed_logins | Correlated log outcome, or explicit unknown placeholder | Repeated authentication failure |
| unique_dst_ports_60s | Source-window cardinality | Short-horizon exploration |
| connections_60s | Observed records in the source window | Activity frequency; not full session reassembly |
| packet_rate | packets / duration | Packets per second |
| byte_rate | bytes / duration | Bytes per second |
| avg_packet_size | bytes / packets | Bulk transfer versus small probing messages |
| syn_ratio | syn_count / packets | SYN concentration |
| ack_ratio | ack_count / packets | Acknowledgement context |
| rst_ratio | rst_count / packets | Reset concentration |
| is_auth_service | Destination in 21, 22, 23 or 3389 | Authentication-service prior, not proof of application |
| ports_per_connection | unique_ports60 / max(observations60, 1) | Diversity relative to activity |
| packets_per_connection | packets / max(observations60, 1) | Packet volume relative to source activity |
| failure_rate | failed_logins / max(observations60, 1) | Authentication-failure context, not a calibrated failure probability |
| auth_available | 0 or 1 | Whether outcomes are known |
| unique_dst_ports_300s | Longer-window cardinality | Persistent exploration |
| connections_300s | Longer-window observation count | Sustained activity |
| port_entropy_300s | Shannon entropy | Spread across destination ports |
| new_port_fraction_300s | Cardinality / window record count | Port diversity in the window |
| service_rate_ratio | Packet rate / benign training p99 for destination service | Relative rather than purely global rate |
| temporal_available | 0 or 1 | Whether measured history exists |

Service baselines are fitted **only on benign training rows**. An unseen destination service uses the global benign training p99. The denominator is floored at one for numerical safety. A ratio is contextual evidence, not an assertion that every observation above a quantile is an attack. Training-data poisoning or a changed workload can make a baseline unreliable.

## 7. Learning a class from examples

Supervised classification learns a relationship between features and known labels. The four labels are benign, port_scan, dos and brute_force. Sentinel combines a Random Forest and Extra Trees classifier using equal-weight soft voting. Soft voting averages their class-probability vectors; it does not count independent witnesses or guarantee lower error.

A decision tree repeatedly splits a feature range into smaller regions. A forest combines many such trees to reduce instability. Random Forest uses bootstrapped samples and randomized candidate features. Extra Trees adds more randomness to split thresholds. They can model nonlinear tabular relationships without standard feature scaling, but can still learn shortcuts from a synthetic generator.

The Random Forest has 220 trees, depth at most sixteen, minimum leaf size two and balanced-subsample class weights. Extra Trees has 220 trees, depth at most eighteen, minimum leaf size two and balanced class weights. Seeds and worker counts are fixed. These are documented research choices, not a search for the largest advertised accuracy.

Two versions are fitted. The core ensemble uses twenty behavioral/evidence features. The contextual ensemble uses all twenty-six features. Their comparison tests the incremental value of history. In this experiment the gain is one correct flow out of 2,880, so the documentation does not present temporal context as the main cause of the large improvement over the old system.

## 8. Why probabilities need calibration

A forest output of 0.99 is model support under its learned patterns; it is not automatically a 99-percent real-world chance of attack. Sentinel freezes the fitted voting model and fits a sigmoid calibrator on a different set of sessions. Calibration changes the mapping from model scores to class probabilities without retraining the tree splits on calibration labels.

Calibration quality is measured. The multiclass Brier score is the mean sum across classes of (predicted_probability - one_hot_truth)^2. Top-label expected calibration error groups predictions into ten confidence bins and compares average confidence with empirical correctness. These diagnostics describe the evaluation population and can vary with binning and distribution.

On the locked synthetic test, Brier decreases from 0.01623 to 0.01034 and top-label ECE from 0.03232 to 0.00567. That measured improvement supports using the calibrator here. It does not prove probabilities remain reliable on another network. Brier reflects discrimination as well as calibration, so it should not be interpreted as a pure reliability measurement.

## 9. Prediction sets instead of forced certainty

A single class can hide uncertainty. Sentinel calculates a set of compatible classes from independently calibrated scores. For each calibration episode, it records the worst member score 1 - p(true_class). It then forms a class-conditional threshold using a finite-sample order statistic. Using episode maxima avoids pretending that twelve correlated rows are twelve independent episodes.

For n calibration episodes and error budget alpha, the rank is ceil((n + 1) * (1 - alpha)). If the rank exceeds n, the threshold is one. For each new row, include class k when 1 - p(k) is at most that class's threshold. Alpha is 0.10. An empty set or a set containing multiple classes triggers review.

This is an episode-oriented conformal construction, not a blanket promise of ninety-percent coverage under all traffic. Exchangeability and consistent episode formation matter. The shifted synthetic test has measured row-level prediction-set coverage of 95.94%, while historical stress falls to 50%. The latter is evidence that a distribution change can undermine a superficially reassuring uncertainty mechanism.

## 10. Novelty detection and unknown attacks

The classifier must choose among four known classes. An Isolation Forest provides a separate unfamiliarity signal. It is trained on log1p-transformed known training features. Its trees isolate sparse observations through random partitions. Low scores indicate observations unlike the training distribution; they do not identify a new attack family.

The novelty cutoff is the lower 0.5th percentile of scores on the separate prediction-set calibration population. This is fixed before final evaluation. A score below it adds `unfamiliar_feature_distribution` to review reasons. It does not overwrite a class with an unsupported invented label.

Novelty detection can miss unfamiliar but normal-looking attacks and flag unusual legitimate behavior. It is a review mechanism rather than proof of maliciousness. Future versions need representative field data, drift monitoring and an analyst feedback process before adapting the model.

## 11. Contextual rules and evidence arbitration

R1 detects fast scanning with at least twenty destination ports, SYN ratio at least 0.35 and ACK ratio below 0.4. R2 detects persistent exploration using measured 300-second history: at least eight unique ports, diversity fraction at least 0.6, ACK ratio below 0.25 and SYN ratio at least 0.25.

R3 requires packet rate at least 800 per second and at least 1,000 packets, plus corroboration. Corroboration is either SYN-heavy/ACK-poor evidence or a service-baseline ratio of at least two with sufficient longer-window activity and ACK ratio below 0.65. Critical severity begins at 2,000 packets per second. A high-rate ACK-rich large-packet transfer produces bulk-context explanatory evidence instead of being called an attack solely from its rate.

R4 requires available authentication outcomes, an authentication service, at least five failures and three source-window observations. Missing outcomes cannot satisfy the rule. The model can still suspect brute force from other features, but that suspicion is reviewed rather than represented as confirmed password failure.

Matches are ordered by critical severity, strength and name. If the strongest evidence agrees with the model, the method records agreement. If it disagrees while the model's top support is below 0.85, the evidence rule supplies the provisional final class and the event is reviewed. A confident disagreement is also reviewed, while preserving the model class. This is an explicit conflict policy, not a mathematically optimal fusion theorem.

The final confidence always remains the calibrated probability of the **final class**. The model's own top class and probability are preserved separately. Rule strength is never substituted for a model probability.

## 12. A complete decision example

Consider 5,000 packets over one second, large average packet size, ACK ratio 0.99, one destination service and no observed authentication failures. A global rate detector sees 5,000 packets per second and may call it a flood. Sentinel records the high rate, but the contextual flood rule lacks its corroborating handshake/service evidence. The ensemble also has training examples of legitimate bulk traffic. Its conclusion can therefore be benign without hiding the measured volume.

Now consider repeated small SYN-heavy observations contacting different destination ports over several minutes. Even when the sixty-second count is modest, the 300-second diversity can activate R2. The explanation states the counts and ratios. If the model and rule disagree, the workbench preserves both opinions and marks review rather than fabricating agreement.

Finally, suppose an administrator and an unauthorized person perform observably identical successful connections. No model using only these counters can identify permission. The challenge gives these identical observations conflicting labels and correctly fails to produce a perfect score. Later fanout is reviewed; early events remain an acknowledged blind spot.

## 13. What each output field means

`predicted_label` is the final provisional class. `ml_label` and `ml_confidence` preserve the calibrated ensemble's top choice. `confidence` is its probability for the final label. `prediction_set` lists compatible classes. `novelty_score` is an Isolation Forest score, not a percentage.

`controlling_rule`, `rule_matches` and `method` explain how the provisional class was selected. `needs_review` and `review_reasons` state uncertainty triggers. `queue` is alert, review or clear. `is_alert` is true only for the alert queue. `severity` prioritizes investigation and is not a probability.

The explanation includes observed rule values, calibration support, decision source, prediction set, missing evidence and review reasons. It is a decision trace rather than causal feature attribution. Analysts should inspect the source record and associated logs before acting.

## 14. How the experiment avoids common evaluation mistakes

Training, probability calibration, prediction-set calibration, validation and final testing use disjoint sessions and source identities. A synthetic session contains twelve observations. Seeds and scale shifts are recorded. The final dataset is generated after development-selected artifacts are persisted; model and decision-code hashes are checked before evaluation.

All rows count toward primary multiclass accuracy and macro F1, including reviewed rows. Separately report accepted accuracy with accepted coverage. Otherwise a detector could reject difficult cases and advertise an inflated score. Class false positives, security-alert false positives, review workload and investigation recall are different quantities and are all available in the result file.

The old prototype is a frozen system comparator. It used narrower and smaller training data, so improvements cannot all be attributed to a new algorithm. Core-only versus context-ensemble versus full policy provides a more controlled ablation within the new training setup. Rules do not change the final accuracy on this particular locked test; their measured benefit is not invented.

An episode bootstrap samples episode-level accuracy values with replacement one thousand times. Its 2.5th and 97.5th percentiles form an empirical interval. It reflects uncertainty among generated episodes, not uncertainty over every real network or every future attack.

## 15. Reading the results correctly

Locked-test all-row accuracy is 99.34% and macro F1 is 99.34%. The old system reaches 62.08% on the same rows. Core-only new accuracy is 99.31%. The raw class false-positive rate is 1.39%, while confident-alert false-positive rate is 0.42%. The difference exists partly because questionable events enter review.

The review rate is 8.68%, accepted coverage 91.32% and accepted accuracy 99.54%. Confident-alert precision is 99.85% and recall 91.30%. An operational team must consider the unalerted attacks and review burden, not just precision. Combined alert-or-review investigation recall is separately reported.

The known historical stress accuracy rises from 15% to 88.33%. However, absent temporal history routes its recognized scans to review, giving zero confident-alert recall in that stress experiment. The older clear diagnostic drops from 100% to 96.21% class accuracy. These regressions and policy trade-offs remain visible.

## 16. Packet ingestion boundaries

The capture reader supports stored IPv4/IPv6 TCP/UDP packets as decoded by Scapy. It counts bytes actually present and flag-bearing packets, then groups directional five-tuples within fixed sixty-second buckets. Single-packet duration uses a documented one-microsecond floor; this prevents division by zero but can create extreme rates and novelty review.

The reader records unsupported packets, malformed observations, IPv4 fragments, wire truncation and explicit packet/flow limits. Incomplete supported captures add review reasons. It does not reassemble IP fragments, deduplicate retransmissions, reconstruct application transactions or infer failed passwords. Unhandled IPv6 fragmentation/reassembly and encrypted application semantics are limitations. Packet-derived feature distributions may differ sharply from the synthetic training population; support for a file format is not an efficacy validation.

## 17. Usefulness and deployment pathway

The project is useful as a reproducible assessment, a teaching tool, an evidence-oriented analyst interface and a platform for controlled experiments. An analyst can compare a fast scan with a backup, inspect uncertainty, export a queue and reproduce a metric from its underlying rows.

A realistic deployment should place trusted sensors upstream, enrich identities and assets, join authentication logs, evaluate public and controlled captures, and set latency and memory budgets. A queue should separate ingestion from scoring. Model and rule versions need audit trails, rollback and drift checks. Automatic blocking requires a separate evaluated policy and authorization; it is not implemented here.

## 18. Research contribution and honest boundaries

The contribution is a specific integrated implementation and its reproducible comparisons: causal context, broader benign/attack coverage, calibrated evidence, episode-based prediction sets, novelty review and transparent disagreement. The underlying algorithms are established. Existing tools already support important forms of thresholding and scan analysis. This project has not demonstrated universal superiority to them or proved that no similar work exists.

The next research step is independent real traffic, not a larger synthetic percentage. Better labels, service context and reliable temporal observations may matter more than a more complicated model. Changes inspired by final-test errors require fresh evaluation rather than renaming the same test as untouched.

## 19. Suggested learning sequence

Read the README, run the dashboard and inspect one event from each class. Trace a row through validation, temporal aggregation, features, calibrated probability and queue selection. Compare the combined confusion matrix with the raw predictions. Then reproduce the baseline comparison and explain why high accepted accuracy is incomplete without coverage.

Before an interview, explain why authentication is unknown in a PCAP, why source history must be causal, why a backup can resemble a flood, what calibration measures, how prediction sets fail under shift, and why hidden authorization creates an information limit. Reviewing those concepts personally is part of the individual assessment.
