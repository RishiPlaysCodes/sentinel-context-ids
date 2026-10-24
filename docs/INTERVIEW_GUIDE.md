# Interview and understanding guide

Use these prompts to explain the project in your own words. Do not memorize a claim you cannot reproduce.

## The thirty-second explanation

Sentinel is an offline network IDS research prototype. It validates flow evidence, builds causal source history, combines a calibrated tree ensemble with contextual rules, and separates alerts from review and clear decisions. It improves a frozen simpler baseline on generated experiments, while explicitly disclosing synthetic-data, missing-context and hidden-intent limits.

## Questions and answer checkpoints

1. **What is a flow?** An aggregation of packet observations. Our PCAP adapter uses directional five-tuples and fixed buckets, not full bidirectional TCP reassembly.
2. **Why not just packet rate?** Backups can be fast. Rate needs handshake, size, service and workload context.
3. **How do you detect slow scans?** Maintain causal sixty- and 300-second source history and inspect diversity, entropy and incomplete-handshake evidence. Slower/distributed campaigns can still evade it.
4. **Why must aggregation be causal?** A detector cannot use future traffic at an earlier decision time. Explain the deque expiry logic and the future-event isolation test.
5. **What is entropy?** A measure of how broadly observations are distributed across ports; explain -sum(p*log2(p)). It is not automatically maliciousness.
6. **What are all twenty-six features?** Use the handbook table; identify raw counters, derived ratios, history, baselines and availability indicators.
7. **Does an authentication port prove brute force?** No. Ports are context; outcomes require logs. The model reviews suspected brute force with unknown outcomes.
8. **Why Random Forest and Extra Trees?** Nonlinear tabular interactions and reproducible training. Their combination is established, not a new algorithm.
9. **What is calibration?** Fit the relationship between model scores and observed outcomes on separate sessions. It does not repair missing information or guarantee transfer.
10. **How are Brier and ECE different?** Brier scores full probabilities against one-hot truth; ECE compares confidence and correctness in bins. Both have interpretation limits.
11. **What is the prediction set?** Classes compatible with episode-calibrated thresholds. Explain the worst-member score and finite-sample rank.
12. **Why episodes?** Rows within one source episode are correlated. Separate sessions are a more meaningful calibration/evaluation unit than a random row split.
13. **What guarantee remains under distribution shift?** No universal guarantee. Measured prediction-set coverage falls to fifty percent on historical stress.
14. **What does Isolation Forest prove?** Unfamiliarity under training features, not malicious intent or a new attack family.
15. **How are conflicts resolved?** Explain agreement, provisional rule override at lower support, and review for confident disagreement. Trace the real output fields.
16. **Why is final confidence sometimes lower than ML top confidence?** A rule may select a different class; confidence stays the model probability for that final class.
17. **Why separate review from alerts?** Operational uncertainty is a work queue, not automatically a confirmed security event. Always show review workload and missed alerts.
18. **Can accepted accuracy be misleading?** Yes. Rejecting hard rows can raise it. Pair it with coverage and retain all rows in primary accuracy/F1.
19. **Why does the frozen baseline comparison not prove algorithmic superiority?** New training is broader/larger. The core ensemble gets almost all the gain before temporal additions.
20. **What did the ablation actually show?** Core accuracy 99.31%, contextual/full 99.34%; rules changed no final classes in this test. Do not exaggerate this delta.
21. **What is the main positive result?** Stronger complete-system synthetic classification and a major improvement on a known diagnostic, with traceable evidence and uncertainty.
22. **What is the main negative result?** Real-network efficacy is unknown; missing history reduces confident alert recall; hidden authorization remains unobservable.
23. **Why only fifty percent on the intent challenge?** Exact same features have opposing labels. Explain why an algorithm cannot infer a hidden variable from identical observations.
24. **Why are early events missed by intent review?** The fanout threshold needs enough history. The implementation does not claim to eliminate that detection delay.
25. **What does the DoS benchmark measure?** Offline scoring cost at mixtures and batch sizes. It excludes aggregation and does not measure link saturation or victim availability.
26. **How do you reproduce everything?** Fresh environment, install, build, test, benchmark, then Streamlit. Show manifests and command outputs.
27. **What is the next strongest experiment?** Representative public/controlled traffic, documented missingness, chronological/grouped splits, and a different-network test with no target-label tuning.
28. **What did AI contribute?** Development, research and review assistance. Explain your own review and understanding; do not claim unaided work if that is untrue.

## Practical exercises before submission

Trace one row by hand through packet rate, SYN/ACK ratios, source windows and queue logic. Change an invalid value and show the validation error. Compare a backup and a flood with similar rate. Inspect a reviewed scan with missing history. Recompute one confusion-matrix cell from CSV rows. Explain why the fifty-percent challenge is a useful negative result. Finally, run the tests and describe what they do not establish.
