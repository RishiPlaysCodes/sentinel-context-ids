# Deployment, operational use and threat model

## Current executable scope

Offline CSV and PCAP/PCAPNG analysis, generated synthetic experiments, a local Streamlit dashboard and CSV exports. Default binding for a local demonstration should remain localhost. There is no firewall modification, automatic blocking, background network capture or attack launcher.

## Trust boundaries

1. The upstream sensor controls counts, timestamps and identities. The validator rejects inconsistent values but cannot prove valid-looking observations are authentic.
2. An authentication-log source supplies outcomes. Missing outcomes are unknown, not successful sign-ins.
3. The model artifact is trusted executable input. Never accept a joblib upload from an untrusted party.
4. The analyst interprets alert, review and clear queues. A class probability is not authorization to block a user.
5. External publishing should contain generated examples and code, not confidential enterprise traffic or credentials.

## Attacker and failure hypotheses

| Condition | Current response | Remaining exposure |
| --- | --- | --- |
| Slow scan | Longer source history and diversity evidence | Activity slower than horizon or distributed sources |
| High-rate legitimate backup | Broad benign training, ACK/size context, no rate-only override | Novel workloads and application-layer floods can overlap |
| Missing/altered authentication logs | Availability flag and review for suspected brute force | Forged believable outcomes cannot be authenticated here |
| Packet loss/truncation/limits | Quality counters and review for known incompleteness | Undetected upstream loss, asymmetric visibility |
| Unfamiliar feature distribution | Novelty and prediction-set review | Normal-looking unknown attacks can remain in-distribution |
| Hidden administrative permission | Fanout review after enough observations | Intent is unobservable; early traffic can be cleared |
| Poisoned training/baseline | Fixed reproducible local training and provenance | No adversarial training or trusted production retraining workflow |
| Oversized batch | Capture and history limits | DataFrames still require input/output memory proportional to rows |

## Performance experiment

The benchmark scores 100/500/2,000-row workloads at 0/50/100% DoS, with warm-up and three repetitions. It measures validation, feature derivation, calibrated inference, novelty, rules and explanation cost. It excludes file reading and temporal aggregation because those workloads reuse precomputed context. Amortized milliseconds per row is not per-event latency.

The result says nothing about live packet drops, victim service availability, saturation of a link, or continuous sensor throughput. Before inline deployment, define queues, bounded buffers, fail-open/fail-closed behavior, p95/p99 latency, sustained-load targets, resource monitoring and overload behavior. Separate capture/aggregation/scoring stages and measure them individually.

## Operational interpretation

Review workload is a real cost. Lower false-positive security-alert rates can reflect more abstention, so always report review volume, investigation recall and missed-alert counts. Establish a triage SLA and audit review outcomes. Never suppress a known backup solely because of a filename or an untrusted CSV tag.

A deployment should add asset/service roles, approved-change context, authentication logs, canonical host identities, sensor health, clock checks and incident feedback. Thresholds need site-specific development data and independent acceptance testing. Drift should trigger investigation, not silent retraining on potentially poisoned observations.

## Privacy and reproducibility

The included datasets use generated addresses/counters. Real captures may contain private payloads and identifiers even though this detector ignores application content. Keep raw captures out of a public repository and apply an explicit retention/access policy. The source checkout rebuilds synthetic artifacts; a local delivery ZIP includes generated results for inspection. No secrets belong in Streamlit configuration committed to GitHub.

## Roadmap with acceptance criteria

- Public/controlled traffic adapter: preserve units, missingness and provenance; do not invent missing features.
- Chronological cross-network evaluation: predeclare metrics and keep target labels out of model selection.
- Streaming aggregation: bounded state plus measured late-event/overload behavior and replay equivalence.
- Calibrated alert budget: validate coverage, false alarms and event-level recall at an agreed analyst capacity.
- Context enrichment: independently sourced host roles and authorization, audited for integrity.
- Response integration: analyst-controlled actions with rollback, monitoring and a separately evaluated policy.
