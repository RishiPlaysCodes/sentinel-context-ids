# Input contract, units and provenance

## Required CSV fields

| Field | Domain | Unit / meaning |
| --- | --- | --- |
| flow_duration_s | Finite >0 | Completed observation duration in seconds |
| packets | Positive integer | Packet count |
| bytes | Nonnegative integer | Bytes represented by that observation |
| syn_count | Integer 0..packets | Packets carrying TCP SYN |
| ack_count | Integer 0..packets | Packets carrying TCP ACK |
| rst_count | Integer 0..packets | Packets carrying TCP RST |
| unique_dst_ports_60s | Integer 0..65536; <=connections_60s | Source-window destination-port cardinality |
| connections_60s | Nonnegative integer | Source-window flow-observation count |
| dst_port | Integer 0..65535 | Destination transport port |

Numeric strings are normalized. NaN, infinity, negative/fractional counters, invalid ratios, duplicate DataFrame columns, empty data and overflowing derived features are rejected. The CSV entry point checks original headers before pandas can rename duplicates, and rejects blank or whitespace-padded headers. Counts concern the same measurement window, and flags may overlap on a packet.

## Optional evidence

`failed_logins` is a nonnegative integer. If absent, it is stored as zero with `auth_available=0`, meaning unknown. If supplied without an availability flag, availability defaults to one. An unavailable outcome cannot assert positive failure counts. Authentication outcomes must come from correlated logs; ordinary encrypted flows do not disclose password correctness.

`protocol`, when supplied, is case-normalized TCP or UDP. UDP cannot contain TCP flags. Endpoints, flow_id, timestamp and ports are display/grouping metadata. Label, scenario, scenario_subtype, partition, session_id and is_ambiguous are never model inputs.

Long-window context fields are unique_dst_ports_300s, connections_300s, port_entropy_300s and new_port_fraction_300s. They require nonnegative finite values, integer cardinalities/counts, cardinality <=count, entropy <=16 and fraction <=1. Set temporal_available=1 only for measured/reconstructed history. Absent history receives compatibility placeholders and temporal_available=0; those placeholders are not measurements, and performance can degrade.

`context_truncated` and `capture_incomplete` are ingestion-quality indicators. Incomplete observations enter review. External callers must supply trustworthy, consistently typed provenance; this is not an authenticated telemetry protocol.

## Reconstructing history

Use `python run_ids.py detect events.csv --aggregate-context`. In addition to per-flow counters, input requires ISO-8601 UTC/offset timestamps, src_ip and dst_port. Timestamps represent completed observations becoming available. All relevant source events should be included. The operation uses causal time ordering, includes the current observation and never looks ahead. Output retains input row order.

Sixty- and 300-second windows are inclusive at the boundary. History caps are 10,000 records per source and 4,096 sources per batch. Truncation is visible; exceeding source capacity raises an error. IP strings should be canonicalized upstream so alternate IPv6 spellings do not become separate identities. Distributed identities, NAT and spoofing remain unresolved.

## Offline packet capture

`python run_ids.py pcap capture.pcap --output results/capture_predictions.csv` supports stored PCAP/PCAPNG through Scapy. IPv4/IPv6 TCP/UDP packets are grouped by directional five-tuple plus a fixed sixty-second bucket. Byte counts use present network-layer bytes. Flag counts are measured from decoded TCP headers. Single-packet duration is floored at one microsecond and that policy is reported.

Default limits are 200,000 packets and 50,000 aggregated flows. The reader reports unsupported, malformed, IPv4-fragmented and wire-truncated packets and whether a capacity limit was reached. Incomplete supported captures receive a review reason. It does not send packets, require live capture, infer authentication outcomes, reassemble fragments/streams or remove retransmissions. The source history counts directional observed records, not verified TCP handshakes.

The included packet example is a constructed offline fixture, not a capture from a real attacked network. Format support and exact counter tests do not establish detection accuracy on operational packet captures.

## Synthetic dataset

Training/calibration/validation/test use separate seeds and sources. Each episode has twelve observations. Benign profiles include web, backups, administrative fanout, DNS bursts and legitimate authentication. Attack profiles include fast/slow/mixed scans, SYN/UDP/request floods and SSH/FTP/RDP-like failures. Twelve percent of observations hide authentication outcomes to exercise missing-evidence handling.

Final traffic changes duration, volume and size scales without changing labels or exposing metadata to the model. This is a synthetic shift, not an independent real network. Source addresses and timestamps are illustrative; they are not contact targets. Ground truth exists because the generator created the episode, not because a packet sensor proved intent.

## Output contract

Preserved raw/derived fields are augmented with predicted_label, ml_label, ml_confidence, confidence, benign_probability, controlling_rule, rule_matches, method, prediction_set, novelty_score, needs_review, review_reasons, queue, severity, is_alert and explanation. Confidence is final-class model support. Novelty is a score, not a probability. Only queue=alert sets is_alert=True. Reviews remain separately exportable and are never silently counted as correct classifications.
