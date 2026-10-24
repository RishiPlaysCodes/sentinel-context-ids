# Local research quality and reproduction record

Date: 25 October 2026 (Asia/Calcutta). Version: Sentinel Context IDS 3.0.

## Verified implementation

- Runtime dependency check: passed in an isolated Python 3.13.9 environment, system site packages disabled.
- Full research test suite: **55 passed in 30.09 seconds**.
- Source-only checkout, with no supplied model binaries or large generated datasets: build completed and **55 tests passed in 30.93 seconds**.
- Source-only build reproduced final all-row accuracy 0.9934027777777777.
- CLI on minimal unlabeled CSV: passed.
- CLI on the constructed offline PCAP: passed; exact packet/flag count tests require no live transmission or packet driver.
- Black formatting and critical Ruff checks: passed. Decision-code formatting preserved syntax trees and fitted artifacts; provenance is retained.
- Strict original CSV header checks reject duplicate, blank and whitespace-padded names before pandas renaming.
- Secret-pattern scan of publishable text: no matches for common token/private-key markers. This is a limited pattern check, not a certification.
- Five-page report and nine-page concept handbook rendered and visually inspected; feature tables, contents, figures, pagination and legibility checked.
- Running Streamlit dashboard visually checked; a separator encoding defect found during review was replaced with ASCII text.
- Source checkout reconstructs its legacy baseline from fixed source/generation recipes rather than requiring an opaque downloaded model.

See VERIFICATION_LOG.txt for local runtime commands and exit codes. The source-only test/build logs are retained with the delivery verification artifacts. GitHub Actions is configured to repeat install, formatting, critical lint, build and tests on Python 3.13/Linux; its actual remote status must be read after publication.

## Research evidence

| Population / metric | Measured value |
| --- | ---: |
| Locked synthetic test rows / sessions | 2,880 / 240 |
| All-row accuracy | 99.34% |
| All-row macro F1 | 99.34% |
| Raw class false-positive rate | 1.39% |
| Review rate | 8.68% |
| Accepted coverage / accuracy | 91.32% / 99.54% |
| Confident security-alert precision / recall | 99.85% / 91.30% |
| Historical known stress accuracy | 88.33% versus 15% prior |
| Historical clear accuracy | 96.21% versus 100% prior |
| Hidden-intent challenge accuracy / review rate | 50% / 41.67% |

All reviewed rows remain in primary class metrics. Class false positives, security-alert false positives and review workload are distinct. The historical stress population was already known during development and is not an untouched test. Its recognized scans go to review when history is absent; confident-alert recall there is zero.

## Contribution and limits

The new core ensemble already achieves 99.31% on the locked test. Context adds one correct flow, and rules change no final classes. Broader training is a major explanation for the large system-level improvement. It is not valid to claim the architecture alone caused the gain, that this is a world-first algorithm, or that it universally outperforms mature IDS tools.

No representative real/public traffic efficacy benchmark has been completed. The synthetic generator still has shortcuts. Calibration and prediction sets degrade under shift. Missing authentication/history, hidden authorization, very slow/distributed activity, NAT and capture quality remain limitations. Security alerts and review items require analyst interpretation; no autonomous blocking is implemented.

## Included documentation

README; complete working-concept handbook; assessment-length technical report; data contract; prior-art research; experiment interpretation; model card; deployment/threat model; interview guide; requirement matrix; video storyboard; source/method hashes and generated results. AI assistance is disclosed. The candidate must understand and explain the work personally.

## Submission boundary

The user authorized a public GitHub repository for this version. Publication is separate from the required 8-10 minute recorded video. A storyboard is supplied, and no recording is claimed. The local ZIP includes generated artifacts; a source clone builds them reproducibly.
