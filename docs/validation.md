# Testing Lowtide in your own lab

Lowtide records, checks and refuses. The right way to trust it is to try to make it fail. This page lists ways to do that, from five minutes to a full exercise.

## 1. Five minutes: the built-in kit

```bash
lowtide selftest     # 13 checks, the last one is the live lab (skipped on Windows)
lowtide lab          # the same lab, every command shown
```

The lab starts a throwaway web app on 127.0.0.1, changes real files through it, rolls them back, and checks that Lowtide catches a rollback that was incomplete.

## 2. One hour: break it on purpose

Try each of these and confirm Lowtide objects. If one slips through, that is a bug; please open an issue.

| Try | Expected |
|---|---|
| Roll back a change but leave one file behind | `change rollback --run --verify` returns MISMATCH, closeout stays blocked |
| Edit one character in `.lowtide/journal/<you>.jsonl` | `lowtide verify` exits 3 |
| Edit a file inside `closeout-pack.zip` | `lowtide verify-pack` exits 3 |
| Point `wrap --host` at a host that is not in scope | refused before the command runs |
| Run `decide` as a name that is not on the Control Team list | refused |
| Add a change with no original value | refused |
| Paste a real-looking key or token as an original value | the journal holds a fingerprint, never the text |
| Freeze, then try to log an action against a target | refused |
| Close with a credential whose tokens are still valid | blocked until the window passes or someone accepts it in writing |

## 3. A day: run an engagement in a range

A range gives you ground truth: you know what you did and what a defender should have seen. Ranges and generators that teams commonly use:

- **Active Directory:** [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD). Elastic describes [automating GOAD and live-malware labs](https://www.elastic.co/security-labs/automating-goad-and-live-malware-labs) with detections.
- **Telemetry for the blue side:** DetectionLab and Splunk's attack_range stand up logging and a SIEM next to a target network.
- **Known actions to compare against:** Atomic Red Team (Red Canary) and MITRE Caldera run tests that map to ATT&CK techniques, so you can check that `lowtide review` and `lowtide navigator` agree with what actually ran.
- **Cloud:** CloudGoat (Rhino Security Labs) for AWS, and your own throwaway projects for GCP and Azure.

Suggested drill:

1. Two operators with their own `LOWTIDE_OPERATOR`. One person plays the Control Team.
2. Log everything through `wrap` and the ledger. Make at least five state changes, including a cloud role or an account.
3. Have the person playing blue trigger a staged "detection" part way through. Freeze, write a SITREP from the log, let the Control Team decide, resume.
4. Clean up, and let the second operator do the read-backs (`require_second_operator`).
5. Export the range SIEM's alerts as CSV and run `lowtide review`. Compare what it says was seen with what you know.

## 4. A real engagement: shadow mode

Run Lowtide **beside** your normal process, with the client's consent, without letting it gate anything. At the end:

- take your usual cleanup checklist and Lowtide's `close --check` list;
- count the items only Lowtide found, the items only your checklist found, and any false alarms;
- send us those counts (no client data): they are the most useful feedback we can get.

## 5. Replaying old work

Export an old, scrubbed log (CSV) and import it with `lowtide import csv log.csv --map time=COL --map text=COL`. Check that the guessed action classes and the review make sense. Imports are history, so scope is not enforced.

## What has and has not been tested

| | |
|---|---|
| Unit tests (63) and the test kit | Python 3.10, 3.11, 3.12, 3.13 on Linux |
| Live lab (real commands, real changes, real rollbacks) | Linux, against a local throwaway app |
| Two-operator drill (`drills/local-two-operator`) | Linux (two machines) and Windows 11, real local services; `--system` mode adds a real local user |
| GOAD-shaped replay (`drills/goad-replay`) | synthetic data in the real export format; **not** a run on GOAD |
| Real Windows events (`drills/evtx-replay`) | public sample set (EVTX-ATTACK-SAMPLES), real events with a synthetic operator log; Linux |
| gpg-signed packs | tested with a throwaway key |
| Windows 11, Python 3.12 | 60 of 61 tests passed (1 skipped), test-kit steps 1 to 12 passed; live lab skipped (needs a POSIX shell) |
| Cobalt Strike importer | a synthetic sample in the format described in public documentation; not yet a real engagement log |
| A range (GOAD and similar), a real client engagement | **not yet** |

## Public data you can test with

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES): small real Windows event logs, grouped by ATT&CK tactic. Used by `drills/evtx-replay`.
- [Security-Datasets (OTRF)](https://github.com/OTRF/Security-Datasets) and Splunk's attack_data: larger telemetry sets from lab exercises. Not yet used here.
- [GOAD](https://github.com/Orange-Cyberdefense/GOAD): the range itself. A community Azure deployment template exists at [SenSecurity/GOAD](https://github.com/SenSecurity/GOAD) if a local build is too heavy; cloud costs apply.
