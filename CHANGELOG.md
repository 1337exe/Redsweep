# Changelog

## Unreleased

- `wrap` now stamps an action with the time it started, not the time it finished.
- `review` credits each blue event to one red action (the one named by `detect --action`, otherwise the closest earlier action on the same host).
- `close` and `seal` can sign with gpg (`--gpg-key`); `import csv|jsonl` takes `--map NAME=COLUMN`.
- Windows: the journal now takes a real file lock on Windows, the test kit's rollback steps run there too (only the live lab still needs a POSIX shell), and the demo prints PowerShell hints.
- `review` no longer treats two different IP addresses as the same host because they share a first number.
- `review` also scores failed attempts (a failed logon still leaves a log).
- New: `drills/goad-replay`, a replay of synthetic GOAD-shaped data in the Windows event export format.
- New: `drills/evtx-replay`, which replays real Windows events from a public sample set.
- `wrap --text` gives an action a readable description (the full command is still stored).
- New: `drills/local-two-operator` (`drill.py` runs on Linux and Windows), a two-operator drill on real local services. New: `docs/validation.md`.

## 0.1.0

First release. Change ledger with verified rollback, rules of engagement as code, credential containment, evidence custody and canary proof,
freeze / stop / SITREP / Control Team decisions, closeout gate with report, handoff list, seal and pack, purple review and ATT&CK Navigator layer,
Cobalt Strike / Ghostwriter / CSV / JSONL import, Ghostwriter / JSON / Markdown export, MCP server, demo, live lab and test kit.
