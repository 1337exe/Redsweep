# Reference

## Commands

| Command | What it does |
|---|---|
| `init` | start an engagement folder |
| `status` | where things stand |
| `scope check TARGET [--class C]` | in, out or unlisted; window and forbidden-action checks |
| `log TEXT` / `log --list` | write to or read the operator log |
| `wrap -- CMD` | run a command and log it |
| `act CLASS --payoff --reversible` | price an action and log the plan |
| `price [CLASS]` | what an action leaves behind |
| `change add\|list\|show\|rollback\|verify\|waive` | the change ledger |
| `cred add\|list\|show\|step\|accept-window` | credential containment |
| `evidence add\|list\|handoff\|destroy` | evidence custody |
| `canary make\|check` | synthetic record and digest proof |
| `detect LEVEL` / `levels` | record and define detection levels |
| `freeze` / `stop` / `resume` | stop activity, and the Control Team lifting it |
| `recommend` / `decide` | red recommends, Control Team decides |
| `sitrep` | situation report built from the log |
| `teardown` | ordered cleanup list |
| `close [--check]` | the closeout gate and reports |
| `review BLUE` / `navigator BLUE` | purple review and ATT&CK layer |
| `import` / `export` / `handoff` | other tools, and the client's to-do list |
| `verify` / `seal` / `verify-pack` | integrity (`close` and `seal` take `--gpg-key KEYID` to sign) |
| `mcp` | MCP server on stdio |
| `doctor` / `demo` / `lab` / `selftest` | the test kit |

Every command takes `--home` (folder) and `--operator`. Defaults: `$REDSWEEP_HOME` or `./.redsweep`; `$REDSWEEP_OPERATOR` or your user name.

## Exit codes

`0` fine · `1` refused or error (including every rules-of-engagement refusal) · `2` closeout has blockers, or a read-back did not match · `3` a journal or pack failed verification.

## `config.json`

| Key | Default | Meaning |
|---|---|---|
| `strict_scope` | `true` | a target not listed in scope is refused |
| `require_second_operator` | `false` | the read-back must come from a different person than the rollback |
| `min_verify_strength` | `attested` | `attested`, `manual` or `auto`: the weakest read-back accepted |
| `assumption_stop_after` | `2` | warn when one assumption fails this many times with nothing new learned |
| `sitrep_requires_log` | `true` | a SITREP must cite operator log entries |
| `levels` | L0..L5 | the detection scale |
| `name`, `client`, `default_operator` | | labels |

Unknown keys are rejected, so a typo cannot silently turn a safety setting off.

## `scope.json`

`engagement`, `window {start,end}`, `in_scope {hosts, cloud_projects, accounts}`, `out_of_scope []`, `forbidden_actions []`, `roles {control_team, red_lead}`, `tripwires []`.
Patterns: exact names, `*` wildcards, and CIDR networks. Out of scope wins. URLs and `host:port` are reduced to the host.

## Files

```
.redsweep/
  config.json  scope.json
  journal/<operator>.jsonl      append-only, one JSON event per line, each with the hash of the one before
  evidence/                     only if you used --copy (mode 600)
  reports/                      closeout.md .html .json, client-handoff.md, seal.json, closeout-pack.zip
```

## Security model, in plain words

- The journal is **tamper-evident, not tamper-proof**. Each event hashes the previous one, so an edit or deletion is detected by `redsweep verify`.
  Someone who can rewrite a whole file and recompute every hash can forge it. To close that gap, sign the closeout (`REDSWEEP_KEY`, or sign `seal.json` yourself) and keep the seal's
  head hashes somewhere else, such as the report you send the client.
- Secrets are replaced by a fingerprint before they reach the journal. The detector looks for common key, token and password shapes; it cannot know your own secret formats. Use `--secret`.
- `capture`, `rollback-cmd` and `wrap` run commands through your shell, as you, on the machine where Redsweep runs. The MCP server never runs them.
- Imports are not scope-checked, because they are history.
- Developed and tested on Linux with Python 3.10 to 3.13. Windows is experimental (CI job only).
- Redsweep scans nothing, exploits nothing and evades nothing. It records, checks and refuses. Use it only on systems you are authorised to test.
