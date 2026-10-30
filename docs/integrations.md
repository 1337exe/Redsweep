# Plugging Lowtide into what you already use

Lowtide does not replace your C2, your reporting platform or your SIEM. It sits beside them and keeps the one record none of them keep:
what you changed, whether you undid it, and who knew what when.

| You use | How it fits | Command |
|---|---|---|
| Cobalt Strike | read operator input from `beacon_*.log` into the log | `lowtide import cobalt-strike beacon_123.log --year 2026 --host ws1.acme.example` |
| Ghostwriter | import its operation-log CSV, export yours back | `lowtide import ghostwriter oplog.csv` · `lowtide export ghostwriter --out oplog.csv` |
| Any other C2 (Sliver, Mythic, Havoc, your own) | run its CLI through `wrap`, or import its export as CSV or JSONL | `lowtide wrap --host H -- sliver-client ...` · `lowtide import csv log.csv` |
| Your shell and scripts | wrap commands so they are logged with exit code and an output hash | `lowtide wrap -- ./my-script.sh` |
| Obsidian, Notion, a wiki | export the log as a Markdown table | `lowtide export markdown --out log.md` |
| A SIEM or the client's blue team | feed their timeline to the review | `lowtide review blue.csv` |
| ATT&CK Navigator | a layer coloured by what blue saw | `lowtide navigator blue.csv --out layer.json` |
| Git, a share, rsync | each operator has their own journal file, so the folder merges without conflicts | copy `.lowtide/journal/*.jsonl` |
| An AI agent | the MCP server gives it the rules, no shell | [mcp.md](mcp.md) |
| CI | refuse to finish a project that is not clean | [ci-cd.md](ci-cd.md) |

## Importing

Imported rows keep their original time and are marked as imported. Importing the same file twice adds nothing the second time, so you can
re-import a growing log. Scope is **not** enforced on imports (they are history, not actions).

```bash
lowtide import cobalt-strike beacon_123.log --year 2026 --host ws1.acme.example --dry-run     # see what would be added
```

- **Cobalt Strike:** Lowtide reads the `[input]` lines (what an operator typed) and marks the previous input as failed when an `[error]` line follows.
  Beacon logs carry no year or host, so give `--year` and `--host`. Check one of your own logs with `--dry-run` first; formats vary a little between versions.
- **CSV and JSONL:** needs `time` and `text` (or `command`). Optional: `host`, `result`, `class`, `operator`. If your export uses other column names, map them:
  `lowtide import csv export.csv --map time=timestamp --map text=task_command --map host=callback_host --map operator=user`. Times with no zone are read as UTC.
  This is how to bring in exports from C2 frameworks that have no dedicated importer yet.
- **Ghostwriter:** reads the standard operation-log columns (`start_date`, `dest_ip`, `command`, `description`, `operator_name`).
- A rough action class is guessed from the command (for example `psexec` becomes `remote-service-create`). Check the guess; it feeds the review and the Navigator layer.

## Purple review

After the engagement, the client sends their alert timeline (CSV or JSONL with `time`, `host`, `source`, `summary`, `level`).

```bash
lowtide review blue.csv --window 30
```

For each red action it finds blue events on the same host within the window after it, and reports: what was seen and how fast, what was **not** seen
(replay those paths with blue), and blue events with **no** red action. Those last ones are either false positives, someone else, or red activity that
was never logged, and each one needs an answer. It then picks the three most expensive actions and writes them as candidate standing rules.

`lowtide navigator blue.csv` writes an ATT&CK Navigator layer. Score 0 means used and never seen; 1 to 6 follow L0 to L5.
Open it at <https://mitre-attack.github.io/attack-navigator/> (Open Existing Layer, Upload from local).

## A cloud engagement

Cloud work is mostly permissions changing state, so the ledger fits naturally:

```bash
lowtide change add --kind iam --host bw-claims-dev --object "custom role ReleaseObserver" --change "add secretmanager.versions.access" \
  --capture "gcloud iam roles describe ReleaseObserver --project bw-claims-dev --format=json" \
  --ignore '"etag"' --rollback-cmd "gcloud iam roles update ReleaseObserver --project bw-claims-dev --file original-role.yaml"
```

Notes: use `--ignore` for fields that change on every read (etags, update times). If the account that could edit the role still can after you roll back,
add `--durable "analyst still holds iam.roles.update"` so the client sees it. Treat propagation delays as "not yet", not as "denied": wait, read back again.

## Team use

Each operator sets `LOWTIDE_OPERATOR` and writes to `journal/<name>.jsonl`. Put `.lowtide/` in a private git repo or a shared folder. Events from all operators are
merged in UTC order when state is built. If clocks differ, the earlier timestamp wins the ordering, so keep time in sync (chrony or similar).
