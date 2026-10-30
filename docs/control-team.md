# Control Team guide

The Control Team owns the engagement for the client. The red team recommends; the Control Team decides. Redsweep enforces that split.
The vocabulary follows the TIBER-EU and DORA threat-led testing frameworks, but nothing here requires them.

## Set it up before testing starts

- Name the Control Team in `scope.json` (`roles.control_team`). Only those names can decide and resume.
- Agree a channel on infrastructure the blue team does not administer, and a night-time deputy.
- Decide your tripwires in `scope.json` (`tripwires`): things the red team may not do without a Control Team decision.
  Defaults: `external_party` (contacting outside parties), `production_containment` (touching production response), `exec_crisis` (starting an executive crisis process).

## When the blue team notices

```bash
redsweep detect L2 --host fs01 --source SOC --evidence "analyst opened a ticket"
redsweep levels                      # the scale (edit it in config.json)
```

Default scale: L0 telemetry exists, nobody looked · L1 an alert fired, nobody triaged it · L2 an analyst looked · L3 treated as malicious, incident opened ·
L4 responders acted against red assets · L5 the escalation left the security function.

## Freeze first, diagnose second

```bash
redsweep freeze --reason "beacon missed three check-ins"
```

Operator activity on targets stops. You can still roll back, contain credentials, write SITREPs, record decisions and handle evidence.
The freeze lists everything still running with no operator (from the ledger). That list is what the Control Team must decide about.
If an item you know about is not in the ledger, put it in the ledger now.

Stop conditions end activity at once and need a recorded decision to resume:

```bash
redsweep stop --condition other-intruder --reason "second set of credentials in use on the file server"
```
Conditions: `other-intruder`, `unexpected-impact`, `out-of-scope-contact`, `tooling-control-lost`, `channel-lost`.

## SITREP

```bash
redsweep log --list                   # find the entries to cite
redsweep sitrep --observed "SOC incident opened 01:40 UTC after an EDR alert at 00:52" \
  --assessed "they have our file-server activity; nothing shows the test user" \
  --ask "continue, go dark, or end the scenario?" --risk "client sees a real response" \
  --based-on A-1a2b3,A-4c5d6
```

A SITREP must cite operator log entries, so what you report matches what was done. EXPOSED, AUTONOMOUS and DATA HELD are filled in from the
ledger and the evidence list. Show an old one with `redsweep sitrep --show 1`.

## Options and decisions

Options: `continue`, `go-dark`, `burn-and-pivot`, `leg-up`, `limited-purple`, `suspend`, `end-scenario`.

```bash
redsweep recommend go-dark --why "the response is worth measuring; no new activity" --also suspend    # red team
redsweep decide go-dark --by pat --why "measure the response until day 5" --tag production_containment  # Control Team
redsweep resume --approved-by pat --decision D-1a2b3
```

A red-team member cannot decide. A tripwire action (`--tripwire external_party --decision D-...`) is refused unless a Control Team decision with that tag exists.

## Closing

`redsweep close` checks the journal, every change, every credential, evidence custody, open stop conditions and scope overrides. The report is
for the client; `client-handoff.md` lists what they need to rotate, revoke or watch. Joint review: [integrations.md](integrations.md#purple-review).
