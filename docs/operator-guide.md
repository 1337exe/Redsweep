# Operator guide

The idea: **write it down before you do it, and prove it is undone before you leave.**

## The three questions

Before each action, ask: What does this buy me? What does it leave behind, and where is it recorded? Can I undo it, and can I prove it?

```bash
lowtide price lsass-access          # what it leaves and which events record it
lowtide price --list                # all classes in the price table
lowtide act bulk-kerberoast --payoff "one service ticket" --reversible "nothing on the target changes"
```

The price table is a starting point from public audit documentation. Audit policy differs by site. Confirm each row in your own lab.

## The operator log

```bash
lowtide log "what you did and what happened" --host H --result ok|fail|partial --layer LAYER --assumption "what you believed"
lowtide wrap --host H --class CLASS -- COMMAND ARGS        # run and log in one step (exit code and an output hash are kept)
lowtide log --list -n 30
```

- **Log the failures.** A log that only has successes cannot be checked. Closeout warns when there are ten actions and no failure.
- **Name the assumption.** If the same assumption fails twice with nothing new learned, Lowtide warns you to stop, write down why, and change the path.
- **Pin the failure to a layer.** `--layer` takes `local-config`, `network-path`, `time`, `authentication`, `authorization`, `target-state`, `tooling`.
  "Kerberos is flaky" is not a diagnosis. Which layer failed?
- **All times are UTC.** Lowtide stores UTC only. A time with no zone is read as UTC.

## The change ledger

Everything that changes state and could be left behind: a setting, a file, an account, a way back in, an implant, a cloud role,
red infrastructure, a domain. Kinds: `config file account persistence implant iam infra domain data other`.

```bash
lowtide change add --kind K --host H --object O --change "what you change" --capture "READ-ONLY COMMAND" --rollback-cmd "COMMAND"
```

Lowtide refuses to record a change with no original value. Ways to give one, best first:

1. `--capture CMD`: Lowtide runs it now and again at read-back. The check is done by the tool, not by you.
2. `--original-file F` or `--original TEXT`: you supply the value; at read-back you supply the value again.
3. `--created`: the object did not exist before (the original value is "absent").

Other options: `--ignore REGEX` (drop lines like timestamps and etags when comparing), `--secret` (store only a fingerprint; anything that looks
like a key, token or password is fingerprinted automatically), `--autonomous` (it keeps running with no operator, so it appears on the freeze list).

Undoing it:

```bash
lowtide change rollback ID --run --verify      # run the stored rollback command, then read back
lowtide change rollback ID --how "removed the line by hand"
lowtide change verify ID                        # re-run the capture and compare with the original
lowtide change verify ID --readback-value "..." # you supply what you saw
lowtide change verify ID --attest --note "looked at the host; port closed"   # weakest: a human says so
lowtide change waive ID --reason "client keeps it" --by "pat"
```

A rollback is not finished until a read-back matches. A read-back has a strength: `auto` (Lowtide ran the capture), `manual` (a value
was compared), `attested` (a person said so). Set `min_verify_strength` in `config.json` to require more. Set `require_second_operator` so the read-back
must come from someone other than the person who rolled back.

If a rollback leaves a *control* behind (for example you edited a role and the account that could edit roles still can), record it:
`lowtide change rollback ID --how ... --durable "analyst still holds iam.roles.update"`. It goes in the report and the client handoff.

## Credentials

```bash
lowtide cred add --family gcp-sa-key --principal svc@proj.iam --material-file key.json --host H
lowtide cred step K-1 1 --note "deleted local copy"
lowtide cred accept-window K-1 --reason "client accepts 60 minutes" --by pat
```

Only a hash of the material is kept. Each family has its own containment steps (see `lowtide cred add` output). Tokens already issued stay valid until
they expire, so Lowtide records the latest possible issue time and the lifetime, and closeout waits for the window to pass (or for someone to accept it in writing).

## Evidence and canaries

```bash
lowtide canary make --label claims       # a synthetic record and its digest, for the Control Team to plant
lowtide canary check --file out.json --expect DIGEST     # prove you read it, keep nothing sensitive
lowtide evidence add out.json --label "canary read" --ladder canary --copy
lowtide evidence handoff E-1 --to pat --purpose "kept for the report"
lowtide evidence destroy E-1 --method "overwrite and delete" --witness pat --delete
```

The ladder runs from least to most sensitive: `authority` (you could do it), `metadata`, `canary`, `real-record`. A real customer record needs a named Control Team approval.

## Teardown

```bash
lowtide teardown      # the cleanup order, built from the ledger: implants, persistence, accounts, roles, config, files, data, infrastructure, domains
```
Keep domains registered until the client confirms the engagement is over.
