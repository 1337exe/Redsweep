# Getting started

Ten minutes from install to your first clean closeout. Everything runs on your own machine. Nothing is sent anywhere.

## 1. Install

Python 3.10 or newer. Lowtide has no dependencies.

```bash
pip install git+https://github.com/1337exe/lowtide      # or: pipx install git+https://github.com/1337exe/lowtide
lowtide doctor
```

From a clone: `bash scripts/quickstart.sh` (makes a venv, installs, runs the tests and the test kit).
For machines with no internet, see [offline.md](offline.md).

## 2. Run the test kit first

Do this before you trust the tool with a real engagement.

```bash
lowtide selftest      # 13 checks, about 5 seconds, includes the live lab
lowtide lab           # the same lab with every command shown
lowtide demo          # a finished, made-up engagement to read
```

`lowtide lab` starts a small web app on 127.0.0.1, makes real changes to it, rolls them back, and shows Lowtide catching
a rollback that looked finished but was not. It touches only its own folder.

## 3. Start your engagement

```bash
mkdir acme-2026 && cd acme-2026
lowtide init --name ACME-RT --client "Acme Corp"
```

This makes a `.lowtide/` folder. Open `.lowtide/scope.json` and fill in what the client signed:

- `in_scope.hosts`: names, wildcards (`*.acme.example`) and networks (`10.20.0.0/16`)
- `out_of_scope`: things you must not touch (a managed-detection vendor's console, a payment system). This wins over in-scope.
- `forbidden_actions`: for example `payment-approval-click`
- `window`: the testing dates
- `roles.control_team`: the names of the people who decide. The red team recommends, they decide.

Anything not listed is treated as out of scope. That is on purpose.

Tell every operator who they are: `export LOWTIDE_OPERATOR=alice`. Each operator writes to their own file, so a shared folder
(git, a share, rsync) merges cleanly.

## 4. The daily loop

```bash
lowtide scope check ws1.acme.example                          # before you touch it
lowtide act lsass-access --payoff "need the service ticket" --reversible "read only, nothing changes"
lowtide wrap --host ws1.acme.example -- some-command --args    # runs it and logs it
lowtide log "tried the admin share" --host ws1.acme.example --result fail --layer authorization --assumption "svc has admin"
```

Before you change anything:

```bash
lowtide change add --kind config --host app1.acme.example --object "app setting export_limit" \
  --change "100 -> 5000" --capture "cat /etc/app/app.ini" --rollback-cmd "cp /root/app.ini.orig /etc/app/app.ini"
# ...now make the change...
```

`--capture` is a read-only command that prints the state. Lowtide runs it now, keeps the result, and can run it again later.

When you clean up:

```bash
lowtide change rollback C-1a2b3 --run --verify       # runs the rollback command, then reads the state back
lowtide close --check                                # what still blocks closeout?
```

## 5. Close

```bash
lowtide close
```

If anything is left behind, it refuses and tells you exactly what. When it is clean it writes a report (`closeout.html`,
`.md`, `.json`), a client handoff list, a seal, and a zip pack that anyone can check with `lowtide verify-pack`.

Next: [the operator guide](operator-guide.md), [the Control Team guide](control-team.md), [plugging it into your tools](integrations.md).
