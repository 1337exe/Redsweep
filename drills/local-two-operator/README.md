# Local two-operator drill

Two red operators and a Control Team work one engagement on a single machine, against a real local web app and a real listener, with a small stand-in blue sensor.
Everything stays on `127.0.0.x` and in one folder. Nothing leaves the machine.

```
python drill.py                # Linux or Windows: a user list inside the app, a config file, a listener
./run.sh /tmp/drill            # the same drill as a shell script (Linux)
./run.sh /tmp/drill --system   # also adds and removes one local user (root, throwaway machine only)
```

`drill.py` finishes with `DRILL RESULT: 13 of 13 checks behaved as expected` when everything behaved as it should.

The roles: `alpha` makes the changes, `bravo` does the read-backs (the engagement requires a second operator), `casey` is the Control Team.

What the run goes through:

1. Scope: a command aimed at an out-of-scope address is refused before it runs.
2. Changes: a config edit, a new account and a listener are recorded with their original state, then made.
3. A failing path: the same assumption fails twice and Redsweep says stop.
4. A staged escalation from blue: freeze, a refused action while frozen, a SITREP built from the log, a recommendation, a decision, a resume.
5. Teardown: alpha rolls back; one rollback is left incomplete on purpose; bravo's read-back catches it; it is fixed and proved.
6. Closeout, purple review against the detector's timeline, ATT&CK Navigator layer, pack verification.

`blue_watch.py` has three rules and misses a lot on purpose. It is a stand-in so the review has something to score, not a model of a real SIEM.
To drill against a real range, swap its CSV for your own blue timeline.
