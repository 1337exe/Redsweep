# Contributing

Redsweep's rule: **"done" does not count until the state is read back.** A check must be able to say no, and "I could not tell" must never become a pass.

```bash
git clone <your fork> && cd redsweep
bash scripts/quickstart.sh
```

Before a pull request: `python -m pytest -q` and `redsweep selftest` must pass. Add a test for every change, including one that should be refused.

Good first contributions:
- importers for other C2 logs (Sliver, Mythic, Havoc): add to `importers.py` with a real, scrubbed sample and a test
- more rows for the price table (`pricing.py`), with the event IDs and a note on which audit setting they depend on
- more credential families and containment steps (`model.py`)
- a Windows port of the file locking in `store.py`
- real-world feedback: what did you need that was not there?

Please do not add anything that attacks, exploits or evades. Redsweep is for record-keeping, safety and proof.
