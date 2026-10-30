# Offline and air-gapped use

Redsweep has no dependencies and makes no network connections. Every feature works with no internet.

## Move it onto an isolated machine

On a machine with internet, from a clone:

```bash
python3 -m pip install build && python3 -m build --wheel     # makes dist/redsweep-0.1.0-py3-none-any.whl
```

Copy the wheel across, then on the isolated machine:

```bash
python3 -m venv ~/redsweep-venv && ~/redsweep-venv/bin/pip install --no-index redsweep-0.1.0-py3-none-any.whl
~/redsweep-venv/bin/redsweep selftest
```

Or skip installing: the package is pure Python, so `PYTHONPATH=/path/to/redsweep/src python3 -m redsweep selftest` runs it straight from a copy of the source.

## Keeping the record safe

- The folder holds your operator log, original values and evidence hashes. Treat it as sensitive and keep it on encrypted storage.
- Secrets are never stored as text, but hostnames, usernames and file paths are.
- Evidence files copied with `--copy` are stored unencrypted with mode 600 inside `.redsweep/evidence/`. Put `.redsweep` on an encrypted volume, or encrypt evidence
  with your own tool (`age`, `gpg`) and record the encrypted file.
- To sign the closeout, set `REDSWEEP_KEY` to a long random value (kept somewhere other than the journal) before `redsweep close`, use `redsweep close --gpg-key KEYID` to sign with gpg (verify with `redsweep verify-pack`), or sign `seal.json` yourself with `ssh-keygen -Y sign`.
