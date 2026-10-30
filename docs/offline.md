# Offline and air-gapped use

Lowtide has no dependencies and makes no network connections. Every feature works with no internet.

## Move it onto an isolated machine

On a machine with internet, from a clone:

```bash
python3 -m pip install build && python3 -m build --wheel     # makes dist/lowtide-0.1.0-py3-none-any.whl
```

Copy the wheel across, then on the isolated machine:

```bash
python3 -m venv ~/lowtide-venv && ~/lowtide-venv/bin/pip install --no-index lowtide-0.1.0-py3-none-any.whl
~/lowtide-venv/bin/lowtide selftest
```

Or skip installing: the package is pure Python, so `PYTHONPATH=/path/to/lowtide/src python3 -m lowtide selftest` runs it straight from a copy of the source.

## Keeping the record safe

- The folder holds your operator log, original values and evidence hashes. Treat it as sensitive and keep it on encrypted storage.
- Secrets are never stored as text, but hostnames, usernames and file paths are.
- Evidence files copied with `--copy` are stored unencrypted with mode 600 inside `.lowtide/evidence/`. Put `.lowtide` on an encrypted volume, or encrypt evidence
  with your own tool (`age`, `gpg`) and record the encrypted file.
- To sign the closeout, set `LOWTIDE_KEY` to a long random value (kept somewhere other than the journal) before `lowtide close`, use `lowtide close --gpg-key KEYID` to sign with gpg (verify with `lowtide verify-pack`), or sign `seal.json` yourself with `ssh-keygen -Y sign`.
