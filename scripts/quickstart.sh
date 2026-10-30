#!/usr/bin/env bash
# Install Redsweep from this folder, check the machine, and run the whole test kit.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
pip install -q -e ".[dev]"
redsweep doctor
python -m pytest -q
redsweep selftest
echo
echo "Ready. Next:  redsweep demo   (look at a finished engagement)   or   redsweep lab   (watch it work on this machine)"
