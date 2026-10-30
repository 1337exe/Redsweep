#!/usr/bin/env bash
# Install Lowtide from this folder, check the machine, and run the whole test kit.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
pip install -q -e ".[dev]"
lowtide doctor
python -m pytest -q
lowtide selftest
echo
echo "Ready. Next:  lowtide demo   (look at a finished engagement)   or   lowtide lab   (watch it work on this machine)"
