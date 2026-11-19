#!/usr/bin/env bash
# Download the cryptography wheel the exfil simulation needs, for the demo pod's
# platform (manylinux x86_64, CPython 3.13). The demo image has no pip, so the
# attack runner copies these wheels into /tmp and runs exfil.py with PYTHONPATH.
#
# Output goes to attack/vendor/ (git-ignored). Run once before run-attack.sh.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor
pip download --only-binary=:all: \
  --platform manylinux2014_x86_64 --python-version 313 --implementation cp --abi cp313 \
  --dest vendor cryptography
echo "Vendored wheels:"
ls -1 vendor/*.whl
