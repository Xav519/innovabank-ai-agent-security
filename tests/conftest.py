# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# pytest automatically loads a file named conftest.py before it runs any test
# in this folder. We use that to do one small setup job: tell Python where the
# project's own code lives, so tests can simply write "import innovabank" or
# "import innovabank_harness" without installing anything.
#
# The project code is split across three top level folders:
#
#   app/          the banking agent itself (package "innovabank")
#   harness/      the attack runner and detectors ("innovabank_harness")
#   supplychain/  the model lock and model file scanner
#
# None of them is installed as a pip package, so Python would not find them
# on its own. This file adds all three folders to Python's search path.
#
# The Makefile and pyproject.toml already set PYTHONPATH to the same folders.
# This file is a safety net so tests also work when someone runs pytest
# directly from an IDE or a plain shell where PYTHONPATH was never set.
# =============================================================================

import pathlib
import sys

# Work out the repository root from this file's own location (tests/ is one
# level below the root), so it works no matter which folder pytest starts in.
ROOT = pathlib.Path(__file__).resolve().parents[1]

# Put each code folder at the front of the search path. Inserting at position 0
# (instead of appending) means our local code wins over any same named package
# that might already be installed elsewhere on the machine.
for sub in ("app", "harness", "supplychain"):
    sys.path.insert(0, str(ROOT / sub))
