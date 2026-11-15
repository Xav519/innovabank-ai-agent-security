# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# IN ONE SENTENCE: this file checks that the commands written in the
# README and docs actually do what the docs say they do.
#
# SOME BACKGROUND
#
# The project has a file called "Makefile". It is a list of shortcuts.
# Instead of typing a long command, you type a short one, and "make"
# replaces it with the long one. For example, you type:
#
#     make attack-live-one MODE=hardened TRIALS=3 ONLY=SD-02
#
# and make actually runs:
#
#     python -m innovabank_harness run --target aws
#         --outputs infra/envs/hardened/outputs.json --trials 3 --only SD-02
#         --out results/live-hardened.json
#
# That long command launches attacks against the chatbot deployed on AWS.
#
# THE PROBLEM THIS FILE PREVENTS
#
# The docs only show the short version. Nobody looks at the long version.
# So if someone makes a typo in the Makefile, for example MODE=hardened
# ends up pointing at the vulnerable chatbot, nobody notices. The command
# still runs, it just attacks the wrong thing or saves results in the wrong
# place. You would only find out after paying for a real run on AWS.
#
# HOW THE TESTS WORK
#
# They ask make to PRINT the long command without running it ("make -n").
# Then they read that printed text and check it contains the right pieces.
# Nothing is sent to AWS, so the tests are free and take a fraction of a
# second.
#
# WHAT IS CHECKED (3 tests)
#
#   1. When you fill in every setting (MODE, TRIALS, ONLY, OUT), each one
#      ends up in the long command.
#   2. When you only give MODE, the missing settings get safe defaults:
#      1 trial (cheap), every attack, and the usual results file.
#   3. The README and docs never show a raw "python -m innovabank_harness"
#      command without PYTHONPATH in front. make sets PYTHONPATH for you,
#      but someone copying the raw command into a terminal would get
#      "No module named innovabank_harness". This test catches that.
#
# NOTE: if make is not installed (common on Windows), the whole file is
# skipped, not failed. CI on Linux has make, so the tests run there.
# =============================================================================

"""The documented make targets expand to the harness calls the docs promise."""
import pathlib
import re
import shutil
import subprocess

import pytest

# The project root (one folder up from tests/). The Makefile and the docs
# live there, so every command and file lookup starts from this folder.
ROOT = pathlib.Path(__file__).resolve().parents[1]

# Skip the whole file if make is missing (common on Windows) instead of
# failing, since a missing tool says nothing about whether the Makefile is
# correct.
pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")


def dry_run(*args: str) -> str:
    # "-n" makes make print the commands without running them, so nothing
    # touches AWS. "-s" hides make's own chatter so only the commands remain.
    # check=True turns a broken Makefile into a test failure right away.
    return subprocess.run(["make", "-n", "-s", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def test_attack_live_one_targets_one_stack_with_trials_filter_and_output():
    # Give every optional setting a value and check each one reaches the
    # harness. The split/join squashes the line break the Makefile uses to
    # wrap the long command, so the text can be matched as one line.
    cmd = " ".join(dry_run("attack-live-one", "MODE=hardened", "TRIALS=3", "ONLY=SD-02",
                           "OUT=results/iam-backstop.json").split())
    # MODE must pick the hardened stack's outputs file, otherwise the run
    # would attack the wrong deployment.
    assert "-m innovabank_harness run --target aws --outputs infra/envs/hardened/outputs.json --trials 3" in cmd
    # ONLY limits the run to one attack (cheaper), and OUT keeps this result
    # from overwriting the normal live results file.
    assert "--only SD-02" in cmd and "--out results/iam-backstop.json" in cmd


def test_attack_live_one_defaults():
    # Only MODE is given. The rest must fall back to safe defaults.
    cmd = " ".join(dry_run("attack-live-one", "MODE=vulnerable").split())
    # One trial by default keeps an accidental run cheap.
    assert "--outputs infra/envs/vulnerable/outputs.json --trials 1" in cmd
    # No ONLY means the whole catalog runs, so "--only" must not appear at
    # all (an empty "--only" would confuse the harness). Without OUT, the
    # result lands in the standard per-mode file the live report reads.
    assert "--only" not in cmd and "--out results/live-vulnerable.json" in cmd


def test_docs_never_call_the_harness_without_pythonpath():
    """A bare `python3 -m innovabank_harness` fails outside make, which sets PYTHONPATH."""
    # Find lines that start a harness command but have no "PYTHONPATH="
    # earlier on that line. re.M makes "^" match at the start of every line.
    # Those are exactly the commands a reader would copy and see fail with
    # "No module named innovabank_harness".
    bare = re.compile(r"^(?!.*PYTHONPATH=)\s*python3? -m innovabank_harness", re.M)
    # Check the README and every Markdown page in docs/, since those are the
    # places people copy commands from.
    offenders = [str(p.relative_to(ROOT)) for p in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]
                 if bare.search(p.read_text(encoding="utf-8"))]
    # Listing the file names (not just True/False) tells you where to fix it.
    assert offenders == []
