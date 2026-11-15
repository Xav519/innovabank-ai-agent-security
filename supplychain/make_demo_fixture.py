# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# This small script creates a fake, booby-trapped model file on purpose, so we
# can prove that the model scanner (ib_supplychain/scan.py) catches it.
#
# Why we need it: a scanner that never finds anything looks exactly the same
# as a scanner that is broken. The only way to know it really works is to hand
# it something truly malicious and check that it says no. This script makes
# that "something".
#
# What the file contains: a "pickle" (Python's way of saving objects) named
# pytorch_model.bin, so it looks like a normal PyTorch model. Next to some fake
# weights it hides an instruction that says "run this shell command". If any
# program ever LOADED (unpickled) this file, the command would run. That is
# the real attack that booby-trapped models on public model hubs use.
#
# Why it is safe:
#   - Writing the file runs nothing. The hidden command only runs when the
#     file is loaded, and nothing in this repository ever loads it. The
#     scanner only READS the instructions, it never follows them.
#   - Even if it were loaded, the command is a harmless "echo" that just
#     prints a message.
#   - The file is created on demand in a temporary folder and never committed,
#     so no malicious file lives in the repository.
#
# Who uses it:
#   - `make gate-demo`: builds the file, shows the scanner rejecting it, then
#     deletes it.
#   - CI ("Prove the scanner rejects a malicious artifact"): builds the file
#     and FAILS the build if the scanner lets it through.
#
# Usage:
#   python supplychain/make_demo_fixture.py /tmp/demo
# =============================================================================

"""Write a malicious pickle for demonstrating the scanner.

Creating the file is harmless: the payload only runs if something unpickles
it, and nothing in this repository ever does. The file is generated on demand
and never committed.

  python supplychain/make_demo_fixture.py /tmp/demo
"""
import os
import pathlib
import pickle
import sys


# The trap itself. When Python saves (pickles) an object, it asks the object
# "how should I rebuild you later?" by calling __reduce__. A normal object
# answers "call my class". This one answers "call os.system with this
# command". So the saved file now contains the instruction "import os and run
# a command", which is exactly what the scanner must spot. Pickle records
# where os.system really lives, so the file says "posix.system" on Linux and
# "nt.system" on Windows. Both are on the scanner's DANGEROUS_MODULES list,
# so it is reported as CRITICAL on any machine.
class _Payload:
    def __reduce__(self):
        # A harmless echo instead of a real attack: if this ever did run by
        # mistake, it would only print a line, never cause damage.
        return (os.system, ("echo innovabank-demo: code ran at model load",))


def main() -> int:
    # Output folder: taken from the command line, or "demo-artifacts" by
    # default. CI passes its own temp folder so the file never touches the repo.
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "demo-artifacts")
    out.mkdir(parents=True, exist_ok=True)
    # Named like a real PyTorch model on purpose: the attack works because the
    # file looks normal, and the scanner has to catch it anyway.
    target = out / "pytorch_model.bin"
    # Mix real looking weights with the hidden payload, the way an attacker
    # would hide a trap inside an otherwise working model. pickle.dumps only
    # WRITES the instructions, it does not run them, so this line is safe.
    target.write_bytes(pickle.dumps({"weights": [0.1, 0.2], "hook": _Payload()}))
    print(f"wrote {target}")
    # Exit code 0 means "file created". The pass or fail decision is made by
    # the scanner afterwards, not by this script.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
