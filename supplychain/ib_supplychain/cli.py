# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# This is the command line entry point for the supply chain checks. It is what
# runs when you type `python -m ib_supplychain ...` (or `make gate`).
#
# An AI system does not only run our code. It also runs models and model files
# that came from somewhere else. If one of those is swapped, tampered with, or
# simply not the version we approved, the agent can behave in ways we never
# tested. This file is the "border control" that stops that before deploy.
#
# It offers two commands:
#
#   gate   The full check used by `make gate` and by CI. It:
#            1. reads the model lock file (the list of approved models and
#               files, with their expected hashes),
#            2. scans every model file on disk for dangerous content
#               (for example a pickle that would run code when loaded),
#            3. checks that the files match the lock, and that every model ID
#               used in app/ or infra/ is one we approved,
#            4. if anything is wrong, prints why and exits with code 1 so the
#               build fails,
#            5. if all is clean, writes the ML-BOM (a CycloneDX "bill of
#               materials" listing every model and file we ship).
#
#   scan   Only step 2, on any file or folder you point it at. Handy for
#          checking a new model file before adding it, and CI uses it to prove
#          the scanner really rejects a malicious pickle.
#
# The real work lives in scan.py, provenance.py and mlbom.py. This file just
# wires them together, prints readable output, and turns the result into an
# exit code (0 = pass, 1 = fail) that Make and CI understand.
# =============================================================================

# Note: the docstring below is also shown as the `--help` text (see main()),
# so it is kept short and command focused.
"""Supply chain gate.

  python -m ib_supplychain gate            fail the build on any violation, write the ML-BOM
  python -m ib_supplychain scan <path>     scan a file or directory of model artifacts
"""
from __future__ import annotations

import argparse
import json
import pathlib

import yaml

from . import mlbom, provenance, scan

# Repository root (this file is supplychain/ib_supplychain/cli.py, so two
# levels up). Default paths are built from it so the commands work no matter
# which folder you run them from.
ROOT = pathlib.Path(__file__).resolve().parents[2]

# Severities that fail the build. The scanner only reports these three levels,
# so in practice any finding blocks. Listing them explicitly keeps the rule
# visible, and means a future "LOW" or "INFO" level would not break builds
# unless someone decides it should.
BLOCKING = {"CRITICAL", "HIGH", "MEDIUM"}


def _print_findings(scans: list[dict]) -> int:
    """Print each scanned file and its findings, return how many are blocking.

    Shared by both commands so the output looks the same everywhere. Only a
    short hash prefix is shown: enough to spot a changed file at a glance
    without flooding the CI log.
    """
    blocking = 0
    for s in scans:
        print(f"  {s['file']}  format={s['format']}  sha256={s['sha256'][:16]}...")
        for f in s["findings"]:
            print(f"    [{f['severity']}] {f['rule']}: {f['detail']}")
            # True counts as 1, False as 0, so this tallies blocking findings.
            blocking += f["severity"] in BLOCKING
    return blocking


def cmd_scan(args) -> int:
    """`scan <path>`: content scan only, no lock file or provenance checks.

    Useful on files that are not (yet) in the lock, such as a model you are
    evaluating, or the deliberately malicious demo file CI uses.
    """
    scans = scan.scan_path(pathlib.Path(args.path))
    print(f"scanned {len(scans)} artifact(s) under {args.path}")
    blocking = _print_findings(scans)
    print("RESULT: " + ("REJECTED" if blocking else "clean"))
    # Non zero exit code is how the shell, Make and CI know it failed.
    return 1 if blocking else 0


def cmd_gate(args) -> int:
    """`gate`: the full check. Fails on any problem, writes the ML-BOM on success."""
    # safe_load, not load: the lock file is input we check, and yaml.load can
    # build arbitrary Python objects, which would be ironic in a security gate.
    lock = yaml.safe_load(pathlib.Path(args.lock).read_text())

    # Step 1: look inside every model file for dangerous content.
    scans = scan.scan_path(pathlib.Path(args.artifacts))
    print(f"model lock: {len(lock.get('models', []))} managed model(s), {len(lock.get('artifacts', []))} artifact(s)")
    blocking = _print_findings(scans)

    # Step 2: provenance. Do the files on disk match what the lock approved
    # (names and hashes)? And does the code or Terraform reference any model
    # ID that is not in the lock? The second check stops someone quietly
    # switching the agent to an unapproved model in app/ or infra/.
    problems = provenance.check_lock(lock, scans)
    problems += provenance.check_references(lock, [ROOT / "app", ROOT / "infra"])
    for p in problems:
        print(f"  [PROVENANCE] {p}")

    # Fail before writing the BOM: a BOM is a statement of "this is what we
    # ship and it passed", so we never produce one for a failing build.
    if blocking or problems:
        print(f"GATE FAILED: {blocking} scan finding(s), {len(problems)} provenance violation(s)")
        return 1

    # Step 3: everything is clean, so record it as a CycloneDX ML-BOM.
    bom = mlbom.build(lock, scans, ROOT)
    out = pathlib.Path(args.bom)
    # Create the output folder if needed, so a fresh checkout or a custom
    # --bom path in CI just works.
    out.parent.mkdir(parents=True, exist_ok=True)
    # Pretty printed with a trailing newline so git diffs of the BOM stay clean.
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"GATE PASSED: wrote ML-BOM with {len(bom['components'])} component(s) to {out}")
    return 0


def main(argv=None) -> int:
    """Parse the command line and run the chosen command.

    `argv` defaults to None (meaning the real command line), but tests can
    pass a list instead. The return value becomes the process exit code.
    """
    # RawDescriptionHelpFormatter keeps the docstring's line layout in --help
    # instead of rewrapping it into one paragraph.
    p = argparse.ArgumentParser(prog="ib_supplychain", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # required=True: running with no command is an error, not a silent pass.
    sub = p.add_subparsers(dest="cmd", required=True)

    # `gate` defaults point at the repo's own files, so `make gate` needs no
    # arguments. CI overrides --bom to write the BOM somewhere it can upload.
    g = sub.add_parser("gate")
    g.add_argument("--lock", default=str(ROOT / "supplychain" / "model-lock.yaml"))
    g.add_argument("--artifacts", default=str(ROOT / "supplychain" / "artifacts"))
    g.add_argument("--bom", default=str(ROOT / "sbom" / "ml-bom.cdx.json"))
    # Each subcommand stores its handler function, so main() can just call it.
    g.set_defaults(fn=cmd_gate)

    # `scan` takes any path, because it is meant for files outside the lock.
    s = sub.add_parser("scan")
    s.add_argument("path")
    s.set_defaults(fn=cmd_scan)

    args = p.parse_args(argv)
    return args.fn(args)
