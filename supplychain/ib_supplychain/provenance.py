# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# This file checks "provenance": where every AI model and model file used by
# the assistant comes from, and whether we approved it. It compares reality
# against the model lock file (supplychain/model-lock.yaml), which is the one
# list of everything we allow.
#
# Think of the lock file as a guest list at the door. This file is the
# bouncer. It runs three kinds of checks:
#
#   1. Is the guest list itself valid?        Every model and artifact must
#                                             come from an allowed source and
#                                             an approved publisher, be pinned
#                                             to an exact version, and use a
#                                             safe file format.
#   2. Do the files on disk match the list?   Each declared file must exist,
#                                             its hash must match the lock,
#                                             and no extra, undeclared file may
#                                             sit next to them.
#   3. Does the code only use listed models?  Any model ID written in Python or
#                                             Terraform must appear in the lock.
#
# Why it matters: a model is part of the supply chain, just like a code
# library. Swapping it (a newer version, a lookalike from an unknown publisher,
# a tampered file) can silently change how the assistant behaves or even run
# hostile code. These checks make such a swap fail CI instead of reaching
# production.
#
# Each function returns a list of human readable problems. An empty list means
# everything passed. cli.py (`make gate`) collects them and fails if any exist.
# =============================================================================

"""Provenance checks against the model lock file."""
from __future__ import annotations

import pathlib
import re

# Bedrock model and inference profile identifiers as they appear in code and Terraform.
# Used to find every model the code mentions, so none can sneak in unlisted.
# Shape it matches, piece by piece:
#   - optional region prefix ("us.", "eu.", ...): cross region inference
#     profiles carry one, plain model IDs do not, and both must be caught.
#   - a known provider name ("amazon", "anthropic", ...): limiting to real
#     providers avoids false alarms on unrelated dotted strings.
#   - the model name, then a "-vN" version and optional ":N" revision, which
#     every Bedrock model ID ends with (for example amazon.nova-lite-v1:0).
_MODEL_REF = re.compile(
    r"\b(?:(?:us|eu|apac|global|us-gov)\.)?"
    r"(?:amazon|anthropic|meta|mistral|cohere|ai21|deepseek|openai|writer|stability|twelvelabs|qwen)"
    r"\.[a-z][a-z0-9-]*(?:[.-][a-z0-9]+)*-v\d+(?::\d+)?\b")
# A full 40 character git commit hash. Branches and tags can be moved to point
# at different content later; a full commit cannot, so it is the only safe pin.
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
# A SHA-256 hash in hex (64 characters). Used to prove a file is byte for byte
# the one we approved.
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def approved_ids(lock: dict) -> set[str]:
    """Every model identifier the lock allows the code to reference."""
    ids = set()
    for m in lock.get("models", []):
        ids.add(m["model_id"])
        # The code may call a model through its inference profile (for example
        # "us.amazon.nova-lite-v1:0") instead of the raw model ID, so both
        # spellings count as approved.
        if m.get("inference_profile"):
            ids.add(m["inference_profile"])
    return ids


def check_lock(lock: dict, scans: list[dict]) -> list[str]:
    """Violations in the lock file itself, and between the lock and the artifacts on disk."""
    # `scans` is what the scanner found on disk: one entry per model file, with
    # its path, real hash and real format. We compare the lock against it.
    problems = []
    policy = lock.get("policy", {})
    sources = policy.get("allowed_sources", {})
    formats = set(policy.get("allowed_artifact_formats", []))
    # Index scans by file path so each declared artifact can find its match fast.
    by_file = {s["file"]: s for s in scans}

    # Check 1: where things come from. Applies to both managed models (called
    # as a service) and artifacts (files we host), because a bad publisher is
    # just as risky either way.
    for m in lock.get("models", []) + lock.get("artifacts", []):
        src, pub = m.get("source"), m.get("publisher")
        if src not in sources:
            problems.append(f"{m.get('name')}: source {src!r} is not allowed")
        # A source can be allowed while only some publishers on it are trusted
        # (anyone can upload to Hugging Face). An empty or null list means no
        # publisher is approved yet, hence the `or []`.
        elif pub not in (sources[src] or []):
            problems.append(f"{m.get('name')}: publisher {pub!r} is not approved for {src}")

    # Check 2: each declared artifact must be pinned, safe, and match the disk.
    declared = set()
    for a in lock.get("artifacts", []):
        name, declared_file = a.get("name"), a.get("file", "")
        # Remember what the lock declares, to spot undeclared files afterwards.
        declared.add(declared_file)
        # Pinning is on by default; the policy can only turn it off explicitly.
        if policy.get("require_pinned_revision", True) and not _COMMIT.match(str(a.get("revision", ""))):
            problems.append(f"{name}: revision must be a full commit hash, got {a.get('revision')!r}")
        # Without a valid hash there is nothing to verify the file against.
        if not _SHA256.match(str(a.get("sha256", ""))):
            problems.append(f"{name}: missing or malformed sha256")
        # Only formats that store plain numbers are allowed. Formats like
        # pickle can run code when loaded, which turns a model file into malware.
        if a.get("format") not in formats:
            problems.append(f"{name}: format {a.get('format')!r} is not allowed")
        scanned = by_file.get(declared_file)
        if not scanned:
            problems.append(f"{name}: declared file {declared_file!r} is not present")
        else:
            # The hash on disk must equal the approved hash, otherwise the file
            # was changed or replaced after review.
            if scanned["sha256"] != a.get("sha256"):
                problems.append(f"{name}: sha256 mismatch, file does not match the lock")
            # Trust what the scanner detected from the file contents, not the
            # label in the lock. A pickle renamed to look safe gets caught here.
            if scanned["format"] != a.get("format"):
                problems.append(f"{name}: file is {scanned['format']}, lock says {a.get('format')}")

    # Check 3: nothing on disk may be missing from the lock. An unlisted file
    # was never reviewed, so it is rejected even if it looks harmless.
    for s in scans:
        if s["file"] not in declared:
            problems.append(f"{s['file']}: artifact is not declared in the lock file")
    return problems


def check_references(lock: dict, roots: list[pathlib.Path]) -> list[str]:
    """Every model identifier referenced in code or Terraform must be in the lock."""
    # The lock is only useful if the code actually respects it. Without this
    # check, someone could change a model ID in a Lambda or a .tf file and the
    # lock would never know.
    approved = approved_ids(lock)
    problems = []
    for root in roots:
        # sorted() keeps the output order stable, so CI logs are easy to diff.
        for path in sorted(root.rglob("*")):
            # Only scan file types where a model ID would actually be used.
            # Skip .terraform folders: they hold downloaded provider code that
            # is not ours and can mention any model.
            if path.suffix not in {".py", ".tf", ".tfvars"} or ".terraform" in path.parts:
                continue
            # set() reports each unknown model once per file, even if it
            # appears many times. errors="ignore" stops one odd byte from
            # crashing the whole gate.
            for ref in sorted(set(_MODEL_REF.findall(path.read_text(encoding="utf-8", errors="ignore")))):
                if ref not in approved:
                    problems.append(f"{path.as_posix()}: references {ref}, which is not in the model lock")
    return problems
