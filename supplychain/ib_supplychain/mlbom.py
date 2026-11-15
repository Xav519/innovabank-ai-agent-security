# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# This file builds the ML-BOM: a "bill of materials" for the AI parts of the
# assistant. Think of the ingredients label on a food package, but for an AI
# system. It answers one question: "what exactly is this assistant made of?"
#
# Normal software BOMs list code libraries. An AI system also depends on
# things that are not code: the models it calls, any model files (weights) it
# ships, and the documents it searches to answer questions. If any of those
# changes, the assistant can behave differently, so they deserve the same
# tracking as code.
#
# The BOM lists three kinds of ingredients, all read from the model lock file
# (supplychain/model-lock.yaml):
#
#   1. Managed models   Models we call as a service (for example Nova Lite on
#                       Bedrock). We record who publishes them, their exact ID
#                       and their license.
#   2. Artifacts        Model files we download and host ourselves (for example
#                       from Hugging Face). We record the exact revision, the
#                       file hash, and how many problems the scanner found.
#   3. Datasets         Folders of documents the assistant retrieves from (the
#                       knowledge base). We record one fingerprint (hash) for
#                       the whole folder plus how many documents it holds.
#
# Why it matters: after an incident, the first question is "what was running
# at the time?". With this file committed alongside the code, the answer is a
# lookup, not a guessing game. Hashes let anyone prove a file or dataset is the
# same one we approved.
#
# The output follows CycloneDX 1.6, an industry standard format, so other
# security tools can read it without custom code. cli.py calls build() at the
# end of `make gate`, only after every check has passed, and writes the result
# to disk.
# =============================================================================

"""CycloneDX 1.6 ML-BOM generation.

The BOM lists what the assistant is made of from an AI point of view: the
models it calls, any weights it ships, and the corpus it retrieves from, each
with enough identity to answer "what exactly was running" after an incident.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
import uuid


def _props(pairs: dict) -> list[dict]:
    # CycloneDX has no fixed field for project specific details, so it offers a
    # generic "properties" list of name/value pairs. We prefix every name with
    # "innovabank:" so our entries never clash with names other tools use.
    # Empty values are dropped so the BOM does not fill up with blank noise,
    # and every value is turned into text because the standard requires it.
    return [{"name": f"innovabank:{k}", "value": str(v)} for k, v in pairs.items() if v not in (None, "")]


def _dataset_hash(path: pathlib.Path) -> tuple[str, int]:
    """One digest over the sorted (name, content hash) pairs of a directory."""
    # A dataset is a whole folder, not one file, so we need a single
    # fingerprint that changes if any document is added, removed, renamed or
    # edited. We feed each file's path and the hash of its content into one
    # running hash.
    h, count = hashlib.sha256(), 0
    # Sorting makes the order the same on every machine and operating system,
    # so the same folder always gives the same fingerprint.
    for p in sorted(path.rglob("*")):
        if p.is_file():
            # The path is included (with forward slashes, so Windows and Linux
            # agree) so that renaming or moving a document also changes the
            # fingerprint, not just editing it.
            h.update(p.relative_to(path).as_posix().encode())
            h.update(hashlib.sha256(p.read_bytes()).digest())
            count += 1
    # The document count is returned too: it is a quick human readable sanity
    # check next to the hash, which on its own says nothing to a reader.
    return h.hexdigest(), count


def build(lock: dict, scans: list[dict], repo_root: pathlib.Path, version: str = "1.0.0") -> dict:
    # lock:      the parsed model lock file (approved models, artifacts, datasets).
    # scans:     results from scan.py, so each artifact can show its finding count.
    # repo_root: where dataset paths in the lock file are resolved from.
    # version:   the application version stamped into the BOM.
    components = []

    # 1. Managed models (called through Bedrock, nothing downloaded).
    for m in lock.get("models", []):
        components.append({
            # "machine-learning-model" is the CycloneDX type that tells readers
            # this component is a model, not a regular code library.
            "type": "machine-learning-model",
            # bom-ref is a unique ID inside this BOM, used later to link the
            # app to each of its ingredients in "dependencies".
            "bom-ref": f"model:{m['name']}",
            # The exact model ID (with version suffix) is what identifies what
            # actually ran, so it is used as the name.
            "name": m["model_id"],
            "supplier": {"name": m["publisher"]},
            "description": m.get("role", ""),
            "licenses": [{"license": {"name": m.get("license", "unknown")}}],
            # No hash here: the provider hosts the weights, so we cannot hash
            # them. "hosting: managed" makes that limit explicit for readers.
            "properties": _props({"source": m["source"], "role": m.get("role"),
                                  "inference_profile": m.get("inference_profile"), "hosting": "managed"}),
        })

    # Index scan results by file name so each artifact can find its own scan
    # in one step instead of searching the whole list every time.
    by_file = {s["file"]: s for s in scans}

    # 2. Self hosted model files (weights we download and ship ourselves).
    for a in lock.get("artifacts", []):
        # An artifact with no matching scan gets an empty result, so it shows
        # zero findings instead of crashing the BOM build.
        scan = by_file.get(a.get("file", ""), {})
        components.append({
            "type": "machine-learning-model",
            "bom-ref": f"artifact:{a['name']}",
            "name": a.get("repo", a["name"]),
            # The revision is the exact commit of the model repo we approved.
            "version": a.get("revision", ""),
            "supplier": {"name": a.get("publisher", "")},
            # A purl ("package URL") is a standard way to say where a package
            # came from, so vulnerability tools can match it against advisories.
            "purl": f"pkg:huggingface/{a.get('repo', a['name'])}@{a.get('revision', '')}",
            # Unlike managed models, we hold these files, so we can record a
            # hash that proves which exact bytes we shipped.
            "hashes": [{"alg": "SHA-256", "content": a.get("sha256", "")}],
            "licenses": [{"license": {"name": a.get("license", "unknown")}}],
            # scan_findings is kept so the BOM also records that the file was
            # scanned and what was found, not just that it exists.
            "properties": _props({"source": a.get("source"), "format": a.get("format"), "file": a.get("file"),
                                  "scan_findings": len(scan.get("findings", [])), "hosting": "self-hosted"}),
        })

    # 3. Datasets (document folders the assistant retrieves answers from).
    # These matter because a poisoned document can steer the agent just like a
    # tampered model can, so they get a fingerprint too.
    for d in lock.get("datasets", []):
        digest, count = _dataset_hash(repo_root / d["path"])
        components.append({
            # "data" is the CycloneDX type for datasets.
            "type": "data",
            "bom-ref": f"dataset:{d['name']}",
            "name": d["name"],
            "description": d.get("role", ""),
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "properties": _props({"path": d["path"], "documents": count}),
        })

    # Deterministic serial and timestamp so the committed BOM only changes when its content does.
    # The serial number is derived from a hash of the components, so the same
    # ingredients always produce the same ID. A random ID would change on every
    # run and make the committed file show a diff even when nothing changed.
    fingerprint = hashlib.sha256(json.dumps(components, sort_keys=True).encode()).hexdigest()
    # SOURCE_DATE_EPOCH is a common convention for reproducible builds: if it
    # is set, that fixed time is used (tests rely on this). Otherwise, the
    # current time is used.
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0")) or int(time.time())
    return {
        # Header fields required by the CycloneDX standard.
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        # uuid5 turns the fingerprint into a stable, valid UUID, which is the
        # format CycloneDX expects for serial numbers.
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'innovabank:' + fingerprint)}",
        "version": 1,
        "metadata": {
            # Always in UTC so the timestamp means the same thing everywhere.
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
            # The thing this BOM describes: the InnovaBank assistant itself.
            "component": {"type": "application", "bom-ref": "app:innovabank", "name": "innovabank", "version": version},
            # The tool that produced the BOM, so readers know where it came from.
            "tools": {"components": [{"type": "application", "name": "ib_supplychain", "version": version}]},
        },
        "components": components,
        # Says the app depends on every component listed above, so tools can
        # draw the link from "the assistant" to each model and dataset.
        "dependencies": [{"ref": "app:innovabank", "dependsOn": [c["bom-ref"] for c in components]}],
    }
