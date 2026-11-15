# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# IN ONE SENTENCE
#   This file checks that the "supply chain gate" stops untrusted or dangerous
#   AI models from getting into the project, and lets trusted ones through.
#
# THE PROBLEM
#   AI models are dependencies, just like code libraries, and they can be
#   attacked the same way:
#     - A model file can hide code that runs the moment the file is opened.
#       The classic example is Python "pickle" files (.pkl, .bin, .pt), which
#       can tell Python to run any command while loading.
#     - Someone can swap in a different model than the one that was reviewed.
#     - A downloaded file can be tampered with after it was approved.
#
# HOW THE PROJECT DEFENDS ITSELF
#   - supplychain/model-lock.yaml is a "guest list" of every approved model.
#   - The scanner reads model files as raw bytes, WITHOUT loading them, and
#     reports problems with a severity (CRITICAL, HIGH, MEDIUM).
#   - The provenance checks compare the code, the Terraform and any model files
#     against the guest list.
#   - The ML-BOM is an inventory of models and data (CycloneDX format) that
#     auditors and tools can read.
#   - The gate (`make gate`, run in CI) runs all of this and fails the build
#     if anything is wrong.
#
# WHAT THE TESTS CHECK
#   - A booby-trapped pickle is flagged CRITICAL, and is never actually run.
#   - Every pickle version, and pickles hidden inside zip files, are caught.
#   - Even a harmless pickle is still rejected, because the format is risky.
#   - Safe "safetensors" files pass, broken ones do not.
#   - The real repository matches its own guest list.
#   - A model that is not on the guest list is caught.
#   - Downloaded model entries must be pinned, hashed, from an approved
#     publisher and in a safe format.
#   - The ML-BOM has the right shape and is the same every time it is built.
#   - The gate passes on the real repository and fails on a bad file.
# =============================================================================

import json
import os
import pathlib
import pickle
import struct
import zipfile

import yaml

from ib_supplychain import cli, mlbom, provenance, scan

# The repository root, so tests can point at the real code, Terraform and lock
# file no matter which folder pytest is started from.
ROOT = pathlib.Path(__file__).resolve().parents[1]
# The real model lock file. Several tests use it so they check the project as it
# actually is, not a made-up example.
LOCK = yaml.safe_load((ROOT / "supplychain/model-lock.yaml").read_text())


# A fake "malicious model". When pickled, __reduce__ tells Python: "to rebuild
# this object, call os.system with this command". That is exactly how real
# pickle attacks run code on load. The command is harmless, and the tests never
# unpickle it anyway: the point is to prove the scanner spots it from the bytes.
class _Evil:
    def __reduce__(self):
        return (os.system, ("echo never-runs",))


# Writes a tiny but valid safetensors file. Safetensors is the safe format: an
# 8 byte length, a JSON header describing the tensors, then raw numbers. It has
# no way to run code, so it is the format we want models to use.
def _safetensors(path):
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    path.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 4)


# Small helper: the set of severities found in one scan result, so tests can
# say "this was CRITICAL" without digging through the full findings list.
def severities(result):
    return {f["severity"] for f in result["findings"]}


# The core promise of the scanner: a pickle that calls os.system is flagged as
# CRITICAL, and the finding names the dangerous call so a human knows why. If
# the scanner loaded the file to inspect it, the attack would already have run.
def test_malicious_pickle_is_critical_without_being_loaded(tmp_path):
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(pickle.dumps({"w": [1.0], "hook": _Evil()}))
    result = scan.scan_file(p)
    assert result["format"] == "pickle" and "CRITICAL" in severities(result)
    assert any("system" in f["detail"] for f in result["findings"])


# Pickle has several versions (protocols) that encode imports differently. An
# attacker can pick any of them, so the scanner must catch the attack in all.
def test_every_pickle_protocol_is_caught(tmp_path):
    for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
        p = tmp_path / f"m{proto}.pkl"
        p.write_bytes(pickle.dumps(_Evil(), protocol=proto))
        assert "CRITICAL" in severities(scan.scan_file(p)), f"protocol {proto}"


# PyTorch .pt files are really zip archives with a pickle inside. A scanner that
# only looked at the outer file would miss the attack, so it must look inside.
def test_pickle_hidden_in_a_torch_style_zip_is_caught(tmp_path):
    p = tmp_path / "model.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(_Evil()))
    assert "CRITICAL" in severities(scan.scan_file(p))


# A pickle with only numbers in it is harmless today, but the format itself can
# run code, so it is still flagged (MEDIUM, and nothing worse). The fix is to
# convert it to safetensors, not to trust it.
def test_data_only_pickle_is_still_rejected_as_a_format(tmp_path):
    p = tmp_path / "weights.pkl"
    p.write_bytes(pickle.dumps({"w": [1.0, 2.0]}))
    assert severities(scan.scan_file(p)) == {"MEDIUM"}


# A good safetensors file must produce no findings at all, or people would learn
# to ignore the gate. A broken one (its header claims to be a terabyte long) is
# flagged HIGH, because a corrupted or crafted file should not be trusted.
def test_safetensors_is_clean_and_malformed_header_is_not(tmp_path):
    good, bad = tmp_path / "model.safetensors", tmp_path / "bad.safetensors"
    _safetensors(good)
    bad.write_bytes(struct.pack("<Q", 10**12) + b"{}")
    assert scan.scan_file(good)["findings"] == []
    assert severities(scan.scan_file(bad)) == {"HIGH"}


# The real project must pass its own rules: the lock file is valid, and every
# model ID mentioned in app/ or infra/ is on the guest list. This catches
# someone changing a model in code or Terraform without updating the lock.
def test_repository_lock_is_consistent_with_code_and_terraform():
    assert provenance.check_lock(LOCK, []) == []
    assert provenance.check_references(LOCK, [ROOT / "app", ROOT / "infra"]) == []


# The opposite case: a Terraform file that quietly uses a model not on the
# guest list must be reported exactly once, with a clear reason.
def test_unapproved_model_reference_is_caught(tmp_path):
    (tmp_path / "main.tf").write_text('model = "us.anthropic.claude-3-5-haiku-20241022-v1:0"\n')
    problems = provenance.check_references(LOCK, [tmp_path])
    assert len(problems) == 1 and "not in the model lock" in problems[0]


# Rules for downloaded model files. The real lock has none yet, so this test
# builds its own small lock to prove the checks work before they are needed.
def test_artifact_rules(tmp_path):
    f = tmp_path / "model.safetensors"
    _safetensors(f)
    scans = scan.scan_path(tmp_path)
    # A fully correct entry: approved publisher, exact 40 character commit,
    # matching hash, safe format.
    good = {"name": "m", "source": "huggingface", "publisher": "acme", "repo": "acme/m",
            "revision": "a" * 40, "file": "model.safetensors", "sha256": scans[0]["sha256"],
            "format": "safetensors", "license": "apache-2.0"}
    policy = {"allowed_sources": {"huggingface": ["acme"]}, "allowed_artifact_formats": ["safetensors"]}

    # The correct entry passes, so the failures below come from the one change
    # made in each case, not from a broken baseline.
    assert provenance.check_lock({"policy": policy, "artifacts": [good]}, scans) == []
    # Break one rule at a time and check the right problem is reported:
    #   - a branch name can be moved later, so only a full commit is accepted,
    #   - a wrong hash means the file is not the one that was approved,
    #   - an unknown publisher is not trusted just because the hub is,
    #   - pickle is not an allowed format because it can run code.
    for change, expect in [({"revision": "main"}, "full commit hash"), ({"sha256": "0" * 64}, "sha256 mismatch"),
                           ({"publisher": "stranger"}, "not approved"), ({"format": "pickle"}, "not allowed")]:
        problems = provenance.check_lock({"policy": policy, "artifacts": [{**good, **change}]}, scans)
        assert any(expect in p for p in problems), (change, problems)
    # A model file sitting on disk but missing from the lock must also fail, so
    # nobody can sneak a file in without declaring it.
    assert any("not declared" in p for p in provenance.check_lock({"policy": policy, "artifacts": []}, scans))


# The ML-BOM must be a valid CycloneDX 1.6 document and must be identical each
# time it is built. A fixed SOURCE_DATE_EPOCH pins the timestamp, so any
# difference between two builds would point to a real, unexpected change.
def test_mlbom_is_valid_shape_and_deterministic(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1794182400")
    a, b = mlbom.build(LOCK, [], ROOT), mlbom.build(LOCK, [], ROOT)
    assert a == b and a["bomFormat"] == "CycloneDX" and a["specVersion"] == "1.6"
    # The inventory must list both Bedrock models and the knowledge base data
    # from the lock file, so nothing the assistant relies on is left out.
    types = [c["type"] for c in a["components"]]
    assert types.count("machine-learning-model") == 2 and types.count("data") == 1
    # The application must be recorded as depending on every listed component.
    assert a["dependencies"][0]["dependsOn"] == [c["bom-ref"] for c in a["components"]]


# End to end check of the command CI runs. On the real repository the gate
# passes and writes the ML-BOM. With a malicious file it must fail, say so
# clearly, and NOT write a BOM, so a failed build never leaves behind an
# inventory that looks approved.
def test_gate_passes_on_the_repository_and_fails_on_a_bad_artifact(tmp_path, capsys):
    bom = tmp_path / "bom.json"
    assert cli.main(["gate", "--bom", str(bom)]) == 0 and bom.exists()
    bad = tmp_path / "artifacts"
    bad.mkdir()
    (bad / "model.bin").write_bytes(pickle.dumps(_Evil()))
    assert cli.main(["gate", "--artifacts", str(bad), "--bom", str(tmp_path / "x.json")]) == 1
    assert not (tmp_path / "x.json").exists()
    assert "GATE FAILED" in capsys.readouterr().out
