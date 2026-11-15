# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# This file inspects model files (the big binary files that hold a model's
# weights) and reports anything that looks dangerous, WITHOUT ever opening
# them the normal way.
#
# Why that matters: many popular model formats (.pkl, .pt, .bin, .ckpt, ...)
# are built on Python's "pickle". A pickle is not just data, it is a small
# list of instructions that Python follows to rebuild objects, and those
# instructions can say "import os and run this command". So simply loading a
# malicious model file can take over the machine. Attackers use this by
# uploading booby-trapped models to public hubs.
#
# How this file stays safe: it never loads or unpickles anything. It reads the
# pickle instructions one by one as plain text (with Python's pickletools),
# writes down every module the file WOULD import, and judges that list:
#
#   - CRITICAL: an import that gives code execution, file or network access
#               (os, subprocess, socket, ...). This is a booby trap.
#   - HIGH:     an import that is not on the short list a normal tensor
#               checkpoint needs. Not proven hostile, but unexplained.
#   - MEDIUM:   the file is pickle-based at all. It may be clean today, but
#               the format can carry code, so converting to safetensors is
#               recommended.
#
# Formats that cannot carry code (safetensors, GGUF) only get a quick check
# that their structure is sane. Unknown formats are flagged, because a file we
# cannot identify is a file we cannot vouch for.
#
# Each scanned file produces a small report (name, format, hash, size,
# findings). There is no AI judging anything: a name is either on one of the
# two fixed lists below or it is not, so the same file always gets the same
# verdict.
#
# WHAT HAPPENS AFTER A FINDING
# This file only REPORTS. It never deletes, moves or blocks a file itself.
# The decision is made in cli.py (`make gate`, also run in CI):
#
#   1. The gate scans every model file and counts the findings.
#   2. CRITICAL, HIGH and MEDIUM all block (see BLOCKING in cli.py). This lab
#      is strict on purpose: no pickle files at all, even clean ones.
#   3. Any blocking finding -> it prints "GATE FAILED", exits with code 1,
#      and does NOT write the ML-BOM (that file means "this passed").
#   4. CI sees exit code 1, turns red and stops, so the model never ships.
#   5. Zero findings -> exit code 0, the ML-BOM is written, the build goes on.
#
# The severity does not change what happens (all three fail the build). It
# tells the person reading the failure how worried to be and what to do:
#   CRITICAL -> it is an attack: delete the file, find out where it came from.
#   HIGH     -> unexplained or broken: investigate before trusting it.
#   MEDIUM   -> probably fine but risky format: convert it to safetensors.
#
# WHY SCAN PICKLES IN DETAIL IF NO PICKLE IS ALLOWED ANYWAY?
#   - The rule needs an enforcer. Files do not label themselves honestly: a
#     pickle can be renamed (model.dat) or hidden inside a .pt zip archive.
#     This scanner checks the real bytes and looks inside archives, so a
#     disguised pickle is still caught. Without it, "no pickle" is just words.
#   - Reading the imports tells you HOW bad it is. A clean pickle (MEDIUM) is
#     a chore: convert it. A pickle that imports os.system (CRITICAL) is a
#     security incident: someone tried to slip an attack in. Both fail the
#     build, but the reaction is completely different.
#   - The strictness lives in one line (BLOCKING in cli.py). A team that must
#     keep a legacy pickle model can drop "MEDIUM" from it: clean pickles then
#     pass with a warning, malicious ones are still blocked. That only works
#     because the scanner already sorts findings by severity.
#   - This is a security lab. A booby-trapped pickle is one of the best known
#     AI supply chain attacks (MITRE ATLAS), and this file shows the real
#     defense: read the instructions without ever running them.
#
# CI also proves the scanner works by feeding it a deliberately malicious
# pickle and failing if the scanner lets it through.
# =============================================================================

"""Static scanning of model artifacts.

Pickle-based model formats run code when they are loaded. This scanner never
loads anything. It walks the pickle opcode stream with pickletools, collects
every import the file would perform, and judges those imports. Formats that
cannot carry code (safetensors, GGUF) only get a structural sanity check.
"""
from __future__ import annotations

import hashlib
import io
import json
import pathlib
import pickletools
import struct
import zipfile
from dataclasses import asdict, dataclass

# File extensions that are usually pickle under the hood. PyTorch (.pt, .pth,
# .bin, .ckpt), scikit-learn (.joblib) and NumPy (.npy, .npz) can all embed
# pickle data, so we treat them as "may run code on load" by default.
PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".npy", ".npz"}

# Imports that give code execution, file or network access.
# A model file has no honest reason to touch any of these: it only needs to
# rebuild arrays of numbers. If a pickle imports one of them, it is almost
# certainly trying to run commands, read files, phone home, or hide a second
# payload (pickle, marshal, base64, zlib can unpack more hidden code).
# "operator", "functools" and "types" are here because attackers use them to
# call arbitrary functions indirectly and slip past simpler scanners.
DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "builtins", "__builtin__", "runpy", "importlib",
    "socket", "shutil", "pty", "commands", "webbrowser", "ctypes", "multiprocessing", "threading",
    "http", "urllib", "requests", "pickle", "_pickle", "marshal", "code", "codeop", "pip", "tempfile",
    "asyncio", "operator", "functools", "types", "base64", "zlib", "bdb", "pdb", "timeit", "torch.hub",
}

# Imports a plain tensor checkpoint legitimately needs.
# This is an allowlist, not a blocklist: anything not here is flagged as
# unexpected. Allowlists are safer because a new attack trick we never heard
# of is still caught (it just will not be on this short list).
SAFE_GLOBALS = {
    "collections.OrderedDict",
    "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_parameter",
    "torch.FloatStorage", "torch.HalfStorage", "torch.LongStorage", "torch.IntStorage",
    "torch.DoubleStorage", "torch.BoolStorage", "torch.ByteStorage",
    # NumPy renamed numpy.core to numpy._core in 2.x, so both spellings appear.
    "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
    "numpy.ndarray", "numpy.dtype",
}


# One problem found in one file. Kept as a simple record so it can be turned
# into JSON for the gate report and the ML-BOM.
@dataclass
class Finding:
    severity: str   # CRITICAL, HIGH, MEDIUM
    file: str
    rule: str
    detail: str


def sha256(path: pathlib.Path) -> str:
    # Fingerprint of the file, recorded in the report so it can be compared
    # with the hash pinned in the model lock (any change to the file changes
    # the hash). Read in 1 MiB blocks so multi-gigabyte models do not have to
    # fit in memory at once.
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pickle_imports(data: bytes) -> list[str]:
    """Every module.name a pickle stream would import, without unpickling it."""
    # pickletools.genops only DECODES the instructions, it does not execute
    # them. That is what makes this safe to run on a hostile file.
    imports, strings = [], []
    for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
        # Older pickle protocols name the import directly in the instruction,
        # as "module name" with a space. We turn it into "module.name".
        if opcode.name in ("GLOBAL", "INST"):
            imports.append(str(arg).replace(" ", "."))
        # Newer protocols push the module and the name as two separate strings
        # first, so remember every string we see along the way...
        elif opcode.name in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING",
                             "BINSTRING", "SHORT_BINSTRING"):
            strings.append(str(arg))
        # ...and when STACK_GLOBAL arrives, the last two strings are the
        # module and the name it is about to import.
        elif opcode.name == "STACK_GLOBAL" and len(strings) >= 2:
            imports.append(f"{strings[-2]}.{strings[-1]}")
    return imports


def _judge_imports(name: str, imports: list[str]) -> list[Finding]:
    # Turn the raw list of imports into findings. Each distinct import is
    # reported once, in a stable order, so reports are easy to read and diff.
    findings = []
    for imp in sorted(set(imports)):
        # "os.path.join" -> module "os.path", root "os". Checking the root too
        # means a dangerous package cannot hide behind one of its submodules.
        module = imp.rsplit(".", 1)[0]
        root = module.split(".")[0]
        if module in DANGEROUS_MODULES or root in DANGEROUS_MODULES:
            findings.append(Finding("CRITICAL", name, "dangerous-import",
                                    f"loading this file would import {imp}"))
        elif imp not in SAFE_GLOBALS:
            findings.append(Finding("HIGH", name, "unexpected-import",
                                    f"{imp} is not on the allowlist for tensor checkpoints"))
    return findings


def detect_format(path: pathlib.Path, head: bytes) -> str:
    # Decide what kind of file this is. Where possible we trust the first bytes
    # of the file (its "magic number") over the extension, because an attacker
    # can rename a file but its content still gives it away.
    ext = path.suffix.lower()
    if head[:4] == b"GGUF":
        return "gguf"
    if ext == ".safetensors":
        return "safetensors"
    if ext == ".onnx":
        return "onnx"
    # "PK" starts every zip archive. Modern PyTorch .pt files are zips with a
    # pickle inside, so they need to be opened and their members scanned.
    if head[:2] == b"PK":
        return "zip"
    # 0x80 followed by a protocol number 2 to 5 is how a binary pickle starts.
    # This catches pickles even when they wear an innocent looking extension.
    if ext in PICKLE_EXTENSIONS or (head[:1] == b"\x80" and head[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05")):
        return "pickle"
    return "unknown"


def _check_safetensors(path: pathlib.Path, name: str) -> list[Finding]:
    # Safetensors cannot run code, but a broken or forged file could still
    # crash or confuse the loader. A safetensors file is: 8 bytes giving the
    # header length, then a JSON header, then raw numbers. We check that shape.
    size = path.stat().st_size
    with path.open("rb") as fh:
        raw = fh.read(8)
        if len(raw) < 8:
            return [Finding("HIGH", name, "malformed-safetensors", "file shorter than its header")]
        # Little endian unsigned 64 bit integer, as the safetensors spec says.
        (n,) = struct.unpack("<Q", raw)
        # The header cannot be longer than the file itself, and we cap it at
        # 100 MiB so a forged length cannot make us read a huge amount of data.
        if n > min(size - 8, 100 * 1024 * 1024):
            return [Finding("HIGH", name, "malformed-safetensors", "header length exceeds file size")]
        try:
            header = json.loads(fh.read(n))
        except (ValueError, UnicodeDecodeError):
            return [Finding("HIGH", name, "malformed-safetensors", "header is not valid JSON")]
    # A valid header is a JSON object (tensor name -> details), nothing else.
    return [] if isinstance(header, dict) else [Finding("HIGH", name, "malformed-safetensors", "header is not an object")]


def scan_file(path: pathlib.Path, root: pathlib.Path | None = None) -> dict:
    # Scan one file and return its report. When scanning a folder, the name is
    # shown relative to that folder so reports match the paths in the lock.
    name = path.relative_to(root).as_posix() if root else path.name
    # The first 8 bytes are enough to recognise every format we care about.
    with path.open("rb") as fh:
        head = fh.read(8)
    fmt = detect_format(path, head)
    findings: list[Finding] = []

    if fmt == "pickle":
        # Always warn that the format itself is risky, even if the imports
        # turn out clean, then look at what it would actually import.
        findings.append(Finding("MEDIUM", name, "pickle-format",
                                "pickle-based format can execute code on load, convert to safetensors"))
        try:
            findings += _judge_imports(name, pickle_imports(path.read_bytes()))
        except Exception as exc:  # truncated or deliberately malformed stream
            # A pickle we cannot read is a pickle we cannot clear. Attackers
            # sometimes break the stream on purpose to confuse scanners, so
            # this is reported rather than silently skipped.
            findings.append(Finding("HIGH", name, "unparseable-pickle", f"opcode stream could not be read: {exc}"))
    elif fmt == "zip":
        # Look inside the archive for pickle members and scan each one. The
        # "archive!member" name tells the reader exactly where a problem is.
        try:
            with zipfile.ZipFile(path) as zf:
                members = [m for m in zf.namelist() if m.endswith((".pkl", ".pickle"))]
                if members:
                    findings.append(Finding("MEDIUM", name, "pickle-format",
                                            "archive contains pickle data, convert to safetensors"))
                for m in members:
                    findings += _judge_imports(f"{name}!{m}", pickle_imports(zf.read(m)))
        except zipfile.BadZipFile:
            findings.append(Finding("HIGH", name, "malformed-archive", "not a readable zip archive"))
    elif fmt == "safetensors":
        findings += _check_safetensors(path, name)
    elif fmt == "unknown":
        # We only allow what we can identify and inspect.
        findings.append(Finding("HIGH", name, "unknown-format", "unrecognised artifact format"))
    # GGUF and ONNX fall through with no findings: they do not carry pickle
    # code, so recognising them is enough for this lab.

    # Plain dict (not the dataclass) so the result can go straight into JSON.
    return {"file": name, "format": fmt, "sha256": sha256(path), "size": path.stat().st_size,
            "findings": [asdict(f) for f in findings]}


def scan_path(root: pathlib.Path) -> list[dict]:
    # Scan a single file, or every file in a folder and its subfolders. The
    # folder's own README and the empty .gitkeep placeholder are not model
    # artifacts, so they are skipped instead of being flagged as unknown.
    skip = {"README.md", ".gitkeep"}
    if root.is_file():
        return [scan_file(root)]
    # Sorted so the report order is the same on every machine and every run.
    return [scan_file(p, root) for p in sorted(root.rglob("*")) if p.is_file() and p.name not in skip]
