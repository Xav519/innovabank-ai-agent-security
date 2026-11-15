# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# These tests check the project's documentation, not its code. They make sure
# the README and the files under docs/ keep rendering correctly and keep the
# structure that other tools in the repo depend on:
#
#   - no em dashes or en dashes anywhere in the docs (a house style rule);
#   - the README still has the hidden markers where generated benchmark results
#     get pasted in, so `make offline` and `make report-live` can update them;
#   - every relative link and image in the README points to a file that exists,
#     so readers never hit a broken link;
#   - the architecture diagram is still a Mermaid flowchart, so GitHub draws it
#     as a picture instead of showing raw text.
#
# They only read files from disk: no AWS, no network, and they run in a blink.
# =============================================================================

"""The README and the docs stay renderable and honest about their own structure."""
import pathlib
import re

# The repository root (this file lives in tests/, so go up one level). Every
# path below is built from here so the tests work no matter where pytest is
# launched from.
ROOT = pathlib.Path(__file__).resolve().parents[1]

# Read the README once at import time because three of the four tests need it.
# utf-8 is explicit so Windows does not fall back to a different default
# encoding and choke on non-ASCII characters.
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_no_em_or_en_dashes_in_any_document():
    # The project avoids em and en dashes as a style rule. Checking it here means
    # a stray dash pasted from an editor or generated text fails CI instead of
    # quietly slipping in. Every Markdown file under docs/ is included, so new
    # docs are covered automatically without editing this test.
    docs = [ROOT / "README.md", ROOT / "CLAUDE.md", *sorted((ROOT / "docs").rglob("*.md"))]
    dashes = ("\u2014", "\u2013")  # em dash, en dash (escaped so this file has none either)
    # Collect the names of offending files rather than stopping at the first one,
    # so a failure shows every file that needs fixing in a single run.
    offenders = [str(p.relative_to(ROOT)) for p in docs if any(d in p.read_text(encoding="utf-8") for d in dashes)]
    assert offenders == []


def test_generated_result_blocks_are_still_marked():
    # The results tables in the README are written by report.py, which replaces
    # whatever sits between a START and an END marker. If a marker is deleted
    # or duplicated during a manual edit, the generator would either fail or
    # overwrite the wrong part of the README. Exactly one of each keeps it safe.
    for block in ("OFFLINE-RESULTS", "LIVE-RESULTS"):
        assert README.count(f"<!-- IB:{block}:START -->") == 1 and README.count(f"<!-- IB:{block}:END -->") == 1


def test_every_relative_link_and_image_exists():
    # Find every Markdown link or image target of the form ](target), skipping
    # web URLs (http/https) and in-page anchors (#section), since those cannot be
    # checked against the file system. What is left are paths inside the repo.
    targets = re.findall(r"\]\(((?!https?://|#)[^)\s]+)\)", README)
    # Drop any "#anchor" part so "docs/controls.md#taint-lock" checks that
    # docs/controls.md exists. Renaming or moving a file without updating the
    # README is then caught here instead of by a confused reader.
    missing = [t for t in targets if not (ROOT / t.split("#")[0]).exists()]
    # "targets" must not be empty: if the regex ever stopped matching anything,
    # the test would pass for the wrong reason, so we insist it found links.
    assert targets and missing == []


def test_architecture_diagram_is_mermaid():
    # GitHub only draws the diagram as a picture when it sits in a ```mermaid
    # code block. This guards against the block being changed to plain text or
    # swapped for an image that could drift out of date with the code.
    assert "```mermaid\nflowchart" in README
