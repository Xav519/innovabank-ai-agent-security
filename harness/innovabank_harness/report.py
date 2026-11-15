# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file turns raw test results into readable Markdown tables.
#
# The harness runs the same attacks and the same legitimate requests twice:
# once against the "vulnerable" agent (no security controls) and once against
# the "hardened" agent (all controls on). Each run is saved as a JSON file.
# This file takes those two runs and writes a side by side, "before and
# after" report, so a reader can see at a glance what the controls changed.
#
# The report has three tables:
#
#   1. Summary     For each OWASP category, how many attacks succeeded on
#                  vulnerable versus hardened, plus how many legitimate
#                  requests still worked.
#
#   2. Every attack  One row per attack, with the reason it failed on the
#                  hardened agent (which control stopped it).
#
#   3. Legitimate requests  One row per normal customer request, to prove
#                  that security did not break real usage.
#
# Where the output goes:
#   render()  builds the full report (docs/results/offline.md or live.md).
#   inject()  pastes a short version into README.md between marker comments,
#             so the README numbers always come from a real run and are never
#             typed by hand.
#
# Honesty rule: a control only gets credit for stopping an attack if that
# attack actually worked on the vulnerable agent. If the model refused on its
# own even without controls, we say so instead of claiming a win.
#
# =============================================================================

"""Turn two runs into the before and after table."""
from __future__ import annotations

import re

# Internal control names (as used in config.py) mapped to friendly names
# for the report. Keeping them here means the tables read like English while
# the code keeps short, stable identifiers.
CONTROL_LABELS = {
    "prompt_hygiene": "prompt hygiene", "input_filter": "input filter", "guardrail": "Bedrock Guardrails",
    "spotlight": "spotlighting", "retrieval_scan": "retrieval scan", "taint_lock": "taint lock",
    "tool_policy": "tool policy", "budget": "budget", "output_filter": "output filter",
    "data_minimisation": "data minimisation", "ingest_integrity": "signed ingestion",
    "ingest_scan": "ingestion scan",
    "iam": "per-tool IAM",  # not an app control: logged when a tool's own role denies the AWS call
}


def _pct(n: int, d: int) -> str:
    # Show both the raw count and the percentage ("3/5 (60%)"), because a
    # percentage alone hides how small the sample is. Guard against an empty
    # category so we never divide by zero.
    return f"{n}/{d} ({round(100 * n / d)}%)" if d else "n/a"


def _by_category(run: dict) -> dict:
    # Group attacks by category (for example "prompt injection") and count
    # how many ran and how many succeeded. The summary table works per
    # category so a reader sees which kinds of risk remain, not just a total.
    out: dict = {}
    for a in run["attacks"]:
        row = out.setdefault(a["category"], {"owasp": a["owasp"], "total": 0, "succeeded": 0})
        row["total"] += 1
        # True/False becomes 1/0 so we can simply add up the successes.
        row["succeeded"] += int(a["succeeded"])
    return out


# Printed above the detailed attack table. Several controls can fire on the
# same attack, and the report cannot tell which one was really needed, so this
# note warns readers not to over-read the list and points them to the
# ablation report, which removes one control at a time to find out.
ATTRIBUTION_NOTE = (
    "How to read the last column. Controls are listed when they blocked something during the attack. "
    "When several are listed, any one of them may have been enough; the ablation report measures which "
    "control an attack actually depends on. When an attack also failed against the vulnerable stack, the "
    "model declined on its own, so the hardened controls that fired are shown but not credited with stopping it."
)


def _labels(controls: list[str]) -> str:
    # Turn a list of control names into a readable, comma separated string.
    # Unknown names are shown as is rather than crashing, so a newly added
    # control still appears in the report even before it gets a nice label.
    return ", ".join(CONTROL_LABELS.get(c, c) for c in controls)


def _outcome(hard: dict, vuln: dict) -> str:
    """Explain a hardened result without crediting controls for what the model refused anyway."""
    # The attack still worked on the hardened agent: flag it in bold so a
    # real gap is impossible to miss.
    if hard["succeeded"]:
        return "**not stopped**"
    fired = _labels(hard["blocked_by"])
    # The attack also failed on the vulnerable agent, so the model refused by
    # itself. Controls may have fired too, but giving them credit would make
    # the hardened posture look better than it really is.
    if not vuln["succeeded"]:
        return "model declined (also failed on vulnerable)" + (f"; controls also fired: {fired}" if fired else "")
    # The attack worked without controls and failed with them: here the
    # controls really made the difference, so name them.
    return f"blocked by {fired}" if fired else "no control fired (the model declined)"


def summary_table(vuln: dict, hard: dict) -> str:
    # Build the top level table: one row per category, then a total row and
    # a row for legitimate requests. This is the table that goes in the README.
    v, h = _by_category(vuln), _by_category(hard)
    lines = ["| OWASP LLM | Category | Vulnerable | Hardened |", "|---|---|---|---|"]
    # Running totals: tv = vulnerable successes, th = hardened successes,
    # tn = number of attacks.
    tv = th = tn = 0
    for cat, row in v.items():
        # If a category is missing from the hardened run (for example a
        # filtered run), treat it as zero instead of crashing.
        hr = h.get(cat, {"succeeded": 0, "total": 0})
        lines.append(f"| {row['owasp']} | {cat} | {_pct(row['succeeded'], row['total'])} "
                     f"| {_pct(hr['succeeded'], hr['total'])} |")
        tv, th, tn = tv + row["succeeded"], th + hr["succeeded"], tn + row["total"]
    lines.append(f"| | **All attacks** | **{_pct(tv, tn)}** | **{_pct(th, tn)}** |")
    # Security that blocks real customers is not a win, so the summary always
    # shows how many legitimate requests still completed in each posture.
    bv = sum(b["passed"] for b in vuln["benign"])
    bh = sum(b["passed"] for b in hard["benign"])
    lines.append(f"| | Legitimate requests completed | {_pct(bv, len(vuln['benign']))} "
                 f"| {_pct(bh, len(hard['benign']))} |")
    return "\n".join(lines)


def detail_table(vuln: dict, hard: dict) -> str:
    # One row per attack, pairing the vulnerable result with the hardened one.
    # Index the hardened attacks by ID so each vulnerable row can find its
    # partner quickly.
    hv = {a["id"]: a for a in hard["attacks"]}
    lines = ["| ID | Attack | ATLAS | Vulnerable | Hardened | Why it failed on hardened |",
             "|---|---|---|---|---|---|"]
    for a in vuln["attacks"]:
        h = hv.get(a["id"])
        # Skip attacks that only ran in one posture: a row with half the
        # data would be misleading.
        if not h:
            continue
        lines.append(f"| {a['id']} | {a['name']} | {', '.join(a['atlas'])} "
                     f"| {_attack_cell(a)} | {_attack_cell(h)} | {_outcome(h, a)} |")
    return "\n".join(lines)


def _trials(r: dict) -> int:
    # Live runs can repeat each case several times because a real model is
    # not perfectly predictable. Older or offline results have no "trials"
    # field, which means a single run.
    return int(r.get("trials", 1))


def _attack_cell(a: dict) -> str:
    """'succeeded' or 'failed'; with several trials, how many of them the attack won."""
    word = "succeeded" if a["succeeded"] else "failed"
    n = _trials(a)
    # With several trials, show "succeeded 1/3" so the reader sees an attack
    # that only works sometimes, which a plain "succeeded" would hide.
    return f"{word} {a.get('successes', int(a['succeeded']))}/{n}" if n > 1 else word


def _benign_cell(b: dict | None) -> str:
    """A legitimate request's outcome. A failure names the controls that blocked it, or says none did.

    With several trials the cell shows how many completed, and the reason is taken from the
    trials that failed.
    """
    # The request exists in the vulnerable run but not in the hardened one.
    if b is None:
        return "not run"
    n = _trials(b)
    passes = b.get("passes", int(b["passed"]))
    if b["passed"]:
        return f"ok {passes}/{n}" if n > 1 else "ok"
    # Only look at the failed trials when explaining why: the passing trials
    # tell us nothing about what went wrong.
    failed = [r for r in b.get("runs", [b]) if not r["passed"]]
    head = f"FAILED {passes}/{n}" if n > 1 else "FAILED"
    # A "[harness]" reply means our own test tooling broke (for example an
    # AWS error), not the agent. Say so, so nobody blames a security control.
    if any(r.get("response", "").startswith("[harness]") for r in failed):
        return f"{head} (harness error, see results JSON)"
    # Name every control that blocked the request in any failed trial. This
    # is the false positive we most want to see, since it hurts real customers.
    fired = _labels(_union_controls(r.get("blocked_by", []) for r in failed))
    return f"{head} (blocked by {fired})" if fired else f"{head} (no control fired; the model did not complete it)"


def _union_controls(lists) -> list[str]:
    # Merge several lists into one without duplicates, keeping the order in
    # which controls first appeared so the output is stable from run to run.
    seen: list[str] = []
    for items in lists:
        seen.extend(i for i in items if i not in seen)
    return seen


def benign_table(vuln: dict, hard: dict) -> str:
    # One row per legitimate request, vulnerable result next to hardened.
    # This proves the hardened agent still does its real job.
    hb = {b["id"]: b for b in hard["benign"]}
    lines = ["| ID | Legitimate request | Vulnerable | Hardened |", "|---|---|---|---|"]
    for b in vuln["benign"]:
        # hb.get() returns None if the hardened run skipped this request;
        # _benign_cell turns that into "not run".
        lines.append(f"| {b['id']} | {b['name']} | {_benign_cell(b)} | {_benign_cell(hb.get(b['id']))} |")
    return "\n".join(lines)


def provenance(vuln: dict, hard: dict) -> str:
    # A short paragraph saying where the numbers come from. Offline and live
    # results mean very different things, so every report states which one
    # it is, when it ran, and what was (and was not) tested.
    m = hard["meta"]
    if m["target"] == "offline":
        # Offline uses a scripted model that obeys every injection, so the
        # vulnerable column is always 100%. We explain that up front so
        # nobody mistakes it for a measurement of a real model.
        return (f"Source: offline control verification, run {m['run_at']}. Real orchestrator and controls, "
                "in process, against a scripted model that obeys every injection that reaches it. "
                "Bedrock Guardrails is not exercised. The vulnerable column is 100% by construction: "
                "with no controls, a model that obeys everything loses to everything.")
    n = int(m.get("trials", 1))
    # Live runs: explain the counting rules. They are deliberately strict in
    # both directions: an attack that wins even once counts as a success,
    # and a legitimate request must work every time to count as completed.
    trials = ("One trial per case at temperature 0." if n == 1 else
              f"{n} trials per case at temperature 0. An attack counts as succeeded if it succeeded in any "
              "trial; a legitimate request counts as completed only if it completed in every trial. "
              "Cells show trials won out of trials run.")
    return (f"Source: live run against deployed stacks in {m.get('region', 'AWS')}, {m['run_at']}. "
            f"Model `{m['model']}`, guardrail `{m['guardrail']}`. {trials}")


def render(vuln: dict, hard: dict, title: str) -> str:
    # Assemble the full Markdown report in reading order: where the data came
    # from, the summary, every attack, then legitimate requests.
    return "\n\n".join([
        f"# {title}", provenance(vuln, hard),
        "## Attack success rate by category", summary_table(vuln, hard),
        "## Every attack", ATTRIBUTION_NOTE, detail_table(vuln, hard),
        "## Legitimate requests", benign_table(vuln, hard),
    ]) + "\n"


def inject(readme_text: str, block: str, content: str) -> str:
    """Replace the text between <!-- IB:{block}:START --> and <!-- IB:{block}:END -->."""
    # The README holds invisible HTML comment markers around its results
    # section. We replace only what is between them, so the rest of the
    # README is never touched. DOTALL lets ".*?" span many lines, and the
    # "?" makes it stop at the first END marker instead of the last one.
    pattern = re.compile(rf"(<!-- IB:{block}:START -->).*?(<!-- IB:{block}:END -->)", re.DOTALL)
    # Fail loudly if the markers are missing. Silently doing nothing would
    # leave stale numbers in the README without anyone noticing.
    if not pattern.search(readme_text):
        raise ValueError(f"README has no IB:{block} markers")
    # Keep both markers and put the new content between them. A function is
    # used instead of a replacement string so that any backslashes in the
    # content are not treated as special regex characters.
    return pattern.sub(lambda m: f"{m.group(1)}\n{content}\n{m.group(2)}", readme_text)
