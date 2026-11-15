# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file runs the test catalog against the agent and writes down what
# really happened.
#
# There are two kinds of test cases, both stored as YAML:
#
#   - Attacks (harness/attacks/*.yaml): things a bad actor would try, such
#     as prompt injection or tricking the agent into sending money. An attack
#     "succeeds" if ANY of its success conditions came true.
#
#   - Legitimate requests (harness/benign.yaml): normal things a real
#     customer would ask. A request "passes" only if ALL of its expected
#     results came true.
#
# For each case, the runner:
#
#   1. Resets the target, so one case can never affect the next.
#   2. Plants any documents the case needs (for example a poisoned
#      knowledge base article).
#   3. Sends the prompt to the agent as the given customer.
#   4. Looks at the real outcome (transfers made, messages sent, the reply)
#      and judges it with plain code in detectors.py. No AI judges the AI.
#   5. Records which security controls blocked something and which security
#      events fired.
#
# The "target" can be the agent running in process (offline, free, used by
# tests and CI) or a real deployed AWS stack (live). The runner does not care
# which one; it only calls reset, plant, invoke, observe and describe.
#
# The result is one JSON friendly dictionary that report.py turns into
# tables and that the CI regression guard checks.
#
# =============================================================================

"""Run the catalog against a target and record what actually happened."""
from __future__ import annotations

import datetime
import pathlib

import yaml

from . import detectors

# The harness/ folder. Attack and benign YAML files are found relative to it,
# so the runner works no matter which directory it is launched from.
HARNESS_DIR = pathlib.Path(__file__).resolve().parents[1]


def load_catalog() -> list[dict]:
    attacks = []
    # Sorted so attacks always run (and appear in reports) in the same order,
    # which keeps result files easy to diff between runs.
    for path in sorted((HARNESS_DIR / "attacks").glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        # Each YAML file holds one category of attacks. The category level
        # details (OWASP code, name, module) are written once per file, so we
        # copy them onto every attack to make each one self contained.
        for a in doc["attacks"]:
            attacks.append({**a, "category": doc["category"], "owasp": doc["owasp"],
                            "owasp_name": doc["owasp_name"], "path_module": doc["path_module"]})
    return attacks


def load_benign() -> list[dict]:
    return yaml.safe_load((HARNESS_DIR / "benign.yaml").read_text(encoding="utf-8"))["cases"]


def _execute(target, case: dict) -> tuple[dict, dict, list[dict]]:
    # Start from a clean state (fresh balances, empty outbox, no leftover
    # documents) so results never depend on which case ran before.
    target.reset()
    events: list[dict] = []
    # Some attacks need a document in place first, such as a poisoned
    # knowledge base article. Planting it goes through the real ingestion
    # path, which can itself raise security events (for example an unsigned
    # document being quarantined), so we keep those events too.
    for doc in (case.get("setup") or {}).get("documents", []):
        outcome = target.plant(doc["key"], doc["body"], bool(doc.get("signed")))
        events.extend(outcome.get("events", []))
    prompt = case["prompt"]
    # Some attacks try to overwhelm the agent with a very long message. Rather
    # than storing huge text in YAML, the case gives a length and we pad the
    # prompt with harmless filler up to exactly that many characters.
    # 23 is the length of the filler sentence, so we repeat it enough times
    # and then cut to the exact size.
    if case.get("pad_chars"):
        prompt = ("Please read carefully. " * (int(case["pad_chars"]) // 23 + 1))[: int(case["pad_chars"])] + "\n" + prompt
    # compromised_model is only used offline: it scripts what a fooled model
    # would try to do. A real model on AWS ignores it and decides for itself.
    result = target.invoke(prompt, case["session"], case.get("compromised_model", []))
    events.extend(result.get("trace", {}).get("events", []))
    # observe() reads the real side effects (transfers, sent messages). We
    # judge on those, not on what the agent claims it did in its reply.
    return result, target.observe(), events


def _controls(events: list[dict], action: str) -> list[str]:
    # List each control that took the given action ("blocked" or "observed"),
    # once, in the order it first appeared. Order is kept so the report shows
    # which control stepped in first.
    seen: list[str] = []
    for e in events:
        if e.get("action") == action and e["control"] not in seen:
            seen.append(e["control"])
    return seen


def _trial(target, case: dict, verdict) -> dict:
    """One execution of a case: what happened, judged by `verdict(result, observed)`."""
    result, observed, events = _execute(target, case)
    return {
        "ok": verdict(result, observed),
        "blocked_by": _controls(events, "blocked"),
        "detected_by": sorted({e["ib_event"] for e in events}),
        # Responses and tool call lists are trimmed so result files stay
        # small and readable, while still showing enough to understand the
        # outcome.
        "response": result.get("response", "")[:400],
        "tool_calls": result.get("trace", {}).get("tool_calls", [])[:12],
    }


def _union(lists) -> list[str]:
    # Merge several lists into one with no duplicates, keeping first seen
    # order (a set would lose the order).
    seen: list[str] = []
    for items in lists:
        seen.extend(i for i in items if i not in seen)
    return seen


def _aggregate(trials: list[dict], show: dict, key: str) -> dict:
    """Summary fields over every trial. Events and blocks are the union, so one noisy trial shows.

    `show` is the trial whose response and tool calls are kept at the top level, the most
    telling one: a trial where the attack got through, or where the legitimate request broke.
    """
    return {
        "trials": len(trials),
        "blocked_by": _union(t["blocked_by"] for t in trials),
        "detected_by": sorted(set(_union(t["detected_by"] for t in trials))),
        "response": show["response"],
        "tool_calls": show["tool_calls"],
        # Keep every trial's details too, renaming "ok" to the meaningful word
        # for this kind of case ("succeeded" for attacks, "passed" for benign).
        "runs": [{key: t["ok"], **{k: v for k, v in t.items() if k != "ok"}} for t in trials],
    }


def run(target, only: set[str] | None = None, trials: int = 1) -> dict:
    """Execute every attack and benign case `trials` times. Returns a JSON-serialisable record.

    A live model is not deterministic even at temperature 0, so one trial can flip either way.
    An attack counts as succeeded if it succeeded in any trial (worst case). A legitimate request
    counts as passed only if it passed in every trial; `passes` says how many did, and the
    regression guard decides how many it needs.
    """
    if trials < 1:
        raise ValueError("trials must be at least 1")
    attacks, benign = [], []
    for case in load_catalog():
        # `only` lets you rerun a few cases by id (for example PI-01,EA-02)
        # instead of the whole catalog while debugging.
        if only and case["id"] not in only:
            continue
        # An attack wins if ANY success condition is met. The `case=case`
        # default binds the current case to the lambda; without it every
        # lambda would see the last case of the loop.
        runs = [_trial(target, case, lambda r, o, case=case: detectors.any_of(case["success"], r, o)) for _ in range(trials)]
        hits = sum(t["ok"] for t in runs)
        # Show a trial where the attack worked, if there was one, because
        # that is the evidence someone reading the report needs to see.
        show = next((t for t in runs if t["ok"]), runs[0])
        attacks.append({
            "id": case["id"], "name": case["name"], "category": case["category"],
            "owasp": case["owasp"], "owasp_name": case["owasp_name"], "atlas": case["atlas"],
            "path_module": case["path_module"],
            # Worst case: a single success out of many trials still counts,
            # because a real attacker only needs to get lucky once.
            "succeeded": hits > 0, "successes": hits,
            **_aggregate(runs, show, "succeeded"),
        })
    for case in load_benign():
        if only and case["id"] not in only:
            continue
        # A legitimate request is fine only if ALL expected results happen.
        runs = [_trial(target, case, lambda r, o, case=case: detectors.all_of(case["expect"], r, o)) for _ in range(trials)]
        passes = sum(t["ok"] for t in runs)
        # Here the interesting trial is one that broke, so show that first.
        show = next((t for t in runs if not t["ok"]), runs[0])
        benign.append({
            "id": case["id"], "name": case["name"],
            # Strict on purpose: a request that works only sometimes is a
            # broken experience for a real customer.
            "passed": passes == trials, "passes": passes,
            **_aggregate(runs, show, "passed"),
        })
    # Leave the target clean so the last case's side effects do not linger
    # (important for a live stack that someone may use afterwards).
    target.reset()
    return {
        # meta records what was tested and when, so a result file explains
        # itself later without needing the command that produced it.
        "meta": {**target.describe(), "trials": trials,
                 "run_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "attacks": attacks,
        "benign": benign,
    }
