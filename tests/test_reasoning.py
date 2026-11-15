# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# IN ONE SENTENCE
#   This file checks that the AI model's private "thinking out loud" notes are
#   always removed before the reply is shown to the bank customer.
#
# THE PROBLEM
#   The real AI model we use in AWS (Amazon Nova Lite) does not just answer.
#   It often writes its reasoning first, wrapped in <thinking> ... </thinking>
#   tags, and sometimes wraps the actual answer in <response> ... </response>.
#
#   We found this on the first live run:
#     - The vulnerable stack showed those notes, tags and all, to the customer.
#     - The hardened stack removed the tags (it treats tags as risky markup)
#       but KEPT the reasoning text, and raised a security alarm on every
#       single reply, even for honest customers.
#
# WHY THIS MATTERS
#   1. Customers should see an answer, not the model's internal plan, which
#      can mention tools, documents or other details they should not see.
#   2. Cleaning these tags is just reading the reply correctly. It is NOT a
#      security control, so it must happen in BOTH postures and must NEVER
#      raise a security event. False alarms on normal traffic would set off
#      the CloudWatch alarms for nothing.
#   3. Real attacks hidden inside the answer (like a malicious <img> tag)
#      must still be caught after the cleanup.
#
# WHAT THE TESTS CHECK
#   - Real replies recorded from Nova come out clean, matching what we expect.
#   - Tricky shapes work: odd capitalisation, several blocks, a reply cut off
#     mid-thought, a closing tag whose opening tag was lost, <response> tags.
#   - Both postures return a clean answer with zero security events.
#   - Dangerous markup inside <response> is still blocked in hardened mode.
#   - A reply that is ONLY reasoning gets replaced with a safe message.
#   - Our fake offline model imitates Nova's format, so the offline tests are
#     realistic.
#   - Across the whole attack bench, no reply ever leaks reasoning text.
# =============================================================================
"""The model's <thinking> blocks never reach the customer, in either posture.

Found in the first live run: Nova Lite wraps its reasoning in <thinking> tags.
The vulnerable stack returned them verbatim, and the hardened output filter
stripped the tags as markup but kept the reasoning, and logged every reply as
an unsafe-rendering event.
"""
import json
import pathlib

import pytest

from innovabank.models import SCRIPTED_REASONING, ScriptedModel, strip_reasoning
from innovabank_harness import runner
from innovabank_harness.targets import LocalTarget

# Real replies saved from the live Nova Lite model, each with the clean text we
# expect after stripping. Using real recordings, not only made-up strings,
# proves the fix works on what the model actually sends.
REPLIES = json.loads((pathlib.Path(__file__).parent / "fixtures" / "nova_lite_replies.json").read_text())["replies"]


# One test per recorded reply (named after its request id, like OK-01), so a
# failure points straight at the reply that broke.
@pytest.mark.parametrize("reply", REPLIES, ids=[r["id"] for r in REPLIES])
def test_recorded_nova_replies_lose_their_reasoning(reply):
    out = strip_reasoning(reply["raw"])
    assert out == reply["expected"]
    # Extra safety net: even if the expected text were wrong, the word
    # "thinking" (from a leftover tag) must never survive.
    assert "thinking" not in out.lower()


# Hand-written edge cases. Models do not always produce tidy tags, so the
# cleanup must handle the messy shapes too. When unsure, it removes text rather
# than show it, because a shorter answer is safer than leaked reasoning.
@pytest.mark.parametrize("text, expected", [
    # The normal case: one closed block before the answer.
    ("<thinking>plan</thinking>Answer.", "Answer."),
    # Tags in any capitalisation and with stray spaces still count.
    ("<THINKING >plan</ Thinking>\n\nAnswer.", "Answer."),
    # Several blocks in one reply: all of them go.
    ("<thinking>a</thinking> One. <thinking>b</thinking> Two.", "One.  Two."),
    # Reply cut off by the token limit while thinking: drop everything after
    # the opening tag, since it is unfinished reasoning.
    ("Answer first. <thinking>then a reply cut off by the token limit", "Answer first."),
    # Nothing but unfinished reasoning: nothing is left to show.
    ("<thinking>only reasoning, never closed", ""),
    # The opening tag was lost: everything before the closing tag was
    # reasoning, so keep only what comes after it.
    ("reasoning whose opening tag was lost</thinking> Answer.", "Answer."),
    # Plain answers must come through untouched.
    ("No reasoning here.", "No reasoning here."),
    # <response> tags are removed but the words inside are kept, because
    # those words ARE the answer.
    ("<thinking>plan</thinking>\n<response>Answer.</response>", "Answer."),
    ("<Response >Answer.</ RESPONSE>", "Answer."),
    # An unclosed <response> is the opposite of an unclosed <thinking>: the
    # text after it is the answer, so it is kept.
    ("<response>Answer cut off by the token limit", "Answer cut off by the token limit"),
    # Other markup inside the answer is left alone here. Deciding if it is
    # dangerous is the output filter's job, tested further down.
    ("<thinking>plan</thinking><response>Answer <b>bold</b>.</response>", "Answer <b>bold</b>."),
])
def test_closed_unclosed_and_orphan_tags(text, expected):
    assert strip_reasoning(text) == expected


# Run the full agent offline in both postures. Stripping reasoning is reply
# parsing, not a security control, so even the vulnerable stack must do it, and
# neither stack may log a security event for a normal balance question.
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_reasoning_is_removed_in_both_postures_without_security_events(mode):
    t = LocalTarget(mode)
    # Start from fresh seeded data so earlier tests cannot affect this one.
    t.reset()
    # The list is the script for the fake model: first call the balance tool,
    # then say the answer. LocalTarget adds Nova-style <thinking> blocks to
    # these steps, which is exactly what we want removed.
    out = t.invoke("What's my balance?", "C-1001", [
        {"tool": "get_account_summary", "args": {"customer_id": "C-1001"}},
        {"say": "Your balance is 2500.00 dollars."}])
    assert out["response"] == "Your balance is 2500.00 dollars."
    # No security events: honest traffic must stay quiet or alarms fire.
    assert out["trace"]["events"] == []


# Same idea for the <response> wrapper, which Nova added in a later live run.
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_response_wrapper_is_unwrapped_without_security_events(mode):
    """Live run 2026-11-11T21:18Z, OK-07: Nova wrapped its answer in <response> tags. The vulnerable
    stack showed them to the customer, the hardened output filter stripped them as markup and logged
    unsafe_output_rendering on a legitimate request."""
    t = LocalTarget(mode)
    t.reset()
    out = t.invoke("What's my balance?", "C-1001", [
        {"tool": "get_account_summary", "args": {"customer_id": "C-1001"}},
        {"say": "<response>Your balance is 2500.00 dollars.</response>"}])
    # The tags are gone, the answer is kept, and no alarm is raised.
    assert out["response"] == "Your balance is 2500.00 dollars."
    assert out["trace"]["events"] == []


# Unwrapping <response> must not become a way to sneak markup past the
# hardened output filter. An <img onerror=...> tag is a classic script
# injection trick, so it must still be removed and reported.
def test_markup_inside_the_response_wrapper_is_still_filtered():
    t = LocalTarget("hardened")
    t.reset()
    out = t.invoke("hi", "C-1001", [{"say": "<response>Hi <img src=x onerror=alert(1)></response>"}])
    assert "<img" not in out["response"]
    # Exactly one event, and it is the right kind: the real threat is flagged,
    # the harmless <response> tags are not.
    assert [e["ib_event"] for e in out["trace"]["events"]] == ["unsafe_output_rendering"]


# If stripping leaves nothing (the model only "thought" and never answered),
# the customer must not get an empty reply or the hidden plan. They should get
# some safe fallback text instead.
def test_answer_that_is_only_reasoning_falls_back_to_a_safe_message():
    t = LocalTarget("hardened")
    t.reset()
    out = t.invoke("hi", "C-1001", [{"say": "<thinking>internal plan, never closed"}])
    # The plan must not leak, and the reply must not be empty.
    assert "internal plan" not in out["response"] and out["response"]


# The offline tests only mean something if the fake model behaves like the real
# one. With reasoning=True it must put a <thinking> block first, then the tool
# call, the same layout Nova uses.
def test_scripted_model_formats_replies_like_nova():
    reply = ScriptedModel([{"tool": "get_account_summary", "args": {"customer_id": "C-1001"}}],
                          reasoning=True).converse("sys", [], [])
    assert reply["content"][0]["text"] == f"<thinking>{SCRIPTED_REASONING}</thinking>"
    assert "toolUse" in reply["content"][1]


# Broad final check: run every attack and every legitimate request in both
# postures, and make sure none of the replies contains the fake model's
# reasoning marker. This catches a leak on any code path, not just the ones
# tested above.
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_no_response_in_the_bench_contains_reasoning(mode):
    record = runner.run(LocalTarget(mode))
    # Collect the id of any reply that leaked. An empty list means no leaks,
    # and if it fails the ids tell you exactly which cases to look at.
    leaks = [r["id"] for r in record["attacks"] + record["benign"] if "IB-SCRIPTED-REASONING" in r["response"]]
    assert leaks == []
