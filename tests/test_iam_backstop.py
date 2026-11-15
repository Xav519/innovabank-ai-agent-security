# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# In the deployed stack, every tool runs in its own Lambda with its own IAM
# role. That role is the last line of defence (the "backstop"): even if every
# other control fails and the model asks for something it should not, AWS
# itself refuses the call when the role lacks permission.
#
# The problem these tests guard against: when AWS refused a call, the tool
# used to just crash. The agent then saw a vague "tool execution failed", no
# security event was written, and the attack report could not say WHICH
# control had stopped the attack. A real block looked like a random bug.
#
# These tests check that an IAM deny is now handled cleanly at every layer:
#
#   - AGENT: a deny is logged as a security event ("tool_access_denied",
#     control "iam", action "blocked") in BOTH postures, and the report
#     credits it as "blocked by per-tool IAM".
#   - DISPATCHER (the code that invokes tool Lambdas): it recognises a deny
#     whether it happened inside the tool or when calling the tool, and it
#     does NOT mislabel other failures (timeouts, throttling) as denies.
#   - TOOL HANDLER (the code running inside each tool Lambda): it returns a
#     deny as a clean result instead of crashing, but still raises any other
#     error so real problems stay visible.
#
# Everything runs offline with fakes in place of AWS: no account, no cost.
# =============================================================================
"""An IAM deny from a tool's own role is logged and attributed, not swallowed as a generic failure.

Before this, a tool Lambda whose role refused the AWS call crashed with an unhandled
ClientError, the dispatcher returned "tool execution failed", no security event was
logged, and the harness could not say which control had stopped the request.
"""
import io
import json

import pytest
from botocore.exceptions import ClientError

from innovabank import handlers
from innovabank.agent import Agent
from innovabank.config import Config
from innovabank.models import ScriptedModel
from innovabank.tools import LambdaDispatcher, access_denied_code
from innovabank_harness import report, runner
from innovabank_harness.targets import LocalTarget

# The exact text S3 puts in an error when a role is not allowed to read an
# object. The dispatcher has to find the deny inside this message, so the
# test uses the real wording rather than a made-up one.
S3_DENY = "An error occurred (AccessDenied) when calling the GetObject operation: Access Denied"


def client_error(code, op="GetObject"):
    # Builds the same kind of error boto3 raises when an AWS call fails, so
    # tests can simulate any AWS error code without touching AWS.
    return ClientError({"Error": {"Code": code, "Message": "denied"}}, op)


# ------------------------------------------------------------------ agent


class DenyingDispatcher:
    # A fake tool runner that always answers as if the tool's IAM role had
    # refused the call. This lets the agent test focus only on how the agent
    # reacts to a deny, without any Lambda or AWS involved.
    def call(self, name, args):
        return {"error": "access denied by the tool's IAM role", "access_denied": True,
                "detail": "GetObject AccessDenied"}


# IAM is enforced by AWS, not by our code, so it cannot be switched off. That
# is why the deny must show up as "blocked" even in the vulnerable posture.
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_agent_logs_an_iam_deny_as_blocked_by_iam_in_both_postures(mode):
    t = LocalTarget(mode)
    t.reset()
    # Script the model to call one tool and then repeat whatever came back.
    model = ScriptedModel([{"tool": "read_document", "args": {"key": "kb/public/fees.md"}},
                           {"say": "{tool_results}"}])
    out = Agent(t.cfg, model, DenyingDispatcher(), t.store).handle("open it", "C-1001", quiet=True)
    events = out["trace"]["events"]
    # Exactly one event, and it names IAM as the control that blocked. Any
    # extra event would mean the deny was also mistaken for something else.
    assert [(e["ib_event"], e["control"], e["action"]) for e in events] == [("tool_access_denied", "iam", "blocked")]
    # The event is tagged with its MITRE ATLAS technique and OWASP category,
    # which CloudWatch alarms and the report rely on.
    assert events[0]["atlas_technique"] == "AML.T0053" and events[0]["owasp"] == "LLM06"
    # The tool name is in the detail so an analyst knows which tool was refused.
    assert "read_document" in events[0]["detail"]
    # The tool call itself is recorded as denied, with a clear reason.
    call = out["trace"]["tool_calls"][0]
    assert (call["status"], call["reason"]) == ("denied", "denied by the tool's IAM role")
    # The harness credits the block to IAM, so the results table is honest.
    assert runner._controls(events, "blocked") == ["iam"]


def test_report_names_the_iam_backstop():
    # The report shows a readable label, not the internal name "iam", so a
    # reader understands which defence stopped the attack.
    assert report._labels(["iam"]) == "per-tool IAM"
    assert report._outcome({"succeeded": False, "blocked_by": ["iam"]}, {"succeeded": True}) == "blocked by per-tool IAM"


# ------------------------------------------------------------------ dispatcher


class FakeLambda:
    # A stand-in for the boto3 Lambda client. It can return a normal payload,
    # pretend the tool crashed (function_error), or raise an error as if the
    # invoke call itself failed (raises). That covers every path the
    # dispatcher has to handle.
    def __init__(self, payload=None, function_error=None, raises=None):
        self.payload, self.function_error, self.raises = payload or {}, function_error, raises

    def invoke(self, FunctionName, Payload):
        if self.raises:
            raise self.raises
        # Real Lambda returns the payload as a readable byte stream, so the
        # fake does the same.
        resp = {"Payload": io.BytesIO(json.dumps(self.payload).encode())}
        if self.function_error:
            resp["FunctionError"] = self.function_error
        return resp


def dispatcher(client):
    # A real LambdaDispatcher wired to a fake client, with one tool mapped to
    # a function name so the dispatcher knows what to invoke.
    return LambdaDispatcher(Config.for_mode("hardened", tool_functions={"read_document": "fn-read"}), client)


def test_dispatcher_reports_an_unhandled_iam_deny_inside_the_tool():
    # Case 1: the tool Lambda ran but crashed on an S3 deny it did not catch.
    # The dispatcher must spot "AccessDenied" in the crash message and turn
    # it into a proper deny result, instead of a generic failure.
    out = dispatcher(FakeLambda({"errorType": "ClientError", "errorMessage": S3_DENY}, "Unhandled")).call(
        "read_document", {"key": "internal/ops-runbook.md"})
    assert out["access_denied"] is True and out["detail"] == "AccessDenied"


def test_dispatcher_reports_the_agent_role_being_denied_invoke():
    # Case 2: the agent's own role is not even allowed to start this tool's
    # Lambda. That is also an IAM block and must be reported as one.
    out = dispatcher(FakeLambda(raises=client_error("AccessDeniedException", "Invoke"))).call("read_document", {})
    assert out["access_denied"] is True and "AccessDeniedException" in out["detail"]


def test_dispatcher_keeps_other_failures_generic_and_reraises_other_errors():
    # A timeout is not a security block. Calling it one would give IAM false
    # credit and fire false alarms, so it stays a generic failure.
    out = dispatcher(FakeLambda({"errorType": "Timeout", "errorMessage": "Task timed out"}, "Unhandled")).call(
        "read_document", {})
    assert out == {"error": "tool execution failed", "detail": "Timeout"}
    # Throttling on invoke is an operational problem, not a deny. It must be
    # raised, not hidden, so it gets noticed and fixed.
    with pytest.raises(ClientError):
        dispatcher(FakeLambda(raises=client_error("ThrottlingException", "Invoke"))).call("read_document", {})


# AWS services use different codes to say "not allowed". All of them must be
# recognised as a deny, and common non-deny errors must not be.
@pytest.mark.parametrize("code, denied", [
    ("AccessDenied", True), ("AccessDeniedException", True), ("UnauthorizedOperation", True),
    ("NoSuchKey", False), ("ThrottlingException", False), ("ResourceNotFoundException", False),
])
def test_access_denied_codes(code, denied):
    assert (access_denied_code(client_error(code)) is not None) is denied
    # A plain Python error (not from AWS) must never be treated as a deny,
    # and must not crash the check either.
    assert access_denied_code(ValueError("not an AWS error")) is None


# ------------------------------------------------------------------ tool handler


class FakeBoto3:
    # The tool handler asks boto3 for AWS clients at startup. This fake hands
    # back dummy objects so the handler can run without real AWS.
    @staticmethod
    def client(name):
        return object()


def test_tool_handler_returns_an_iam_deny_instead_of_crashing(monkeypatch):
    # Replace the handler's AWS setup with fakes, so nothing real is called.
    monkeypatch.setattr(handlers, "_runtime", lambda: (Config.for_mode("hardened"), FakeBoto3, None))

    # Make the tool fail exactly as S3 does when the role cannot read a file.
    def deny(*a, **k):
        raise client_error("AccessDenied", "GetObject")

    monkeypatch.setattr(handlers, "run_tool", deny)
    out = handlers.tool_handler({"tool": "read_document", "args": {"key": "internal/ops-runbook.md"}}, None)
    # The handler returns a clean deny result naming the refused AWS action,
    # so the agent can log it, instead of the Lambda crashing.
    assert out["access_denied"] is True and out["detail"] == "GetObject AccessDenied"


def test_tool_handler_still_raises_other_errors(monkeypatch):
    monkeypatch.setattr(handlers, "_runtime", lambda: (Config.for_mode("hardened"), FakeBoto3, None))

    # A DynamoDB capacity error is a real operational problem, not a deny.
    def boom(*a, **k):
        raise client_error("ProvisionedThroughputExceededException", "GetItem")

    monkeypatch.setattr(handlers, "run_tool", boom)
    # Only denies are converted. Everything else must still raise so it is
    # visible in logs instead of being quietly swallowed.
    with pytest.raises(ClientError):
        handlers.tool_handler({"tool": "get_account_summary", "args": {}}, None)
