# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# A "target" is the thing the harness attacks. This file defines the two
# kinds of target the harness can point at:
#
#   - LocalTarget ("offline"): the whole agent runs inside this Python
#     process. Memory instead of DynamoDB and S3, a scripted fake model
#     instead of Bedrock, local signing instead of KMS. It is free, fast and
#     needs no AWS account, so tests and CI use it.
#
#   - AwsTarget ("aws"): a real stack deployed with Terraform. The harness
#     reads the Terraform outputs file to find the Lambda functions, tables,
#     bucket and signing key, then talks to them with boto3. It costs money
#     and uses the real Bedrock model.
#
# Both classes offer the same five methods, so the runner never needs to know
# which one it is using:
#
#   reset()     put the environment back to a clean, known state
#   plant()     drop a document into the knowledge base (for poisoning attacks)
#   invoke()    send one prompt to the agent as a given customer
#   observe()   read back the side effects (transfers made, messages sent)
#   describe()  say what was tested (mode, controls, model), for the report
#
# Keeping the two targets interchangeable is the point: the same attack
# catalog and the same success checks run against both, so offline and live
# results can be compared directly.
#
# =============================================================================

"""Where the harness points: an in-process stack, or a deployed one in AWS."""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

# The agent code lives in app/, not in the harness package. Add it to the
# import path so this file works even when PYTHONPATH was not set.
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "app"))

# These imports must come after the sys.path change above, which is why the
# linter's "imports at the top" rule (E402) is silenced on each line.
from innovabank import ingest, seed  # noqa: E402
from innovabank.agent import Agent  # noqa: E402
from innovabank.config import Config  # noqa: E402
from innovabank.models import ScriptedModel  # noqa: E402
from innovabank.rag import LocalEmbedder  # noqa: E402
from innovabank.seclog import Trace  # noqa: E402
from innovabank.store import SIGNATURE_META, AwsStore, KmsSigner, LocalSigner, MemoryStore  # noqa: E402
from innovabank.tools import LocalDispatcher  # noqa: E402


class LocalTarget:
    """Runs the real orchestrator and controls in process.

    The model is replaced by ScriptedModel, an adversary that obeys any
    injection that reaches it. Bedrock Guardrails is not available offline, so
    results from this target measure the deterministic controls only.
    """

    # Label shown in reports so readers know these are offline results.
    kind = "offline"

    def __init__(self, mode: str, controls: str | None = None):
        # mode is "vulnerable" or "hardened"; controls can override it (for
        # example "-taint_lock" for the ablation study).
        self.cfg = Config.for_mode(mode, controls)
        # Offline stand-ins for DynamoDB/S3, KMS and Titan embeddings.
        self.store = MemoryStore()
        self.signer = LocalSigner()
        self.embedder = LocalEmbedder()
        # Read the seed documents from disk once, not on every reset, since
        # reset runs before every single attack.
        self._corpus = seed.load_corpus()

    def _ingest(self, key: str) -> dict:
        # Index one document using the same ingest code the Lambda uses.
        # quiet=True keeps security events off stdout; we still collect them
        # so the runner can see if ingest_integrity or ingest_scan blocked it.
        trace = Trace(self.cfg.mode, quiet=True)
        outcome = ingest.ingest_document(key, self.cfg, self.store, self.embedder, self.signer, trace)
        return {**outcome, "events": trace.events}

    def reset(self) -> None:
        # Shared reset logic, so offline and AWS start from the same state.
        seed.reset(self.store, self.signer, self._ingest, self._corpus)

    def plant(self, key: str, body: str, signed: bool) -> dict:
        # Simulate an attacker slipping a document into the knowledge base.
        # signed=True models a compromised publisher (a valid signature);
        # signed=False models an outsider who cannot sign, which the
        # ingest_integrity control should reject.
        raw = body.encode()
        self.store.doc_put(key, raw, {SIGNATURE_META: self.signer.sign(raw)} if signed else {})
        return self._ingest(key)

    def invoke(self, prompt: str, customer_id: str, script: list[dict]) -> dict:
        # Offline there is no real model, so each attack brings a script of
        # what a compromised model would do. A fresh model and agent per call
        # means nothing leaks from one attack into the next.
        model = ScriptedModel(script, reasoning=True)  # replies carry <thinking> blocks, like Nova
        agent = Agent(self.cfg, model, LocalDispatcher(self.cfg, self.store, self.embedder), self.store)
        return agent.handle(prompt, customer_id, quiet=True)

    def observe(self) -> dict:
        # Transfers and sent messages are the real damage an attack can do,
        # so the success checks look here rather than trusting the reply text.
        return {"transfers": self.store.list_transfers(), "outbox": self.store.outbox_list()}

    def describe(self) -> dict:
        # Be honest in the report about what was NOT tested offline: no real
        # model and no Guardrail.
        return {"target": self.kind, "mode": self.cfg.mode, "controls": sorted(self.cfg.controls),
                "model": "ScriptedModel (assumed-compromised adversary)", "guardrail": "not exercised offline"}


class AwsTarget:
    """Drives a deployed stack using its Terraform outputs.

    Needs credentials that can invoke the agent and ingestion functions, read
    and write the stack's tables and bucket, and call kms:Sign on the corpus
    signing key. That is the publisher and assessor role, not the agent's.
    """

    # Label shown in reports so readers know these are live results.
    kind = "aws"

    def __init__(self, outputs_file: str):
        # Imported here, not at the top, so offline runs and tests work
        # without boto3 being loaded.
        import boto3

        raw = json.loads(pathlib.Path(outputs_file).read_text())
        # `terraform output -json` wraps each value as {"value": ..., "type": ...}.
        # Unwrap it so the rest of the code can read out["region"] directly,
        # while still accepting a file that is already flat.
        # Terraform output values are loose JSON; typed as Any so the editor
        # doesn't guess a narrower type for them.
        out: dict[str, Any] = {k: (v["value"] if isinstance(v, dict) and "value" in v else v) for k, v in raw.items()}
        self.out = out
        session = boto3.Session(region_name=out["region"])
        # Build the same config the deployed Lambdas use, so the harness reads
        # and writes the exact tables and bucket of this stack.
        self.cfg = Config.for_mode(
            out["mode"], out.get("controls_override") or None,
            customers_table=out["customers_table"], transfers_table=out["transfers_table"],
            outbox_table=out["outbox_table"], kb_table=out["kb_table"],
            bucket=out["bucket"], signing_key_id=out["signing_key_id"],
            model_id=out["model_id"],
        )
        self.store = AwsStore(self.cfg, session)
        # Real KMS signing, so planted "signed" documents pass the same
        # signature check a legitimate publisher's would.
        self.signer = KmsSigner(session.client("kms"), out["signing_key_id"])
        from botocore.config import Config as BotoConfig

        # An agent turn can take minutes in the vulnerable posture. Never retry: a retry re-runs the attack.
        self._lambda = session.client("lambda", config=BotoConfig(
            read_timeout=330, connect_timeout=10, retries={"total_max_attempts": 1}))
        self._corpus = seed.load_corpus()

    def _call(self, function: str, payload: dict) -> dict:
        # Invoke a Lambda and return its JSON reply.
        resp = self._lambda.invoke(FunctionName=function, Payload=json.dumps(payload).encode())
        body = json.loads(resp["Payload"].read() or b"{}")
        # Lambda reports a crash in the reply, not as an exception, so check
        # for it explicitly instead of silently treating it as a result.
        if resp.get("FunctionError"):
            raise RuntimeError(f"{function} failed: {json.dumps(body)[:500]}")
        return body

    def _ingest(self, key: str) -> dict:
        # Ingest through the deployed Lambda so the real cloud ingest path
        # (signature check, content scan, Titan embeddings) is what gets tested.
        return self._call(self.out["ingest_function"], {"key": key})["results"][0]

    def reset(self) -> None:
        # Same reset logic as offline, just backed by DynamoDB, S3 and KMS.
        seed.reset(self.store, self.signer, self._ingest, self._corpus)

    def plant(self, key: str, body: str, signed: bool) -> dict:
        # Same idea as LocalTarget.plant: put the document in S3, then ingest it.
        raw = body.encode()
        self.store.doc_put(key, raw, {SIGNATURE_META: self.signer.sign(raw)} if signed else {})
        outcome = self._ingest(key)
        # In AWS the security events go to CloudWatch logs, not back in the
        # Lambda reply. Rebuild the matching event from the quarantine reason
        # so the report can still credit the control that blocked the document.
        if outcome.get("status") == "quarantined":
            reasons = outcome.get("reasons", [])
            control = "ingest_integrity" if "signature" in reasons else "ingest_scan"
            outcome["events"] = [{"control": control, "action": "blocked", "ib_event": "rag_document_rejected"}]
        return outcome

    def invoke(self, prompt: str, customer_id: str, script: list[dict]) -> dict:
        # The script is ignored here: the real Bedrock model decides what to
        # do. It is only in the signature so both targets look the same.
        try:
            return self._call(self.out["agent_function"], {"message": prompt, "session": {"customer_id": customer_id}})
        except Exception as exc:  # timeout or function error: record it and keep the run going
            return {"response": f"[harness] agent call failed: {exc}"[:400], "blocked": False, "trace": {}}

    def observe(self) -> dict:
        # Read the real side effects straight from DynamoDB.
        return {"transfers": self.store.list_transfers(), "outbox": self.store.outbox_list()}

    def describe(self) -> dict:
        # Record the exact model, Guardrail and region, so a live result can
        # be traced back to the stack that produced it.
        return {"target": self.kind, "mode": self.cfg.mode, "controls": sorted(self.cfg.controls),
                "model": self.out["model_id"],
                "guardrail": self.out.get("guardrail_id") or "none", "region": self.out["region"]}
