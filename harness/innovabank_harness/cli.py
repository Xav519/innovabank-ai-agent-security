# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This is the "front door" of the attack harness: the commands you type in a
# terminal (or that the Makefile and CI type for you). It does not attack
# anything itself. It reads your command, picks the right target, calls the
# code that does the real work, and saves or prints the result.
#
# There are five commands:
#
#   run       Fire the whole attack catalog (plus the legitimate requests)
#             at the agent and save the outcome to a JSON file.
#               --target offline : everything runs on your laptop, free,
#                                  with a scripted "evil" model.
#               --target aws     : hits a real deployed stack on AWS.
#
#   report    Read two JSON results (vulnerable and hardened) and turn them
#             into a readable Markdown before/after table. It can also
#             refresh the results block inside the README.
#
#   ablation  Take the hardened agent, switch off ONE control at a time,
#             and see which attacks come back. This shows what each control
#             is really holding back on its own.
#
#   seed      Reset a deployed AWS stack to a clean starting state (fake
#             customers restored, help documents signed and indexed).
#
#   ask       Send one message to a deployed stack, as one customer, and
#             print what happened: the answer, the tools it used, and any
#             security events. Handy for poking at the agent by hand.
#
# Why a separate file: keeping all the "terminal plumbing" here means the
# runner, the targets and the report code stay plain functions that the
# tests can call directly, with no command line parsing in the way.
#
# =============================================================================

"""Command line entry point.

  python -m innovabank_harness run --target offline --mode hardened --out results/offline-hardened.json
  python -m innovabank_harness run --target aws --outputs infra/envs/hardened/outputs.json --trials 3 --out results/live-hardened.json
  python -m innovabank_harness report --vulnerable a.json --hardened b.json --out docs/results/offline.md
  python -m innovabank_harness ablation
  python -m innovabank_harness seed --outputs infra/envs/hardened/outputs.json
  python -m innovabank_harness ask --outputs infra/envs/hardened/outputs.json --customer C-1001 "What is my balance?"
"""
from __future__ import annotations

import argparse
import json
import pathlib

from . import report, runner
from .targets import ROOT, AwsTarget, LocalTarget


def _positive_int(value: str) -> int:
    # Used to check --trials. argparse only knows "is it a number?", not
    # "is it at least 1?". Zero trials would produce an empty, misleading
    # result, so we reject it right away with a clear message.
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def _target(args):
    # Pick WHAT we are attacking. Both targets offer the same methods, so
    # the runner does not need to know which one it got.
    if args.target == "aws":
        # A deployed stack is found through the JSON file Terraform writes
        # (table names, bucket, Lambda names...). Without it we cannot know
        # where the stack lives, so stop with a helpful message.
        if not args.outputs:
            raise SystemExit("--outputs <terraform outputs json> is required with --target aws")
        # Note: --mode and --controls are ignored here. A live stack already
        # has its posture baked in at deploy time; we read it from outputs.
        return AwsTarget(args.outputs)
    # Offline: build the agent in memory with the chosen posture and any
    # control tweaks (for example "-taint_lock").
    return LocalTarget(args.mode, args.controls)


def cmd_run(args) -> int:
    # --only "PI-01,EA-02" becomes a set of ids so you can rerun just a few
    # attacks while debugging. No --only means "run everything" (None).
    record = runner.run(_target(args), set(args.only.split(",")) if args.only else None, trials=args.trials)
    out = pathlib.Path(args.out)
    # Create the results folder if needed so a fresh clone just works.
    out.parent.mkdir(parents=True, exist_ok=True)
    # Saved as pretty JSON: report, the regression guard and humans all
    # read this same file later. The trailing newline keeps git diffs clean.
    out.write_text(json.dumps(record, indent=2) + "\n")
    # A one-line score so you see the outcome without opening the file.
    # True counts as 1 in Python, so sum() counts the successes.
    hit = sum(a["succeeded"] for a in record["attacks"])
    ok = sum(b["passed"] for b in record["benign"])
    print(f"{record['meta']['target']}/{record['meta']['mode']}: {hit}/{len(record['attacks'])} attacks succeeded, "
          f"{ok}/{len(record['benign'])} legitimate requests completed"
          f"{f' (over {args.trials} trials)' if args.trials > 1 else ''} -> {out}")
    # Always 0: a run that finds successful attacks is still a successful
    # run. Deciding whether that is acceptable is the regression guard's job
    # (tests/check_regression.py), not this command's.
    return 0


def cmd_report(args) -> int:
    vuln = json.loads(pathlib.Path(args.vulnerable).read_text())
    hard = json.loads(pathlib.Path(args.hardened).read_text())
    # The result file remembers where it came from. Live and offline numbers
    # mean different things (real model vs scripted adversary), so they get
    # different titles and go into different README blocks. Never mix them.
    live = hard["meta"]["target"] == "aws"
    title = "InnovaBank results: live Bedrock run" if live else "InnovaBank results: offline control verification"
    text = report.render(vuln, hard, title)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(f"wrote {out}")
    if args.readme:
        # Rewrite only the text between the README's START/END markers, so
        # the published numbers always match the latest run and nobody has
        # to copy them by hand (and get them wrong).
        readme = pathlib.Path(args.readme)
        block = "LIVE-RESULTS" if live else "OFFLINE-RESULTS"
        # Provenance first, so a reader knows how the numbers were produced
        # before reading them.
        content = report.provenance(vuln, hard) + "\n\n" + report.summary_table(vuln, hard)
        readme.write_text(report.inject(readme.read_text(), block, content))
        print(f"updated {block} block in {readme}")
    return 0


def cmd_ablation(args) -> int:
    """Remove one control at a time from the hardened posture and see what comes back."""
    # Imported here, not at the top, because only this command needs it.
    from innovabank.config import ALL_CONTROLS

    # First, the starting point: which attacks already get through with ALL
    # controls on (the accepted residual). We subtract these later, so each
    # row only shows attacks that the removed control was stopping.
    baseline = {a["id"] for a in runner.run(LocalTarget("hardened"))["attacks"] if a["succeeded"]}
    lines = ["# Control ablation (offline)", "",
             "Each row is the hardened posture with one control removed, against the scripted adversary model. "
             "An attack listed here is one that this control alone was holding back. A control with no "
             "attacks listed is not redundant: it means another layer also covers those attacks.", "",
             f"Baseline, all controls on: {', '.join(sorted(baseline)) or 'none'} succeed.", "",
             "| Control removed | Attacks that now succeed | Legitimate requests |", "|---|---|---|"]
    for control in ALL_CONTROLS:
        if control == "guardrail":
            # Bedrock Guardrails is an AWS service and is not simulated
            # offline, so removing it here would show nothing. Rather than
            # print a misleading "none", we state the live measurement.
            lines.append("| Bedrock Guardrails | not measurable offline. Live, on the deployed stack (3 trials): "
                         "PI-06 succeeds 3/3 without it, 0/3 with it. See docs/controls.md | n/a offline |")
            continue
        # "-taint_lock" means "hardened, minus the taint lock". A fresh
        # target each time, so one row cannot leak state into the next.
        rec = runner.run(LocalTarget("hardened", f"-{control}"))
        back = sorted({a["id"] for a in rec["attacks"] if a["succeeded"]} - baseline)
        # Also count legitimate requests: if removing a control changes
        # them, that control was affecting real customers too.
        ok = sum(b["passed"] for b in rec["benign"])
        lines.append(f"| {report.CONTROL_LABELS[control]} | {', '.join(back) or 'none'} | {ok}/{len(rec['benign'])} |")
    text = "\n".join(lines) + "\n"
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    # Print the table too, so you see it right away in the terminal.
    print(text)
    return 0


def cmd_seed(args) -> int:
    # Seeding only makes sense for a real stack: offline targets reset
    # themselves in memory before every case.
    target = AwsTarget(args.outputs)
    # Same reset the harness uses between attacks: restore customers, clear
    # transfers and outbox, sign and index the help documents. Running it
    # after deploy gives the stack a known, clean starting state.
    target.reset()
    print(f"seeded {target.out['bucket']}: customers restored, corpus signed and indexed")
    return 0


def format_turn(result: dict) -> str:
    """Human-readable view of one agent turn: the answer, the tool calls, the security events."""
    # Shows the three things you want to see when testing by hand:
    # what Inno said, what it tried to DO, and what the controls noticed.
    # The answer alone can look harmless while a tool call did the damage.
    # .get(...) or {} keeps this safe if a field is missing from the reply.
    trace = result.get("trace") or {}
    # Indent every line of the answer so it stands apart from the headings.
    lines = ["", "ANSWER", "  " + (result.get("response") or "").replace("\n", "\n  "), ""]
    calls = trace.get("tool_calls") or []
    lines.append("TOOL CALLS" + ("" if calls else "  (none)"))
    for t in calls:
        # Status is padded to a fixed width so the columns line up.
        # If a policy denied the call, the reason is shown after an arrow.
        reason = f"  <- {t['reason']}" if t.get("reason") else ""
        lines.append(f"  {t['status']:<9} {t['name']} {json.dumps(t['args'])}{reason}")
    events = trace.get("events") or []
    lines.append("")
    lines.append("SECURITY EVENTS" + ("" if events else "  (none)"))
    for e in events:
        # One line per event: blocked or observed, which control, and the
        # MITRE ATLAS / OWASP labels, so you can map it to the threat model.
        lines.append(f"  {e['action']:<9} {e['control']:<16} {e['atlas_technique']} {e['atlas_name']} ({e['owasp']})")
        if e.get("detail"):
            lines.append(f"            {e['detail']}")
    return "\n".join(lines) + "\n"


def cmd_ask(args) -> int:
    target = AwsTarget(args.outputs)
    # Call the agent Lambda directly with the same payload shape the real
    # front end would send. The customer id is the "logged in" session, which
    # the tool policy uses to decide whose accounts this person may touch.
    result = target._call(target.out["agent_function"],
                          {"message": args.message, "session": {"customer_id": args.customer}})
    # Say which stack and customer answered, because the same question can
    # behave very differently on the vulnerable and hardened stacks.
    print(f"[{target.out['mode']} stack, customer {args.customer}]")
    print(format_turn(result))
    return 0


def main(argv=None) -> int:
    # argv=None means "read the real command line". Tests can pass a list
    # instead and drive the CLI without starting a new process.
    # The module docstring (the usage examples above) doubles as the --help
    # text. RawDescriptionHelpFormatter keeps its line breaks intact.
    p = argparse.ArgumentParser(prog="innovabank_harness", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # One sub-command is required: running with no command does nothing useful.
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the attack catalog")
    # Defaults are offline + hardened: free, needs no AWS, and is the posture
    # we most want to check.
    r.add_argument("--target", choices=["offline", "aws"], default="offline")
    r.add_argument("--mode", choices=["vulnerable", "hardened"], default="hardened")
    # The "=" form matters: without it, argparse would read "-taint_lock" as
    # an unknown option instead of as the value of --controls.
    r.add_argument("--controls", help='offline only. Use the = form for removals, for example --controls=-taint_lock,-tool_policy')
    r.add_argument("--outputs", help="terraform outputs json of the stack to attack")
    r.add_argument("--only", help="comma separated attack ids")
    # A real model can answer differently each time, so live runs often use
    # several trials to catch attacks that only win sometimes.
    r.add_argument("--trials", type=_positive_int, default=1,
                   help="run each case N times and record how many trials each one won (default 1)")
    r.add_argument("--out", required=True)
    # set_defaults(fn=...) ties each sub-command to its function, so main()
    # can just call args.fn(args) without a big if/else.
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="render the before and after tables")
    rp.add_argument("--vulnerable", required=True)
    rp.add_argument("--hardened", required=True)
    rp.add_argument("--out", required=True)
    rp.add_argument("--readme", help="also update the results block in this README")
    rp.set_defaults(fn=cmd_report)

    ab = sub.add_parser("ablation", help="measure what each control is holding back")
    # Default path is anchored at the repo root, so it works from any folder.
    ab.add_argument("--out", default=str(ROOT / "docs" / "results" / "ablation.md"))
    ab.set_defaults(fn=cmd_ablation)

    sd = sub.add_parser("seed", help="seed a deployed stack")
    sd.add_argument("--outputs", required=True)
    sd.set_defaults(fn=cmd_seed)

    ak = sub.add_parser("ask", help="send one message to a deployed stack and show what happened")
    ak.add_argument("--outputs", required=True)
    # C-1001 is the default fictional customer in the seed data.
    ak.add_argument("--customer", default="C-1001")
    ak.add_argument("message")
    ak.set_defaults(fn=cmd_ask)

    args = p.parse_args(argv)
    # The return value becomes the process exit code (0 means success).
    return args.fn(args)
