#!/usr/bin/env python3
"""Safe, local demonstration of a delayed indirect prompt-injection attack."""

from __future__ import annotations

import argparse
import contextlib
import functools
import http.server
import json
import secrets
import shutil
import socketserver
import sys
import tempfile
import threading
from pathlib import Path


PROJECT = Path(__file__).resolve().parent
PACKAGE_ROOT = PROJECT.parent
MODULE_RUNTIME = PACKAGE_ROOT / "context" / "security-cartographer" / "runtime"
MODULE_ENTRYPOINT = MODULE_RUNTIME / "security_cartographer.py"

if not MODULE_ENTRYPOINT.is_file():
    raise RuntimeError(
        "The deployable ICM Backbone runtime was not found at "
        f"{MODULE_ENTRYPOINT}. Keep demo/ beside instructions/, context/, and memory/."
    )

# Import the engine from the deployable ICM module. The demo deliberately does
# not contain a second copy of security_cartographer.py. Disable bytecode
# output so running the optional demo does not add __pycache__ to Context.
sys.dont_write_bytecode = True
sys.path.insert(0, str(MODULE_RUNTIME))

from security_cartographer import (
    GuardFailure,
    VERSION,
    append_audit_event,
    approve_sources,
    check_action,
    check_handoff,
    inspect_untrusted_input,
    render_outputs,
    scan_project,
    seal_handoff,
    verify_audit_log,
    verify_sources,
    write_json,
)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002, ANN001
        return


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


@contextlib.contextmanager
def local_site(directory: Path):
    handler = functools.partial(QuietHandler, directory=str(directory))
    with ReusableTCPServer(("127.0.0.1", 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=2)


def prepare_context(destination: Path, port: int) -> tuple[Path, Path]:
    source = PROJECT / "demo_workspace"
    context = destination / "community_pantry"
    shutil.copytree(source, context)
    # The two bulletin files are demonstration controls, not part of the pantry's
    # agent-readable working folder. The live copy is served separately.
    shutil.rmtree(context / "remote_site")
    shutil.rmtree(context / "attack_lab")
    shutil.move(str(context / "actions"), str(destination / "actions"))
    # Sensitive context is deliberately excluded from the agent's exact-hash
    # runtime bundle because this workflow does not need it.
    shutil.rmtree(context / "context" / "private")
    workflow = context / "instructions" / "daily-brief.md"
    workflow.write_text(workflow.read_text(encoding="utf-8").replace("{{PORT}}", str(port)), encoding="utf-8")

    policy_inside_context = context / "source-policy.yaml"
    policy_data = json.loads(policy_inside_context.read_text(encoding="utf-8"))
    policy_data["allowed_hosts"] = ["127.0.0.1"]
    policy_data["allowed_url_prefixes"] = [f"http://127.0.0.1:{port}/bulletin.md"]
    policy_data["allow_private_networks"] = True
    policy = destination / "source-policy.yaml"
    policy.write_text(json.dumps(policy_data, indent=2) + "\n", encoding="utf-8")
    policy_inside_context.unlink()
    return context, policy


def run(output: Path) -> int:
    output = output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    print("\nSECURITY CARTOGRAPHER — SAFE LOCAL DEMONSTRATION")
    print("No information leaves this computer. The 'outside website' is a temporary local web server.\n")
    print(f"ICM Backbone runtime: {MODULE_ENTRYPOINT}")
    print(f"Security Cartographer version: {VERSION}")
    print("The demo contains no duplicate engine; it is running the deployable module above.\n")

    with tempfile.TemporaryDirectory(prefix="security-cartographer-demo-") as temp_name:
        temp = Path(temp_name)
        served = temp / "served_site"
        served.mkdir()
        clean = (PROJECT / "demo_workspace" / "remote_site" / "bulletin-clean.md").read_text(encoding="utf-8")
        hostile = (PROJECT / "demo_workspace" / "remote_site" / "bulletin-hostile.md").read_text(encoding="utf-8")
        live = served / "bulletin.md"
        live.write_text(clean, encoding="utf-8")

        with local_site(served) as port:
            context, policy = prepare_context(temp, port)
            key = temp / "integrity.key"
            key.write_bytes(secrets.token_bytes(32))
            baseline_output = output / "01-approved-baseline"
            verified_output = output / "01-verified-context"
            blocked_output = output / "02-blocked-change"
            channel_output = output / "03-channel-inspection.json"
            audit_output = output / "04-runtime-audit.jsonl"

            attack_scan = scan_project(PROJECT / "demo_workspace" / "attack_lab")
            render_outputs(attack_scan, output / "00-attack-surface-map", findings={
                "status": "mapped-with-findings",
                "generated_at": "demonstration",
                "items": attack_scan["findings"],
            })
            print("0. The wider map identifies pre-trust startup hooks, persistent memory, hidden text,")
            print("   active remote links, encoded instructions, tool definitions, and opaque files.\n")

            print("1. The cartographer validates the pantry's Instructions–Context–Memory backbone.")
            print("   Only Instructions may direct behavior; Context and Memory remain data.\n")
            print("2. It walks all three ICM layers, retrieves the approved bulletin, and freezes exact fingerprints.")
            manifest = approve_sources(context, baseline_output, policy, key)
            print(f"   APPROVED — {len(manifest['sources'])} outside source; exact bytes saved.\n")
            print("   SEALED — the policy and baseline are protected by an integrity key kept outside the folder.\n")
            clean_check = verify_sources(
                context, verified_output, policy, baseline_output / "security-manifest.json",
                baseline_output / "integrity-seal.json", key,
            )
            if clean_check["status"] != "verified":
                raise RuntimeError("Demo failed: unchanged content did not verify")
            safe_decision = check_action(
                temp / "actions" / "safe-action.json", policy, baseline_output / "security-manifest.json",
                baseline_output / "integrity-seal.json", key, verified_output / "context-envelope.json",
            )
            if not safe_decision["allowed"]:
                raise RuntimeError("Demo failed: the intent-bound report action was not allowed")
            write_json(verified_output / "action-decision.json", safe_decision)
            append_audit_event(audit_output, {"kind": "action-decision", "decision": safe_decision}, key.read_bytes())
            print("   ICM BUNDLE — the agent receives run-specific exact-hash Instructions, Context, and Memory copies,")
            print("   including the bulletin as Context, with no permission to fetch the site again.")
            print("   ALLOWED — one public report write matches the sealed user-intent contract.\n")

            print("3. Time passes. The Markdown workflow does not change.")
            print("4. A bad actor changes only the information served by the outside website.")
            live.write_text(hostile, encoding="utf-8")
            findings = verify_sources(
                context, blocked_output, policy, baseline_output / "security-manifest.json",
                baseline_output / "integrity-seal.json", key,
            )
            if findings["status"] != "blocked":
                raise RuntimeError("Demo failed: changed content was not blocked")
            print("   BLOCKED — the live bytes no longer match the approved fingerprint.")
            print("   The replacement was quarantined before it could enter the ICM Context layer.\n")

            hostile_action = temp / "actions" / "hostile-action.json"
            decision = check_action(
                hostile_action, policy, baseline_output / "security-manifest.json",
                baseline_output / "integrity-seal.json", key, blocked_output / "context-envelope.json",
            )
            write_json(blocked_output / "action-decision.json", decision)
            append_audit_event(audit_output, {"kind": "action-decision", "decision": decision}, key.read_bytes())
            if decision["allowed"]:
                raise RuntimeError("Demo failed: hostile action was unexpectedly allowed")
            print("5. The independent action gate also refuses the requested network upload.")
            print(f"   BLOCKED — {decision['reason']}\n")

            tool_result = inspect_untrusted_input(
                PROJECT / "demo_workspace" / "attack_lab" / "tool-output.txt", "tool", channel_output,
            )
            if tool_result["status"] != "blocked":
                raise RuntimeError("Demo failed: hostile tool output was not blocked")
            print("6. The same inspection boundary blocks hostile tool output before it reaches an action-capable agent.\n")

            tampered_policy = temp / "tampered-policy.yaml"
            tampered = json.loads(policy.read_text(encoding="utf-8"))
            tampered["always_deny_action_types"] = []
            tampered_policy.write_text(json.dumps(tampered), encoding="utf-8")
            try:
                check_action(
                    hostile_action, tampered_policy, baseline_output / "security-manifest.json",
                    baseline_output / "integrity-seal.json", key, blocked_output / "context-envelope.json",
                )
            except GuardFailure:
                print("7. A forged policy fails the integrity seal before it can grant additional authority.\n")
            else:
                raise RuntimeError("Demo failed: policy tampering was not detected")

            handoff = output / "05-agent-handoff.json"
            handoff_decision = output / "05-handoff-decision.json"
            replay_cache = output / "05-handoff-replay-cache.json"
            seal_handoff(
                temp / "actions" / "handoff-request.json", handoff, policy,
                baseline_output / "security-manifest.json", baseline_output / "integrity-seal.json", key,
            )
            accepted = check_handoff(
                handoff, replay_cache, policy, baseline_output / "security-manifest.json",
                baseline_output / "integrity-seal.json", key,
            )
            write_json(handoff_decision, accepted)
            try:
                check_handoff(
                    handoff, replay_cache, policy, baseline_output / "security-manifest.json",
                    baseline_output / "integrity-seal.json", key,
                )
            except GuardFailure:
                print("8. Agent-to-agent delegation is identity-bound, scoped, expiring, and single-use; replay is blocked.\n")
            else:
                raise RuntimeError("Demo failed: replayed handoff was accepted")

            audit_count = verify_audit_log(audit_output, key.read_bytes())
            print(f"9. The authenticated runtime audit chain verifies {audit_count} action decisions without tampering.\n")

    print("RESULT: Delayed, cross-channel, action-escalation, policy-tampering, and inter-agent attacks were contained.")
    print(f"Open the walkable map: {output / '02-blocked-change' / 'map.html'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT / "demo_output")
    args = parser.parse_args()
    return run(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
