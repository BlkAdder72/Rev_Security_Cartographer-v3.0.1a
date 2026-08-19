# Security Cartographer Call Protocol

## Existing-agent invocation

The existing ICM agent requests the Security Cartographer capability through its host or orchestrator.
The host—not untrusted model output—supplies protected policy, manifest, seal, and key paths.

```python
from icm_runtime_adapter import CartographerRuntime, IntegrationError

runtime = CartographerRuntime(
    policy="CONTROL/source-policy.json",
    manifest="CONTROL/approved-baseline/security-manifest.json",
    seal="CONTROL/approved-baseline/integrity-seal.json",
    key_file="CONTROL/integrity.key",
)

try:
    verified = runtime.verify(
        workspace="EXISTING_ICM",
        output_dir="CONTROL/verified-runs/run-001",
    )
except IntegrationError:
    # The host must not start or continue the agent.
    raise
```

The host supplies only:

- `verified.instructions` as the Instructions root;
- `verified.context` as the Context root; and
- `verified.memory` as the Memory root.

The mutable source ICM and pinned live sources must be unavailable during that run.

## Action invocation

When the agent proposes an effect, the host validates it against the Context action schema, inserts the
authenticated agent identity and `verified.run_id`, and calls:

```python
decision = runtime.check_action(
    verified,
    action="CONTROL/proposals/action-001.json",
    decision="CONTROL/decisions/action-001.json",
    audit="CONTROL/audit/runtime-audit.jsonl",
)

if not decision["allowed"]:
    raise RuntimeError(decision["reason"])
```

Only a restricted tool broker may execute the exact allowed effect. The agent must not hold the
integrity key, unrestricted credentials, or a direct path around the broker.

## Mandatory failure behavior

The host stops the agent or blocks the effect when verification, hash validation, identity, run binding,
approval, handoff, audit, or action authorization fails.

