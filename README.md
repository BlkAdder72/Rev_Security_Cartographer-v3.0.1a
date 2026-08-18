# Security Cartographer

**An ICM-native security module that maps how information, trust, and authority move through an AI
agent—and places deterministic limits between agent reasoning and consequential actions.**

Security Cartographer is designed to be added manually to an existing
**Instructions–Context–Memory (ICM)** agentic workflow. It maps the complete ICM, records exact approved
content, detects later changes, produces a run-specific verified ICM bundle, and checks proposed actions
against a sealed user-intent policy.

Version: **3.0.1**

## Why this exists

An agent can be influenced by more than the user's prompt. Instructions may arrive through websites,
retrieved documents, email, tool output, persistent memory, hidden HTML, encoded text, remote resources,
subagent handoffs, and generated material.

A particularly difficult attack can occur after review:

1. An ICM workflow references a legitimate website.
2. A human reviews the workflow and website.
3. The website changes later, while the local workflow remains unchanged.
4. The agent receives different content from the same previously approved address.

Security Cartographer records the exact approved bytes and verifies them before use. If local or remote
content changes, the guarded workflow closes instead of silently trusting the replacement.

## ICM security model

```text
Instructions  → verified, bounded workflow authority
Context       → facts and evidence; data only
Memory        → persistent state; data only
Action gate   → independent decision on proposed effects
```

Only verified Instructions may direct bounded workflow behavior. Context and Memory cannot promote
themselves into Instructions, create new permissions, approve tools, or expand the user's intent.

## What Security Cartographer does

- Walks and fingerprints an ICM workspace.
- Requires separate Instructions, Context, and Memory layers.
- Maps local references, external dependencies, active remote resources, cycles, and symlinks.
- Detects Context-or-Memory authority inversions.
- Identifies hidden, encoded, persistent, tool-supplied, and opaque attack surfaces.
- Pins approved remote content by exact URL, type, size, timestamp, snapshot, and SHA-256.
- Seals the policy and approved manifest with HMAC-SHA256.
- Detects changed, missing, added, redirected, expired, or tampered dependencies.
- Quarantines changed remote material.
- Produces a run-specific exact-hash ICM bundle.
- Inspects web, email, tool, retrieval, OCR, clipboard, Memory, and subagent inputs.
- Checks proposed actions against sealed intent, target, provenance, data class, effect, and count.
- Restricts tools by name, schema digest, and agent identity.
- Supports digest-bound human approvals.
- Authenticates scoped, expiring, single-use agent handoffs.
- Maintains an authenticated runtime audit chain.

## Repository structure

This repository contains only the working ICM package:

```text
instructions/
└── security-cartographer/
    ├── SKILL.md
    ├── INSTALL.md
    ├── CALL_PROTOCOL.md
    └── DEPLOYMENT_GUIDE.md

context/
└── security-cartographer/
    ├── runtime/
    │   ├── security_cartographer.py
    │   ├── icm_runtime_adapter.py
    │   └── pyproject.toml
    ├── templates/
    │   ├── source-policy.template.json
    │   ├── action-proposal.template.json
    │   └── handoff-request.template.json
    ├── references/
    │   ├── ICM_ARCHITECTURE.md
    │   └── THREAT_MODEL.md
    ├── ACTION_PROPOSAL_SCHEMA.json
    ├── ICM_MODULE_MANIFEST.json
    └── INTEGRATION_CONTRACT.md

memory/
└── security-cartographer/
    └── state.json
```

## Requirements

- Python 3.10 or later
- An existing ICM agent with `instructions/`, `context/`, and `memory/`
- Access to modify the agent's startup and tool-execution orchestration
- Protected storage outside agent control
- The ability to deny access to the mutable source ICM during a verified run
- The ability to intercept consequential tool calls before execution

## Manual deployment

### 1. Merge the ICM package

Copy the three namespaced directories into the matching layers of the existing ICM:

```text
instructions/security-cartographer/
    → EXISTING_ICM/instructions/security-cartographer/

context/security-cartographer/
    → EXISTING_ICM/context/security-cartographer/

memory/security-cartographer/
    → EXISTING_ICM/memory/security-cartographer/
```

Do not replace unrelated files in the existing ICM.

### 2. Stage and install the runtime

Copy the runtime to protected staging outside the live ICM before installation. This prevents Python
build tools from leaving generated files in Context.

#### Windows PowerShell

```powershell
Copy-Item "EXISTING_ICM\context\security-cartographer\runtime" "C:\protected\cartographer-runtime-source" -Recurse
py -3 -m venv C:\protected\cartographer-runtime
C:\protected\cartographer-runtime\Scripts\python.exe -m pip install --no-deps C:\protected\cartographer-runtime-source
C:\protected\cartographer-runtime\Scripts\security-cartographer.exe --version
```

#### macOS or Linux

```sh
cp -R EXISTING_ICM/context/security-cartographer/runtime /protected/cartographer-runtime-source
python3 -m venv /protected/cartographer-runtime
/protected/cartographer-runtime/bin/python -m pip install --no-deps /protected/cartographer-runtime-source
/protected/cartographer-runtime/bin/security-cartographer --version
```

Expected result:

```text
security-cartographer 3.0.1
```

### 3. Create protected operational storage

Create this outside the ICM:

```text
CONTROL/
├── source-policy.json
├── integrity.key
├── approved-baseline/
├── verified-runs/
├── quarantine/
├── proposals/
├── decisions/
├── approvals/
├── handoffs/
└── audit/
```

The agent must not be able to read the integrity key or modify this directory.

### 4. Customize the policy

Copy:

```text
context/security-cartographer/templates/source-policy.template.json
```

to `CONTROL/source-policy.json`. Replace every placeholder with the real agent identity, intent,
destination, source boundary, tool, and schema digest.

Keep `"icm_mode": "required"`. Begin with no remote hosts and no tools, then add only the capabilities
the workflow actually requires.

### 5. Create the key and map the combined ICM

```sh
security-cartographer init-key --key-file CONTROL/integrity.key
security-cartographer scan EXISTING_ICM --policy CONTROL/source-policy.json --output CONTROL/preflight
```

Open `CONTROL/preflight/map.html` and resolve unacceptable Critical and High findings.

The Cartographer runtime contains security-detection expressions and may identify its own source as a
risky text surface. Review the exact runtime files and hashes. Do not generalize that acceptance to other
source code.

### 6. Approve the baseline

```sh
security-cartographer approve EXISTING_ICM --policy CONTROL/source-policy.json --key-file CONTROL/integrity.key --output CONTROL/approved-baseline
```

If the reviewed Cartographer runtime is the only accepted high-risk surface, an accountable reviewer may
repeat initial approval with `--reviewed`.

Never automate `--reviewed` and never automatically create a new baseline after verification fails.

### 7. Verify before every run

```sh
security-cartographer verify EXISTING_ICM --policy CONTROL/source-policy.json --manifest CONTROL/approved-baseline/security-manifest.json --seal CONTROL/approved-baseline/integrity-seal.json --key-file CONTROL/integrity.key --output CONTROL/verified-runs/RUN-001
```

The agent must consume only:

```text
CONTROL/verified-runs/RUN-001/trusted-context/<run_id>/icm/
```

The original mutable ICM and pinned live sources must be unavailable during the run.

## Python orchestrator integration

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
        output_dir="CONTROL/verified-runs/RUN-001",
    )
except IntegrationError:
    # The host must not start or continue the agent.
    raise

# Supply only these roots to the agent:
print(verified.instructions)
print(verified.context)
print(verified.memory)
```

## Action gating

The agent emits a strict proposal conforming to
`context/security-cartographer/ACTION_PROPOSAL_SCHEMA.json`. The host supplies the authenticated agent
identity and the actual verified run ID.

```python
decision = runtime.check_action(
    verified,
    action="CONTROL/proposals/action-001.json",
    decision="CONTROL/decisions/action-001.json",
    audit="CONTROL/audit/runtime-audit.jsonl",
)

if not decision["allowed"]:
    raise RuntimeError(decision["reason"])

# Only a separate restricted broker may execute the exact allowed effect.
```

The model must not hold the integrity key, unrestricted credentials, or a direct path around the action
broker.

## Fail-closed behavior

Stop the agent or block the effect when:

- verification or delivered-file hash validation fails;
- an ICM layer is missing;
- the envelope is absent or malformed;
- local or external content changes;
- a tool or schema is unregistered;
- agent identity is unknown;
- the verified run ID is missing or mismatched;
- approval or handoff is invalid, expired, or replayed;
- audit verification fails; or
- an unguarded source, tool, credential, network, or Memory path becomes available.

## Documentation

- [Security boundary](instructions/security-cartographer/SKILL.md)
- [Quick installation](instructions/security-cartographer/INSTALL.md)
- [Complete deployment guide](instructions/security-cartographer/DEPLOYMENT_GUIDE.md)
- [Call protocol](instructions/security-cartographer/CALL_PROTOCOL.md)
- [Integration contract](context/security-cartographer/INTEGRATION_CONTRACT.md)
- [ICM architecture](context/security-cartographer/references/ICM_ARCHITECTURE.md)
- [Threat model](context/security-cartographer/references/THREAT_MODEL.md)

## What this project can fairly claim

When integrated as a mandatory boundary—and when bypass paths are removed—Security Cartographer can
materially improve the security of an existing ICM agentic workflow. It separates data from authority,
detects unauthorized content changes, supplies exact-hash runtime content, and independently restricts
consequential actions.

It does not make an agent completely secure. Production use still requires sandboxing, credential
isolation, network enforcement, workload identity, protected audit storage, format-specific parsers,
monitoring, human approval, incident response, and recovery testing.

## License

The runtime metadata declares the project under the MIT License. When publishing the repository, add
the project's `LICENSE` file at the repository root so GitHub can display and index the license.
