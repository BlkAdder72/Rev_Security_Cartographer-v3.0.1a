# Deploy Security Cartographer into an Existing ICM Agent

## 1. Purpose and completion standard

This procedure installs Security Cartographer as a callable security module within an existing
Instructions–Context–Memory agent.

Copying the folders is only the first step. Deployment is complete only when:

> The host verifies the complete ICM before every run, supplies only the resulting exact-hash ICM bundle
> to the agent, treats Context and Memory as data, and prevents consequential effects unless the
> independent action boundary permits them.

If the agent can read the mutable source ICM, retrieve pinned sources again, call an unrestricted tool,
read the integrity key, modify the policy, or continue after verification failure, the deployment is
incomplete.

## 2. Package contents

The package contains only three ICM layers:

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
    ├── references/
    ├── ACTION_PROPOSAL_SCHEMA.json
    ├── ICM_MODULE_MANIFEST.json
    └── INTEGRATION_CONTRACT.md

memory/
└── security-cartographer/
    └── state.json
```

The Python runtime is distributed as Context because it is callable implementation material, not
instruction authority. The host installs and invokes it. Protected operational state is created outside
the ICM.

## 3. Roles and responsibilities

| Role | Responsibility |
| --- | --- |
| ICM owner | Approves where the module is merged and what existing content may influence the agent |
| Security reviewer | Reviews the initial map, runtime source findings, policy, and approved baseline |
| Agent integrator | Connects verification, bundle loading, ingress inspection, and action gating |
| Tool broker | Holds credentials and executes only the exact allowed effect |
| Operator | Responds to blocks, changes, key exposure, failed audit, and rollback events |
| Agent | Consumes the verified bundle and emits proposals; it does not enforce its own boundary |

One person may perform several roles in a small deployment, but the agent itself cannot be the security
reviewer, key custodian, or final action authority.

## 4. Prerequisites

Before starting, confirm:

- Python 3.10 or later is installed.
- The existing agent has top-level `instructions/`, `context/`, and `memory/` directories.
- You can change the host's startup process and tool invocation path.
- You can prevent the running agent from reading the mutable source ICM.
- You can keep keys, policies, manifests, decisions, and logs outside agent control.
- You have a staging environment without production credentials or production write access.
- You have a recoverable backup of the existing ICM.

Do not deploy directly into production before completing the acceptance tests in Section 19.

Commands below use uppercase placeholders such as `EXISTING_ICM` and `CONTROL`. Replace them with the
real absolute paths for the deployment. Do not pass the placeholder words literally.

## 5. Back up and inspect the existing ICM

Record:

- current ICM location;
- current version or commit;
- existing startup command;
- all tools and connectors;
- all network paths;
- credential locations;
- Memory read and write paths;
- human-approval points; and
- rollback procedure.

Check whether any layer already contains a `security-cartographer` directory. If it does, stop and compare
versions before merging. Do not silently overwrite an earlier installation.

## 6. Merge the three ICM layers

Copy each namespaced directory into its matching layer.

### Windows PowerShell

```powershell
$Package = "C:\path\to\Security_Cartographer_ICM_v3.0.1"
$AgentICM = "C:\path\to\existing-icm"

Copy-Item "$Package\instructions\security-cartographer" "$AgentICM\instructions\" -Recurse
Copy-Item "$Package\context\security-cartographer" "$AgentICM\context\" -Recurse
Copy-Item "$Package\memory\security-cartographer" "$AgentICM\memory\" -Recurse
```

### macOS or Linux

```sh
PACKAGE="/path/to/Security_Cartographer_ICM_v3.0.1"
AGENT_ICM="/path/to/existing-icm"

cp -R "$PACKAGE/instructions/security-cartographer" "$AGENT_ICM/instructions/"
cp -R "$PACKAGE/context/security-cartographer" "$AGENT_ICM/context/"
cp -R "$PACKAGE/memory/security-cartographer" "$AGENT_ICM/memory/"
```

Confirm these paths:

```text
EXISTING_ICM/instructions/security-cartographer/SKILL.md
EXISTING_ICM/context/security-cartographer/runtime/security_cartographer.py
EXISTING_ICM/context/security-cartographer/runtime/icm_runtime_adapter.py
EXISTING_ICM/memory/security-cartographer/state.json
```

Do not move the runtime into Instructions or Memory.

## 7. Install the callable runtime

Copy the runtime directory to protected staging outside the ICM and install from that copy. Do not build
directly from the live Context directory; Python build tools may otherwise leave generated files in the
source ICM.

### Windows PowerShell

```powershell
Copy-Item "C:\path\to\existing-icm\context\security-cartographer\runtime" "C:\protected\cartographer-runtime-source" -Recurse
py -3 -m venv C:\protected\cartographer-runtime
C:\protected\cartographer-runtime\Scripts\python.exe -m pip install --no-deps C:\protected\cartographer-runtime-source
C:\protected\cartographer-runtime\Scripts\security-cartographer.exe --version
```

### macOS or Linux

```sh
cp -R /path/to/existing-icm/context/security-cartographer/runtime /protected/cartographer-runtime-source
python3 -m venv /protected/cartographer-runtime
/protected/cartographer-runtime/bin/python -m pip install --no-deps /protected/cartographer-runtime-source
/protected/cartographer-runtime/bin/security-cartographer --version
```

Expected version:

```text
security-cartographer 3.0.1
```

The runtime has no third-party runtime dependencies. Protect the installed environment from modification
by the agent. After installation, verify that no `build/`, `*.egg-info/`, `__pycache__/`, or generated
metadata appeared in the live ICM runtime source.

## 8. Create protected operational storage

Create this structure outside the existing ICM:

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
├── handoff-replay-cache.json
└── audit/
```

Required protections:

- The agent cannot read `integrity.key`.
- The agent cannot modify any file under `CONTROL/`.
- The action broker may read only the files required for its function.
- Audit records are copied to protected append-only storage.
- Backups preserve the baseline and policy without exposing the key.

Production deployments should replace the local key file with service-backed or hardware-backed key
custody.

## 9. Customize the deny-first policy

Copy:

```text
EXISTING_ICM/context/security-cartographer/templates/source-policy.template.json
```

to:

```text
CONTROL/source-policy.json
```

Replace every placeholder. Do not deploy the template unchanged.

### Required policy decisions

| Field | Deployment decision |
| --- | --- |
| `icm_mode` | Keep `required` |
| `allowed_schemes` | Normally only `https` |
| `allowed_hosts` | Exact hosts needed for the approved task |
| `allowed_url_prefixes` | Narrow path prefixes, not broad domain permission |
| `allowed_content_types` | Only types the inspection boundary can safely handle |
| `allow_redirects` | Keep false unless an external gateway constrains redirects |
| `allow_private_networks` | Keep false outside an isolated test environment |
| `allow_nested_remote_references` | Keep false unless every nested source is separately governed |
| `allow_source_query_strings` | Keep false unless queries are independently constrained |
| `max_bytes` | Maximum bytes for one remote source |
| `max_local_bytes` | Maximum total local bytes inspected |
| `max_files` | Maximum local file count |
| `max_external_sources` | Maximum remote dependency count |
| `max_baseline_age_hours` | Maximum lifetime of an approved baseline |
| `trusted_agents` | Exact agent identities, intents, and handoff destinations |
| `allowed_tools` | Exact tool names, schema digests, and agent scopes |
| `intent_contracts` | Exact permitted purpose, action, target, data, effect, and count |
| `always_deny_action_types` | Capabilities that remain unavailable even when requested |

Begin with no remote hosts and no tools. Add each capability only after documenting why the task needs
it and what external enforcement limits it.

## 10. Create the integrity key

```sh
security-cartographer init-key --key-file CONTROL/integrity.key
```

The command refuses to overwrite an existing key. If the key may have been exposed, stop the agent,
invalidate the baseline, generate a new key through the approved key-management process, and reapprove
the policy and content.

## 11. Map the combined ICM before approval

```sh
security-cartographer scan EXISTING_ICM --policy CONTROL/source-policy.json --output CONTROL/preflight
```

Open `CONTROL/preflight/map.html` and review:

- missing ICM layers;
- files outside the three layers;
- Context or Memory paths into Instructions;
- live remote dependencies originating in Memory;
- symlink escapes;
- startup configuration;
- active remote images, scripts, forms, or frames;
- hidden or encoded content;
- opaque or over-budget files;
- sensitive paths;
- unapproved remote sources; and
- generated-output feedback cycles.

The bundled runtime source contains security-detection expressions and may be reported as a risky text
surface. That is expected only for the exact supplied runtime files. Review their exact hashes. Do not
generalize that acceptance to other source code.

## 12. Approve the initial baseline

First attempt approval without an override:

```sh
security-cartographer approve EXISTING_ICM --policy CONTROL/source-policy.json --key-file CONTROL/integrity.key --output CONTROL/approved-baseline
```

If the reviewed Cartographer runtime source is the only accepted high-risk surface, an accountable
reviewer may repeat the command once with `--reviewed`:

```sh
security-cartographer approve EXISTING_ICM --policy CONTROL/source-policy.json --key-file CONTROL/integrity.key --output CONTROL/approved-baseline --reviewed
```

Never automate `--reviewed`. Never invoke approval automatically after verification fails. A new baseline
is a new trust decision.

Reapproval is required after an authorized change to:

- any Instruction;
- eligible Context or Memory;
- the Cartographer runtime or adapter;
- a remote dependency;
- policy;
- agent registry;
- tool registry or schema;
- intent contract; or
- accepted package version.

## 13. Verify before every agent run

Use a new empty run-output directory:

```sh
security-cartographer verify EXISTING_ICM --policy CONTROL/source-policy.json --manifest CONTROL/approved-baseline/security-manifest.json --seal CONTROL/approved-baseline/integrity-seal.json --key-file CONTROL/integrity.key --output CONTROL/verified-runs/RUN-001
```

Interpret exit codes:

| Code | Meaning | Response |
| ---: | --- | --- |
| 0 | Verified | Continue with only the generated bundle |
| 2 | Dependency or input blocked | Stop and investigate |
| 3 | Action denied | Do not execute the effect |
| 4 | Policy, seal, retrieval, configuration, or approval failure | Stop and repair |
| 130 | Interrupted | Treat the run as incomplete |

On success, read `context-envelope.json` and require:

- `status` equals `verified`;
- `icm_backbone.mode` equals `required`;
- Instructions, Context, and Memory are all present;
- every entry has a layer and hash; and
- the run ID is present.

The only agent-readable runtime root is:

```text
CONTROL/verified-runs/RUN-001/trusted-context/<run_id>/icm/
```

Mount it read-only or use a content-addressed protected store.

## 14. Wire the Python integration adapter

The existing host invokes:

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
except IntegrationError as error:
    stop_agent_startup(error)

start_agent(
    instructions_root=verified.instructions,
    context_root=verified.context,
    memory_root=verified.memory,
    source_workspace_access=False,
    direct_network_access=False,
    unrestricted_tool_access=False,
)
```

`stop_agent_startup` and `start_agent` are placeholders for the existing orchestration platform. The
integrator must implement equivalent behavior.

Do not parse terminal prose for success. Use process exit codes, the JSON envelope, and adapter results.

## 15. Route material arriving after startup

Post-start material must not enter Instructions directly.

For example:

```sh
security-cartographer inspect-input --channel tool --input TOOL_RESULT.txt --output CONTROL/inspected/tool-result.json
```

Supported channels:

```text
web, email, tool, memory, subagent, retrieval, ocr, clipboard
```

An exit code of 2 means the material is blocked. Quarantine it and keep it away from the action-capable
agent.

A passing inspection means the material may enter Context—or Memory when it is genuine persistent
state. It does not gain instruction authority.

Production adapters must also validate sender, tenant, object authorization, content type, size, schema,
provenance, and data-loss constraints. Opaque formats require isolated format-specific parsing.

## 16. Gate consequential actions

The agent creates a strict proposal conforming to
`context/security-cartographer/ACTION_PROPOSAL_SCHEMA.json`.

The host supplies trusted identity and the actual `verified.run_id`. It must not trust the model to prove
its own identity or approval.

```python
decision = runtime.check_action(
    verified,
    action="CONTROL/proposals/action-001.json",
    decision="CONTROL/decisions/action-001.json",
    audit="CONTROL/audit/runtime-audit.jsonl",
)

if not decision["allowed"]:
    block_effect(decision["reason"])
else:
    restricted_tool_broker.execute_exact_decision(decision)
```

The broker must:

- compare the requested effect with the allowed decision;
- execute exactly the allowed type, target, side effect, and count;
- expose only the credential and object scope required for that effect;
- refuse any changed or additional operation;
- return output as untrusted Context; and
- record actual execution success or failure.

An allowed decision is not permission to execute arbitrary model-generated code.

## 17. Human approvals, tools, and handoffs

### Human approval

Prepare the final action first:

```sh
security-cartographer issue-approval --action CONTROL/proposals/action-001.json --key-file CONTROL/integrity.key --approved-by REVIEWER_ID --ttl-seconds 300 --output CONTROL/approvals/action-001.json
```

Insert the returned approval object into the unchanged action and resubmit it. Any action change invalidates
the approval. Production approval must sit behind separately authenticated human interaction.

### Registered tools

For every callable tool:

- register the exact name;
- record the exact schema SHA-256;
- identify permitted agents;
- constrain mode and side effects; and
- reapprove after any schema or capability change.

### Agent handoffs

```sh
security-cartographer seal-handoff --request CONTROL/handoffs/request-001.json --policy CONTROL/source-policy.json --manifest CONTROL/approved-baseline/security-manifest.json --seal CONTROL/approved-baseline/integrity-seal.json --key-file CONTROL/integrity.key --ttl-seconds 300 --output CONTROL/handoffs/sealed-001.json
```

```sh
security-cartographer check-handoff --handoff CONTROL/handoffs/sealed-001.json --replay-cache CONTROL/handoff-replay-cache.json --policy CONTROL/source-policy.json --manifest CONTROL/approved-baseline/security-manifest.json --seal CONTROL/approved-baseline/integrity-seal.json --key-file CONTROL/integrity.key --decision CONTROL/decisions/handoff-001.json
```

Keep replay state outside agent control. A valid handoff transfers bounded facts and task scope, not new
Instruction authority.

## 18. Audit, failure response, and recovery

Verify the authenticated audit chain:

```sh
security-cartographer verify-audit --audit CONTROL/audit/runtime-audit.jsonl --key-file CONTROL/integrity.key
```

Stop the agent and block effects when:

- verification or hash validation fails;
- the envelope is absent or malformed;
- a layer is missing;
- a source changes;
- a tool or schema is unregistered;
- agent identity is unknown;
- run ID is absent or mismatched;
- approval or handoff is invalid, expired, or replayed;
- audit verification fails;
- the key or protected state may be exposed; or
- any bypass path is discovered.

Response sequence:

1. stop new agent runs and tool execution;
2. preserve the failed run, findings, quarantine, decisions, and audit;
3. isolate suspected credentials and affected systems;
4. determine whether the change was authorized;
5. repair the source or policy through normal change control;
6. rotate exposed secrets or keys;
7. create a new accountable baseline only after review;
8. rerun all acceptance tests; and
9. document the incident and recovery.

Do not turn a failed verification into automatic approval.

## 19. Deployment acceptance checklist

The deployment owner must demonstrate:

- [ ] The three Cartographer namespaces are present in the matching ICM layers.
- [ ] The callable runtime installs and reports version 3.0.1.
- [ ] A clean combined ICM can be approved and verified.
- [ ] The agent receives only the generated verified bundle.
- [ ] The verified bundle contains Instructions, Context, and Memory.
- [ ] The agent cannot read the mutable source ICM.
- [ ] The agent cannot retrieve a pinned remote source directly.
- [ ] A changed Instruction blocks verification.
- [ ] A changed Context or Memory file blocks verification.
- [ ] A changed external source is quarantined.
- [ ] Context or Memory attempting to import Instructions creates a Critical finding.
- [ ] Memory attempting to create a live external dependency is rejected.
- [ ] An unregistered tool is denied.
- [ ] A changed tool schema is denied.
- [ ] An unknown agent identity is denied.
- [ ] An action outside the intent, target, data class, side effect, or count is denied.
- [ ] A mismatched verified run ID is denied.
- [ ] A changed action cannot reuse an earlier human approval.
- [ ] A handoff replay is denied.
- [ ] Audit tampering is detected.
- [ ] Removing or failing Cartographer stops the workflow rather than bypassing it.

Do not describe the integration as enforced until all applicable bypass tests pass.

## 20. Upgrade, rollback, and removal

### Upgrade

1. stop agent runs;
2. back up the current three Cartographer namespaces and protected state;
3. verify the new package checksum and version;
4. compare the new Instructions, runtime, schemas, and templates;
5. merge the new version;
6. reinstall the runtime into a new protected environment;
7. review the new map and findings;
8. create a new baseline;
9. run the full acceptance checklist; and
10. switch orchestration only after success.

### Rollback

Rollback must restore a previously reviewed package, policy, runtime environment, and compatible baseline
as one unit. Restoring only some of those parts may create policy or schema drift. Because a local HMAC
does not prevent rollback to an older valid baseline, production deployment needs protected monotonic
version state or an external append-only ledger.

### Removal

1. stop the agent;
2. remove Cartographer calls from startup and the tool broker;
3. remove the three namespaced `security-cartographer` directories;
4. revoke or archive related credentials and protected state under retention policy; and
5. do not restart the agent with consequential tools unless a replacement security boundary is active.

## 21. Production controls that remain necessary

Security Cartographer is a defense-in-depth component. Production use also requires:

- operating-system or container isolation;
- read-only or content-addressed runtime storage;
- enforcing outbound network controls;
- workload identity and short-lived credentials;
- tenant- and object-level authorization;
- isolated parsers for opaque and multimodal content;
- centralized append-only audit and protected version state;
- rate limits and anomaly detection;
- authenticated human approval;
- incident response and emergency disablement; and
- backup, rollback, and recovery testing.
