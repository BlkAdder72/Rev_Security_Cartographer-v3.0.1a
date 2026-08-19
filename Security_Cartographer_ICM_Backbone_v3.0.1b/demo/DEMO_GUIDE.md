# Security Cartographer 3.0.1b — Demonstration Guide

## Purpose of this guide

This guide explains how a contest judge can run the Security Cartographer demonstration, what happens
during the demonstration, where to find the results, and what those results establish.

This is the demonstration of the **ICM Backbone version** of Security Cartographer. ICM means:

- **Instructions** — the verified workflow authority;
- **Context** — reference material, retrieved information, and external evidence treated as data; and
- **Memory** — persistent state treated as data.

Only verified Instructions may direct the workflow. Context and Memory cannot create new goals, grant
permissions, approve tools, or promote themselves into Instructions.

## What problem does the demonstration recreate?

The fictional Maple Street Community Pantry has an AI-agent workflow written in Markdown. The workflow
uses information from an outside bulletin. A reviewer initially sees a harmless bulletin and approves it.

Later, a bad actor changes the bulletin at the same address. The local Markdown workflow has not changed,
but the information the agent would receive has changed. The replacement attempts to persuade the agent
to perform an unauthorized network upload.

Security Cartographer is expected to:

1. recognize that the workflow uses all three required ICM layers;
2. record and seal the exact approved local and external content;
3. create a verified, run-specific copy of Instructions, Context, and Memory;
4. detect that the outside bulletin changed after approval;
5. quarantine the changed material instead of putting it into the agent's Context; and
6. independently refuse the unauthorized action.

The demonstration also shows how the system handles hostile tool output, policy tampering, agent
handoffs, replay attempts, and audit-record integrity.

## Safety and privacy

The demonstration is synthetic and self-contained:

- It does not require an AI account or API key.
- It does not send information over the internet.
- It does not access private files outside the extracted demonstration folder.
- It does not execute the synthetic hostile instructions.
- It does not upload or delete user information.
- It uses a temporary website available only through the local computer's loopback address.
- Temporary secrets and working files are destroyed when the demonstration finishes.

Some operating systems may display a firewall notice because the demonstration temporarily starts a
local web server. It binds to `127.0.0.1`, uses a temporary port, and is not intended to accept connections
from another computer.

## Requirements

The judge needs:

- Windows, macOS, or Linux;
- Python 3.10 or later; and
- permission to create files inside the extracted demonstration folder.

No third-party Python packages are required.

## Before running the demonstration

1. Download `Security_Cartographer_ICM_Backbone_v3.0.1b.zip`.
2. Extract the ZIP into a normal folder.
3. Open the extracted `Security_Cartographer_ICM_Backbone_v3.0.1b` folder and then open `demo/`.
4. Do not try to run the launcher from inside the ZIP preview window.

Optional Python check:

### Windows

```text
py -3 --version
```

### macOS or Linux

```sh
python3 --version
```

The reported version should be Python 3.10 or later.

## Run the demonstration

### Windows — easiest method

Double-click:

```text
RUN_DEMO.bat
```

The command window remains open when the run completes so the judge can read the result.

### Windows — PowerShell method

Open PowerShell in the extracted folder and run:

```powershell
python .\run_demo.py
```

`RUN_DEMO.ps1` provides the same operation when local PowerShell script execution is permitted.

### macOS or Linux

Open a terminal in the extracted folder and run:

```sh
./run_demo.sh
```

If the file does not have execute permission, run:

```sh
sh run_demo.sh
```

The demonstration normally completes in a few seconds. It creates a new `demo_output/` directory in the
same folder.

## What happens during the demonstration

### Stage 0 — Map the wider attack terrain

The Cartographer maps a separate collection of harmless attack fixtures. These illustrate hidden HTML,
encoded instructions, persistent state, a startup setting, a tool definition, active remote content,
hostile tool output, and an opaque file.

This stage is supplemental reconnaissance. It shows the wider terrain the Cartographer can map. It is
not the guarded ICM workflow used in the remaining stages.

### Stage 1 — Validate the ICM backbone

The main pantry workflow is assembled with three distinct directories:

```text
instructions/
context/
memory/
```

The policy sets `icm_mode` to `required`. A guarded workflow missing any layer would fail closed.

### Stage 2 — Approve, fingerprint, and seal

The demo starts a temporary local website containing the harmless bulletin. Security Cartographer:

- walks the three ICM layers;
- classifies each file and its authority;
- retrieves the permitted bulletin;
- records exact SHA-256 fingerprints;
- saves an approved snapshot; and
- authenticates the policy and manifest with HMAC-SHA256.

The integrity key remains outside the agent-readable ICM workspace.

### Stage 3 — Verify and create the runtime ICM bundle

The Cartographer verifies that the workspace, policy, manifest, seal, snapshot, and live bulletin still
match. It then creates a new exact-hash runtime bundle containing:

```text
icm/
├── instructions/
├── context/
└── memory/
```

The approved outside bulletin is placed under Context as data. The resulting envelope states that only
Instructions have workflow authority and that the agent must not return to the mutable source or fetch
the website again during that run.

A narrowly permitted local report action is allowed because it matches the sealed user-intent contract.

### Stage 4 — Simulate the delayed website attack

The demonstration changes only the bulletin served by the temporary website. The Markdown workflow and
the previously approved manifest remain unchanged.

Security Cartographer retrieves the new bytes, detects that their fingerprint differs from the approved
fingerprint, places the replacement in quarantine, and marks verification as blocked. The replacement is
not promoted into a verified runtime ICM bundle.

### Stage 5 — Block the unauthorized action

The hostile fixture proposes a network upload. The independent action gate checks the proposal against
the sealed intent, approved target, data classification, provenance, side effect, and operation count.
The action is denied.

This is important because the protection does not depend solely on deciding whether text “looks
malicious.” Even persuasive content cannot grant itself a capability that the policy does not allow.

### Stage 6 — Inspect hostile tool output

The same input boundary examines a hostile instruction arriving through synthetic tool output. It is
blocked before reaching an action-capable agent.

### Stage 7 — Detect policy tampering

The demo modifies a temporary copy of the policy to remove its categorical action denials. The changed
policy no longer matches the authenticated seal, so it fails before it can expand authority.

### Stage 8 — Authenticate an agent handoff

The Cartographer signs a scoped, expiring handoff between registered synthetic agents. The first use is
accepted. Reusing the exact same handoff is rejected as a replay.

### Stage 9 — Verify the audit chain

The runtime decisions are added to an HMAC-authenticated chain. The demo verifies the retained chain so
modification, reordering, or removal within that chain would be detectable.

## Expected final message

A successful run ends with language substantially matching:

```text
RESULT: Delayed, cross-channel, action-escalation, policy-tampering,
and inter-agent attacks were contained.
```

It also prints the path to the blocked-change visual map.

## Results to inspect

### 1. Wider attack-surface map

Open:

```text
demo_output/00-attack-surface-map/map.html
```

This standalone map lets the judge inspect files, roles, links, and findings from the supplemental attack
fixtures.

### 2. Approved baseline

Inspect:

```text
demo_output/01-approved-baseline/security-manifest.json
demo_output/01-approved-baseline/integrity-seal.json
demo_output/01-approved-baseline/snapshots/
```

These files show what was approved, its exact fingerprint, the saved external snapshot, and the
authentication evidence for the policy and manifest.

### 3. Verified ICM runtime handoff

Inspect:

```text
demo_output/01-verified-context/context-envelope.json
demo_output/01-verified-context/trusted-context/<run-id>/icm/
```

The `<run-id>` directory is generated during the run. Inside `icm/`, the judge should see all three
layers: `instructions/`, `context/`, and `memory/`.

The names `01-verified-context`, `trusted-context`, and `context-envelope.json` remain for interface
compatibility. The delivered artifact is a complete ICM bundle, not a Context-only bundle.

### 4. Blocked replacement and quarantine

Open:

```text
demo_output/02-blocked-change/map.html
```

Also inspect:

```text
demo_output/02-blocked-change/findings.json
demo_output/02-blocked-change/quarantine/
demo_output/02-blocked-change/action-decision.json
```

These files show that the live source changed, the new material was quarantined, verification was
blocked, and the proposed network action was refused.

### 5. Cross-channel, handoff, and audit results

Inspect:

```text
demo_output/03-channel-inspection.json
demo_output/04-runtime-audit.jsonl
demo_output/05-agent-handoff.json
demo_output/05-handoff-decision.json
demo_output/05-handoff-replay-cache.json
```

These artifacts show the tool-output decision, authenticated action history, signed handoff, accepted
first use, and replay protection.

## Suggested five-minute judging sequence

For a fast evaluation:

1. Run the launcher and confirm that the final result says the attacks were contained.
2. Open `demo_output/02-blocked-change/map.html` and review the blocked-source finding.
3. Open `demo_output/01-verified-context/context-envelope.json` and find the `icm_backbone` section.
4. Open the generated `trusted-context/<run-id>/icm/` folder and confirm that it contains Instructions,
   Context, and Memory.
5. Inspect `demo_output/02-blocked-change/quarantine/` and `action-decision.json`.
6. Read `SUBMISSION.md` for the contest narrative and
   `../context/security-cartographer/references/ICM_ARCHITECTURE.md` for the layer contract.

## What the demonstration establishes

The demonstration provides working evidence that the prototype can:

- enforce a required ICM folder structure for guarded operations;
- distinguish verified Instructions from non-authoritative Context and Memory;
- map local and external influence paths;
- record and authenticate an approved content baseline;
- detect a later change at the same outside location;
- quarantine changed content;
- create a verified, run-specific, exact-hash ICM bundle;
- prevent changed Context from granting itself action authority;
- detect policy tampering;
- control synthetic agent handoffs and replay; and
- maintain and verify an authenticated local audit chain.

## What the demonstration does not establish

The demonstration does not prove that every prompt-injection technique can be recognized or that an
agent becomes completely secure. It is a local prototype using synthetic content and a temporary local
website.

In a real deployment, the controls must be mandatory: the agent must receive only the verified ICM
bundle, must not reopen the mutable source or refetch approved websites, and must not have a path around
the action gate. Production security also requires sandboxing, credential isolation, network controls,
protected state, workload identity, monitoring, incident response, and recovery testing.

The fair conclusion is:

> Integrating Security Cartographer as a mandatory boundary can materially improve the security of an
> existing ICM agentic workflow within the controls' defined scope.

## Running the demonstration again

The demonstration is repeatable. Running it again replaces only its own `demo_output/` directory and
recreates the temporary local website and working files. The packaged source fixtures remain unchanged.

## Troubleshooting

### “Python was not found”

Install Python 3.10 or later, then close and reopen the command window. Confirm the installation with
`py -3 --version` on Windows or `python3 --version` on macOS/Linux.

### The launcher closes immediately on Windows

Open Command Prompt in the extracted folder and run:

```text
RUN_DEMO.bat
```

This keeps any error message visible.

### PowerShell blocks the `.ps1` file

Use `RUN_DEMO.bat` or run `python .\run_demo.py`. Changing the computer's PowerShell security policy is
not required for this demonstration.

### The shell says “permission denied”

Run:

```sh
sh run_demo.sh
```

### The visual map does not open automatically

The demo intentionally prints the file location instead of launching a browser. Open the generated
`map.html` file manually with any modern browser.

### A firewall prompt appears

Allowing Python for private/local loopback use may be necessary on some systems. The demo binds only to
`127.0.0.1` and does not need public-network access. If organizational security policy prevents any local
server, run the demonstration on an approved isolated workstation.

### The output directory already exists

That is expected after the first run. The demonstration replaces its own `demo_output/` directory at the
start of the next run.
