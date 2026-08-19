# Security Cartographer 3.0.1b — ICM Judges' Demo

Security Cartographer is a folder-based trust mapper and deterministic security gate for AI-agent
workflows. This optional folder contains only the files needed to understand and run the safe
demonstration. The working engine remains in the adjacent deployable ICM module.

The demonstration uses **Instructions–Context–Memory (ICM) as its required backbone**. It is not the
earlier generic folder-mapping version of the project.

## Start here

For the simplest complete instructions—including how to delete the demo—read
[`../START_HERE.md`](../START_HERE.md). For a detailed judge walkthrough, continue with this README and
[`DEMO_GUIDE.md`](DEMO_GUIDE.md). The short instructions below are enough to start the demonstration
right away.

Requirements:

- Python 3.10 or later
- No third-party Python packages
- No AI account, API key, or internet connection

### Windows

Double-click:

```text
RUN_DEMO.bat
```

You may instead run `RUN_DEMO.ps1` from PowerShell.

### macOS or Linux

From this folder, run:

```sh
./run_demo.sh
```

If the script is not executable, run:

```sh
sh run_demo.sh
```

The demonstration normally completes in a few seconds and creates a new `demo_output/` folder.

## What the demonstration proves

At startup, the console prints the exact runtime path and version. The demonstration imports the engine
from `../context/security-cartographer/runtime/security_cartographer.py`; there is no duplicate engine
inside `demo/`.

The fictional Maple Street Community Pantry has an agent workflow with three required layers:

```text
instructions/   Approved workflow authority
context/        Reference material and retrieved evidence as data
memory/         Persistent state as data
```

The workflow points to a harmless bulletin served by a temporary website on the judge's own computer.
The demo approves the exact bulletin, seals its fingerprint, verifies all three ICM layers, and creates
a run-specific exact-hash ICM bundle.

The demo then changes only the website bulletin. The local Markdown workflow remains unchanged. Security
Cartographer detects the changed bytes, quarantines the replacement, refuses to create a trusted ICM
bundle from it, and independently blocks the requested network-upload action.

The demo also maps additional synthetic attack surfaces, blocks hostile tool output, detects an attempted
policy modification, authenticates one scoped agent handoff, rejects reuse of that handoff, and verifies
the runtime audit chain.

No hostile instruction is executed. Nothing is uploaded, deleted, or transmitted over the internet.

## Where to look after the run

1. Open `demo_output/00-attack-surface-map/map.html` to explore the wider attack-surface map.
2. Inspect `demo_output/01-verified-context/context-envelope.json` to see the verified ICM handoff.
3. Open `demo_output/02-blocked-change/map.html` to see why the delayed website change was blocked.
4. Inspect `demo_output/02-blocked-change/quarantine/` to see the rejected replacement.
5. Inspect `demo_output/05-agent-handoff.json` and `demo_output/05-handoff-decision.json` to see the
   identity-bound handoff.
6. Inspect `demo_output/04-runtime-audit.jsonl` to see the authenticated action-decision chain.

The `trusted-context/` directory name and `context-envelope.json` filename are retained for interface
compatibility. The verified artifact is a complete ICM bundle containing Instructions, Context, and
Memory—not Context alone.

## ICM protections visible in the demo

| ICM control | Demonstrated behavior |
| --- | --- |
| Required layers | Guarded approval and verification fail closed unless Instructions, Context, and Memory exist |
| Authority separation | Only verified Instructions may direct the workflow; Context and Memory remain data |
| Exact-byte verification | Every eligible ICM file and approved outside source receives a SHA-256 fingerprint |
| Verified runtime delivery | The agent would receive only a new exact-hash copy of the approved ICM layers |
| Remote-content pinning | The exact approved website response is snapshotted and sealed |
| Change containment | A later website replacement is detected and quarantined before entering Context |
| Action control | A separate gate allows a narrow local report but blocks a network upload |
| Policy integrity | An attempted policy change fails authentication |
| Delegation control | A signed, scoped handoff is accepted once and its replay is blocked |
| Audit integrity | Action decisions are stored in an authenticated chain |

## Files included

```text
README.md                 Judge instructions and demonstration guide
DEMO_GUIDE.md             Complete step-by-step walkthrough and interpretation guide
SUBMISSION.md             Contest explanation and evaluation narrative
RUN_DEMO.bat              Windows one-click launcher
RUN_DEMO.ps1              PowerShell launcher
run_demo.sh               macOS/Linux launcher
run_demo.py               Safe local demonstration orchestrator
demo_workspace/           Synthetic ICM workspace and harmless attack fixtures
```

The deployable runtime used by the demonstration is located at
`../context/security-cartographer/runtime/`. All generated output remains under `demo_output/`, so the
entire demonstration and its results can be removed by deleting `demo/`.

## How this answers the challenge

The Cartographer walks a body of work and leaves three useful maps:

- `map.html` — a standalone visual map a later reader can search and wander;
- `SECURITY_MAP.md` — a durable plain-language field guide; and
- `map.json` — a machine-readable trust graph.

The map records more than file location. It shows what can influence the agent, which ICM layer contains
each item, where external content enters, what was approved, what changed, and why the gate allowed or
blocked the workflow.

## Security claim and limits

When integrated as a mandatory boundary with bypass paths removed, Security Cartographer can materially
improve the security of an existing ICM agentic workflow. It separates data from authority, detects
unauthorized content changes, supplies verified runtime material, and places deterministic limits on
consequential actions.

This demonstration is a contest prototype, not a claim of complete agent security. Production use still
requires sandboxing, credential isolation, network enforcement, workload identity, protected audit
storage, format-specific parsers, monitoring, incident response, and recovery testing.

For the contest narrative, read `SUBMISSION.md`. For the exact ICM contract, read
[`../context/security-cartographer/references/ICM_ARCHITECTURE.md`](../context/security-cartographer/references/ICM_ARCHITECTURE.md).
