# Contest Entry: Security Cartographer 3.0.1b — ICM Backbone

## Entry statement

Most maps tell you where things are. Security Cartographer tells you where trust goes, where hostile
instructions can enter, and where authority must stop.

It walks a folder-based body of work and maps the files, local references, websites, persistent memory,
tool definitions, opaque materials, active rendering paths, and action boundaries that can steer an AI
agent. It then leaves three complementary maps:

1. A standalone visual map a later reader can wander.
2. A Markdown field guide that remains readable without special software.
3. A machine-readable trust graph that can enforce a closed gate.

Security Cartographer uses **Instructions–Context–Memory (ICM) as its required backbone**, not as an
optional folder convention. Instructions define the authorized task. Context supplies current evidence.
Memory supplies persistent state. Only sealed and verified Instructions may direct behavior; Context and
Memory remain data and cannot promote themselves into authority.

### The security claim

When integrated as a mandatory control layer in an existing agentic workflow, Security Cartographer's
ICM architecture can **materially improve security**. It does so by controlling where information enters,
distinguishing data from authority, freezing the exact content supplied to the agent, and placing a
deterministic authorization gate between the agent's reasoning and consequential actions.

This reduces both the likelihood and potential impact of prompt-injection, memory-poisoning,
tool-manipulation, and trust-escalation attacks within the controls' stated scope. The claim depends on
real enforcement: the agent must consume the verified ICM bundle, consequential actions must pass through
the action gate, and alternate routes to tools, credentials, networks, or the mutable source workspace
must be removed.

The project does **not** claim to make any agent completely secure. It is one testable layer in a
defense-in-depth deployment that should also include sandboxing, credential isolation, network controls,
enterprise identity, monitoring, and incident response.

## The terrain

The motivating attack is quiet. A Markdown workflow points to a currently harmless website. A human
reviews both. Later, the Markdown is unchanged but the website serves different instructions. The folder
appears identical while the agent receives a different workflow.

The threat analysis widens the terrain. Injection may also arrive through email, tool results, subagent
handoffs, retrieved documents, OCR, persistent memory, hidden HTML, encoded text, remote images, symlinks,
generated output, connector descriptions, pre-trust startup hooks, and opaque files. It may then flow into a dangerous sink such
as a network transmission, code execution, deletion, permission change, credential read, or persistent
state modification.

Security Cartographer therefore maps sources, paths, trust levels, and sinks—not merely filenames.

## What the cartographer does

### Walk

It inventories regular files and symbolic links, applies size and file-count budgets, assigns each
agent-readable file to an ICM layer, classifies secondary roles such as tool definitions, sensitive
material, generated output, and opaque formats, and records an exact SHA-256 fingerprint for each file.

Before walking, it validates the required ICM layout. A missing layer fails closed. Each file is assigned
to Instructions, Context, Memory, or outside the ICM boundary. A Context-or-Memory link back into
Instructions is treated as a Critical authority inversion.

### Reveal

It finds local links, broken links, remote references, active images/scripts/forms, embedded data,
dependency cycles, and filesystem links. It examines raw and safely decoded representations for hidden or
encoded instruction-like content, including Unicode controls and invisible HTML/CSS.

### Freeze and seal

For each explicitly permitted remote source, it records the exact URL path, final location, content type,
size, timestamp, snapshot, and SHA-256 fingerprint. It then seals the canonical policy and manifest with
HMAC-SHA256 using a key that remains outside the mapped folder and output.

### Return and compare

Immediately before use, it verifies the seal, baseline age, local folder state, saved snapshots, and live
remote bytes. New, missing, changed, redirected, mistyped, expired, or tampered dependencies close the
gate.

### Quarantine and materialize

Changed bytes go to quarantine. When all approved local and remote content still matches, the
cartographer creates a run-specific, exact-hash ICM bundle containing eligible Instructions, Context,
and Memory. Approved remote snapshots are placed under `icm/context/external/` and remain data-only.

The on-disk container is named `trusted-context/` and its manifest is named `context-envelope.json` for
interface compatibility. Those names do not mean that the bundle contains only Context. The envelope
enumerates all three ICM layers, preserves sealed Instruction authority, labels Context and Memory as
non-authoritative data, and tells the workflow not to return to mutable source files or refetch websites.

This closes an important time-of-check/time-of-use gap when the integration gives the agent only this
verified ICM bundle and prevents it from reopening the mutable workspace or fetching the website again.

### Bind actions to intent

A separate deterministic gate checks the proposed action against a sealed user-intent contract. The
action must match the permitted purpose, operation type, relative target, data classification, provenance,
side-effect class, count, and any required human approval. The example policy categorically denies code
execution, network upload, deletion, permission changes, credential access, memory modification, and tool
installation.

### Contain identity, tools, and delegation

The action gate reads only a strict schema and sealed policy—not the agent's persuasive explanation or
the hostile tool output that may have influenced it. Agent identities come from a sealed registry. Tools
must match an approved name, schema fingerprint, and agent scope. Inter-agent handoffs are signed,
intent-bound, payload-bound, expiring, and single-use. Required human approvals are cryptographically
bound to one exact action instead of being represented by a forgeable Boolean.

Every action decision can enter an HMAC-authenticated hash chain, making modification, reordering, or
removal inside the retained chain detectable in the local prototype.

## Demonstration

The fictional Maple Street Community Pantry uses a Markdown workflow, a local volunteer guide, and a
public operations bulletin. Everything is synthetic and contains no private or proprietary information.

The one-click demonstration:

1. Maps a separate attack laboratory containing hidden HTML, encoded instructions, persistent memory, a
   startup hook, tool definition, an active remote image, hostile tool output, and an opaque document.
2. Approves the pantry's harmless local bulletin and seals the policy and baseline.
3. Verifies the unchanged content and produces a run-specific exact-hash ICM bundle.
4. Allows one public report write that exactly matches the sealed user intent.
5. Changes only the pretend website while leaving the Markdown workflow untouched.
6. Detects the changed fingerprint, quarantines the replacement, and creates no ICM runtime bundle.
7. Refuses the replacement's proposed network upload.
8. Blocks the same malicious instructions when they arrive through tool output.
9. Detects an attempted policy modification before it can expand authority.
10. Accepts one authenticated agent handoff and blocks a replay of the same handoff.
11. Verifies a tamper-evident runtime audit chain.

The temporary website is bound to the local computer. No hostile instruction is executed, and nothing is
sent to the internet.

## What is functional

This is working software, not a mockup. It performs folder traversal, role classification, link extraction,
content normalization and inspection, resource budgeting, remote-source validation, exact-byte snapshots,
HMAC sealing, change verification, quarantine, ICM runtime-bundle materialization, cross-channel inspection,
intent-bound action decisions, machine-readable findings, Markdown reporting, and standalone interactive
HTML generation using only Python's standard library. Version 3.0.1b makes ICM the required content
backbone and delivers a verified, exact-hash copy of all eligible Instructions, Context, and Memory files.
It also retains pre-trust configuration
detection, query-string egress rejection, registered tool fingerprints, sealed agent identity paths,
single-use handoffs, digest-bound approvals, and authenticated audit chaining.

The included judge-facing demonstration directly exercises the central ICM, change-detection, action-gate,
handoff, policy-integrity, and audit-chain controls.

## Why the map matters

A later reader can answer:

- What can steer this agent?
- Which sources are persistent?
- Which paths can silently make network requests?
- Which materials were inspected and which remain opaque?
- What exact bytes were approved?
- Is the policy itself authentic?
- What changed?
- What was quarantined?
- What data may reach which action?
- Why did the gate allow or block the workflow?

The original author does not need to be present. The map preserves the chain of trust and the reasons for
each boundary.

For an existing agentic workflow, the practical value is direct: Instructions gain a controlled home;
web, email, retrieval, and tool returns remain data-only Context; persistent state remains data-only
Memory; and a proposed action cannot inherit authority merely because persuasive content requested it.
The included demonstration makes those principles observable: it constructs an ICM workspace, approves
and verifies it, creates the exact-hash runtime handoff, changes only an outside source, and shows the
resulting quarantine and blocked action.

## Honest boundary

Security Cartographer does not claim to solve prompt injection by perfectly recognizing malicious prose.
Modern attacks may resemble ordinary social engineering. Its core strategy is therefore structural:
separate data from authority, minimize reachable capabilities, seal the rules, remove second live fetches,
bind actions to user intent, and fail closed when evidence changes.

Opaque formats are flagged, not silently declared safe. HMAC does not prevent rollback to an older valid
seal without protected external version state. A production deployment still requires sandboxing,
credential isolation, network enforcement, audit retention, identity controls, and human approval for
consequential actions.

## How to judge it

1. Run `RUN_DEMO.bat` on Windows or `./run_demo.sh` on macOS/Linux.
2. Open `demo_output/00-attack-surface-map/map.html` to wander the wider attack terrain.
3. Inspect `demo_output/01-verified-context/context-envelope.json` to see the complete ICM runtime handoff.
4. Open `demo_output/02-blocked-change/map.html` to see the delayed attack contained.
5. Inspect `demo_output/05-agent-handoff.json` and `demo_output/04-runtime-audit.jsonl`.
6. Open `../context/security-cartographer/references/ICM_ARCHITECTURE.md` and inspect the three layers
   inside the verified runtime bundle.
7. Read `README.md` for the short judge guide and the module's `ICM_ARCHITECTURE.md` for the enforced
   layer contract.

Security Cartographer maps not only where information lives, but how trust moves—and ensures that trust
cannot silently expand merely because an agent encountered persuasive text.

> **Judge-ready conclusion:** Integrating this ICM-based Cartographer as a mandatory boundary can
> materially improve the security of an existing agentic workflow. It provides enforceable separation of
> data and authority, verified runtime content, and deterministic limits on agent actions, while remaining
> one component of a broader defense-in-depth architecture.
