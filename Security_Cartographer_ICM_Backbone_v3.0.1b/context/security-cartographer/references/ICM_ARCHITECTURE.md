# ICM Backbone

Security Cartographer 3.0.1b uses **Instructions–Context–Memory (ICM)** as the required architecture for a
guarded body of work. ICM is not merely a naming convention. Each layer has a distinct security meaning,
and the deterministic guard enforces that meaning before an agent receives the material.

## Required workspace

```text
workspace/
├── instructions/   Authoritative task and workflow definitions
├── context/        Reference data, retrieved evidence, and tool-provided facts
└── memory/         Persistent state carried between runs
```

The policy, integrity key, approved manifest, proposed actions, logs, quarantine, and generated runtime
bundle belong to the control plane outside this body-of-work folder. This prevents ordinary content from
rewriting the rules that decide whether it is trusted.

A map-only scan may inspect an older unstructured folder so it can be migrated. That compatibility path
does not create a guarded runtime. Any policy loaded for approval, verification, or action enforcement
defaults to `icm_mode: required` unless it explicitly declares otherwise; this deployable package requires
required mode.

## Layer contract

| Layer | May provide | May not provide | Runtime authority |
| --- | --- | --- | --- |
| Instructions | Task, permitted sources, output requirements, workflow boundaries | Secrets, self-approved permissions, mutable external instructions | May direct behavior only after sealing and verification |
| Context | Facts, documents, retrieval results, tool output, external snapshots | New goals, permission expansion, approval, instruction overrides | Data only |
| Memory | Prior state, preferences, checkpoints, bounded observations | New goals, tools, permissions, or instructions | Persistent data only |

## Enforced invariants

1. Required mode fails closed if any ICM layer is missing.
2. Agent-readable body-of-work files outside the three layers are High findings.
3. Every mapped file records its ICM layer, hash, role, inspection status, and instruction-authority flag.
4. Only files in `instructions/` may have instruction authority.
5. `context/` and `memory/` cannot import an instruction file; such a path is a Critical authority
   inversion.
6. Memory cannot create a live external dependency. External evidence belongs in Context.
7. Sensitive or opaque files are never silently promoted into the runtime bundle.
8. Verification produces a fresh, run-specific exact-hash copy of all eligible ICM files.
9. Approved remote snapshots are materialized under `icm/context/external/`.
10. Context-derived actions are denied unless they present the current verified ICM envelope.

## Runtime bundle

After verification, the agent receives only:

```text
trusted-context/<run-id>/icm/
├── instructions/
├── context/
│   └── external/
└── memory/
```

The accompanying `context-envelope.json` enumerates every delivered file and restates the authority of
each layer. The `trusted-context/` and `context-envelope.json` names are retained for interface
compatibility; the artifact is a complete ICM bundle, not a Context-only package. The agent must not read
the original mutable workspace or refetch remote evidence during that run.

## Trust direction

Instructions may identify Context and Memory that are needed for a task. Context and Memory may supply
facts to Instructions, but they cannot redefine the Instructions. Any action produced after combining
the layers remains only a proposal until the independent intent-bound action gate permits it.

This creates two separate controls:

1. **ICM controls what information may influence reasoning and at what authority.**
2. **The action gate controls what effects the resulting reasoning may cause.**

## Existing-workflow integration

For an existing agentic workflow:

1. Place authoritative workflows in `instructions/`.
2. Route retrieved documents, email, web results, tool output, and RAG evidence into `context/` or an
   equivalent transient Context adapter.
3. Route durable state through `memory/` and prohibit direct agent writes except through the action gate.
4. Keep the policy, key, manifests, approvals, and enforcement process outside the agent-readable ICM
   folder.
5. Give the agent only the verified runtime bundle, mounted read-only or revalidated at the execution
   boundary.
6. Force every consequential tool call and handoff through the deterministic gates.

ICM therefore becomes the content backbone, while Security Cartographer remains the surrounding
reference monitor that validates the backbone and constrains its effects.

The complete end-user integration sequence, including exact commands and deployment acceptance tests, is
provided in `DEPLOYMENT_GUIDE.md`.

## Real-world security effect

Integrating this architecture into an existing agentic workflow can materially improve security when the
integration makes the boundaries mandatory. The improvement comes from four concrete changes:

1. Information is assigned an explicit authority level before the model sees it.
2. The agent receives a verified exact-hash bundle instead of continuing to read mutable sources.
3. Context and Memory cannot authorize tools or redefine the task.
4. The result of model reasoning remains a proposal until a deterministic gate permits the effect.

The benefit is lost if the agent can bypass the bundle, call unrestricted tools directly, retrieve the
source again, access credentials, or write Memory without enforcement. ICM improves the workflow's
security posture; it does not replace sandboxing, network enforcement, identity, monitoring, recovery, or
other production controls.
