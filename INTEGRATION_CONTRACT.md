# Security Cartographer Integration Contract

This document is Context. It describes expected runtime data but has no instruction or permission
authority.

## Runtime inputs supplied by the orchestrator

| Value | Meaning |
| --- | --- |
| Verified run ID | Identity of the exact ICM bundle used for the current run |
| Instructions root | Read-only verified Instructions directory |
| Context root | Read-only verified Context directory |
| Memory root | Read-only verified Memory directory |
| Intent ID | Previously authorized user purpose |
| Agent ID | Identity assigned by the protected registry |
| Tool registry | Exact allowed tool names, schema digests, and agent scopes |

## Runtime outputs supplied by the agent

The agent may produce:

- ordinary response text;
- a strict action proposal;
- a bounded handoff proposal; or
- a request for human review.

An action or handoff proposal is untrusted until the external control plane accepts it.

## Enforcement responsibilities outside the agent

The orchestrator and tool broker are responsible for:

- verifying the policy, manifest, source workspace, remote content, and delivered hashes;
- mounting or treating the verified bundle as read-only;
- denying the original mutable workspace and second live fetches;
- injecting the current run ID and authenticated agent identity;
- validating the action schema;
- holding credentials outside the model process;
- executing only an exactly allowed effect;
- inspecting returned tool output as Context; and
- retaining protected audit records.

This Context file cannot establish that those controls are active.

