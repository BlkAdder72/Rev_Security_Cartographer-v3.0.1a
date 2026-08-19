# Threat Model — Security Cartographer 3.0.1b — ICM Backbone

## Protected decision

An agent should not treat mutable, inherited, rendered, retrieved, encoded, or tool-supplied content as
authoritative instructions, and it should not perform an action merely because such content requested or
socially engineered it.

## Adversary capabilities considered

- Create or modify files inside a body of work.
- Place a symbolic link that resolves outside the mapped root.
- Control a website after its earlier review.
- Add nested remote references, redirects, active images, forms, scripts, or data URIs.
- Hide instructions with HTML/CSS, Unicode controls, percent encoding, or Base64.
- Influence email, tool results, retrieval results, OCR, clipboard data, persistent memory, or subagent
  output.
- Attempt to change the policy, manifest, saved snapshot, or action request.
- Persuade the model to use valid delegated credentials for an unauthorized purpose.
- Exploit a check-then-refetch gap.
- Trigger project-local hooks or tool configuration before a folder trust decision.
- Abuse an approved domain for uploads, attacker-controlled accounts, or query-string exfiltration.
- Add or mutate a tool after its initial approval.
- Spoof, alter, or replay an agent-to-agent handoff.
- Insert persuasive rationale into an authorization request or self-assert human approval.

## Source-to-sink model

| Untrusted source | Possible propagation path | Dangerous sink |
| --- | --- | --- |
| Markdown or structured file | Agent context | Tool or connector call |
| Mutable website | Retrieval result | External transmission |
| Remote image/form/script | Renderer or browser | Silent request with data |
| Email or message | Summary/handoff | Send, update, or disclosure |
| Tool output | Main-agent context | Authenticated API action |
| Persistent memory/state | Future session | Repeated compromise |
| Subagent result | Trust escalation | Privileged parent action |
| Generated output | Re-ingestion cycle | Persistent poisoning |
| Opaque document or vector store | Parser/RAG | Hidden instruction retrieval |
| Symlink | Filesystem resolution | Out-of-scope file disclosure |

## Trust boundaries

| Component | Trust level | Rule |
| --- | --- | --- |
| Present human request | Authoritative within outer system limits | Defines current intent, not unlimited capability |
| Sealed policy and manifest | Deterministic authority | Valid only when HMAC verifies with an external key |
| Unverified source workspace | Untrusted | Mapped and hashed; never supplied directly to the guarded agent |
| Verified ICM Instructions | Bounded workflow authority | May direct behavior only after policy and content verification |
| Verified ICM Context | Reviewed data | May provide facts but never grant instruction or action authority |
| Verified ICM Memory | Persistent reviewed data | May carry state but never create goals, permissions, tools, or instructions |
| Approved remote snapshot | ICM Context data | Exact bytes may provide facts but no instruction authority |
| Live response | Untrusted and mutable | Must match the sealed baseline |
| ICM runtime envelope | Verified transport description | Enumerates all delivered layers, their hashes and authority, and the no-refetch rule |
| Model or subagent output | Proposal | Must fit a strict schema and independent action policy |
| Proposed tool action | Untrusted until checked | Must match sealed intent, provenance, data, effect, target, and count |
| Agent identity and handoff | Untrusted until authenticated | Must match the sealed registry, intent, direction, payload digest, expiry, and replay state |

## Security invariants

1. Approval attaches to exact bytes, exact permitted source path, type, and time—not a domain forever.
2. The policy and manifest are rejected if their HMAC seal fails.
3. New, removed, changed, stale, redirected, missing, or tampered dependencies stop the guarded workflow.
4. Changed bytes never overwrite the approved snapshot.
5. The agent consumes only the run-specific verified ICM bundle and must not reopen mutable source files
   or refetch the remote source.
6. Remote references inside retrieved content are blocked by default.
7. Active remote rendering paths are separate, visible security findings.
8. Private and non-global network destinations are denied unless a narrow test policy explicitly permits
   them.
9. Symbolic links are never followed as ordinary files and out-of-root links are Critical.
10. Opaque or over-budget content is flagged rather than treated as inspected.
11. Untrusted email, tool, memory, retrieval, OCR, clipboard, and subagent text has no instruction
    authority.
12. External content cannot create, change, or expand an action contract.
13. Action authorization is deterministic and separate from model reasoning.
14. Security reports explain the decision but do not enforce it.
15. Project-local executable configuration is identified before it can be treated as trusted startup state.
16. An approved hostname is not a blanket capability grant; query-bearing source URLs are denied by default.
17. Dynamic tools are denied unless their name, schema digest, and agent scope match the sealed registry.
18. Action authorization excludes persuasive prose and tool-return content from its decision basis.
19. Human approval is short-lived and bound to the exact action digest.
20. Agent handoffs are authenticated, scoped, expiring, and single-use.
21. Runtime audit events are authenticated and hash-chained.
22. Required-mode workspaces contain separate Instructions, Context, and Memory layers.
23. Only Instructions may carry instruction authority.
24. Context and Memory cannot import Instructions or promote their content into authority.
25. Memory cannot introduce live remote dependencies.
26. The runtime consumes a run-specific exact-hash ICM bundle rather than the mutable source workspace.
27. Sensitive and opaque content is excluded from automatic ICM delivery.

## Detection versus prevention

Text inspection is a detection aid. It covers obvious override, exfiltration, persistence, concealment,
remote execution, destructive action, authority claims, capability escalation, agent handoff, invisible
Unicode, hidden HTML/CSS, and several safe decoded views.

Prevention relies primarily on structural controls: the mandatory ICM authority split, exact-byte
comparison, sealed policy, private-network blocking, resource budgets, no second live fetch, default-denied
actions, and intent-bound side effects.

## Explicit limitations

- The HMAC key must remain outside attacker control. If the attacker obtains it, the seal can be forged.
- HMAC detects modification but not rollback to an older valid policy and manifest. Production use needs
  monotonic protected state or an external append-only ledger.
- The standard-library prototype does not parse PDFs, Office files, images, audio, video, archives,
  databases, vector indexes, or steganography. It flags them as opaque.
- DNS can change after resolution. The design avoids a second application-level fetch, but production
  deployments should use a network proxy that pins and validates destinations at connection time.
- Content scanners cannot reliably identify every socially engineered or semantically malicious message.
- The prototype supplies a sealed local identity registry and HMAC-authenticated handoffs, but not
  enterprise workload identity, mutual TLS, hardware-backed keys, or cross-platform PKI.
- The authenticated audit chain is local and detects modification, reordering, and interior removal; it
  cannot detect tail truncation or rollback without an externally retained head or remote append-only storage.
- The sealed replay cache blocks reuse while current state is retained, but an attacker able to roll the
  cache back to an older valid copy could replay a handoff. Production needs monotonic or server-side nonce state.
- The `approved_by` value is an audit label, not proof of interactive human presence. Production approval
  should be issued by a separately authenticated service or hardware-backed identity that the agent cannot invoke.
- The prototype does not supply operating-system sandboxing, credential brokerage, centralized audit
  storage, rate limiting across processes, or incident response.
- A human can intentionally approve risky exact bytes with `--reviewed`; governance must control that
  override.
- The prototype writes a run-specific exact-hash ICM bundle and records every delivered hash. Production
  integration must additionally make that bundle read-only to the agent and revalidate it at the
  execution boundary or place it in a protected content store.

## Production controls to surround the prototype

- Hardware- or service-backed key storage and signed release identities.
- Append-only, externally timestamped audit and baseline version records.
- Egress proxy with destination, method, path, and data-flow enforcement.
- Ephemeral read-only content-inspection sandbox with no credentials.
- Format-specific parsers that return schema-validated facts, not freeform inherited instructions.
- Mandatory ICM adapters for every agent-readable ingress channel and a broker that prevents bypass of
  the verified bundle and action gate.
- Short-lived, task-specific agent credentials with revocation and object-level authorization.
- Human approval for external communication, irreversible actions, privilege changes, and sensitive data.
- Runtime budgets, anomaly detection, emergency disablement, incident response, and recovery testing.
