# Install This ICM Package

This package contains only the three ICM layers. Add its contents to the matching folders of the existing
ICM agent:

```text
instructions/security-cartographer/  → EXISTING_ICM/instructions/security-cartographer/
context/security-cartographer/       → EXISTING_ICM/context/security-cartographer/
memory/security-cartographer/        → EXISTING_ICM/memory/security-cartographer/
```

Do not replace unrelated files in the existing ICM.

## Install the callable runtime

The reusable Python runtime is stored as Context at:

```text
context/security-cartographer/runtime/
```

The agent host or orchestrator first copies that directory to protected staging outside the ICM, then
installs from the copy. This prevents Python build tools from leaving generated files in Context.

### Windows PowerShell

```powershell
Copy-Item "EXISTING_ICM\context\security-cartographer\runtime" "C:\protected\cartographer-runtime-source" -Recurse
py -3 -m pip install --no-deps C:\protected\cartographer-runtime-source
```

### macOS or Linux

```sh
cp -R EXISTING_ICM/context/security-cartographer/runtime /protected/cartographer-runtime-source
python3 -m pip install --no-deps /protected/cartographer-runtime-source
```

Confirm:

```sh
security-cartographer --version
```

Expected version: `3.0.1`.

## Establish the external enforcement state

Although the runtime files are distributed through this ICM package, the following operational items must
be created outside the agent-readable ICM:

- customized policy;
- integrity key;
- approved manifest and seal;
- verified-run outputs;
- action proposals and decisions;
- approvals, replay state, and audit records.

Use the deny-first template at
`context/security-cartographer/templates/source-policy.template.json` and replace every placeholder.
Keep `icm_mode` set to `required`.

Create the key, map the combined ICM, and approve its initial baseline:

```sh
security-cartographer init-key --key-file CONTROL/integrity.key
security-cartographer scan EXISTING_ICM --policy CONTROL/source-policy.json --output CONTROL/preflight
security-cartographer approve EXISTING_ICM --policy CONTROL/source-policy.json --key-file CONTROL/integrity.key --output CONTROL/approved-baseline
```

The source runtime is intentionally visible and hashed as part of Context. Review any findings associated
with the runtime source. If accountable review accepts those exact files, `--reviewed` may be used once
for that known baseline; it must never be added automatically after later verification failures.

## Connect the existing agent

The host imports `CartographerRuntime` from `icm_runtime_adapter`. Follow `CALL_PROTOCOL.md` for the
required sequence.

The package is not active merely because its folders were copied. Deployment is complete only when the
agent host calls verification before a run, gives the agent only the verified bundle, and routes effects
through the action boundary.

Before production use, complete the operational steps and acceptance checklist in `DEPLOYMENT_GUIDE.md`.
