# Security Cartographer — Simple Start Guide

This guide uses short words and small steps. It explains two different jobs:

1. **Try the demo.** This is a safe pretend example on your computer.
2. **Install the real module.** This adds Security Cartographer to an existing ICM agent.

The demo is optional. You may delete the whole `demo/` folder after you try it.

## The big idea

Think of an ICM agent as having three labeled boxes:

```text
Instructions = the job the agent is allowed to do
Context      = facts and outside information
Memory       = saved information from earlier work
```

Security Cartographer checks the boxes and makes a map. It records exactly what was approved. Before the
agent runs, it checks again. If something changed, it closes the gate.

The agent is then given a checked copy of the three boxes. The agent should not go back to the unchecked
files or fetch the website again.

## What is inside this package?

```text
instructions/   Part of the real module
context/        Part of the real module and the working Python engine
memory/         Part of the real module
demo/           Optional pretend example
```

Important: the working engine exists only once. It is here:

```text
context/security-cartographer/runtime/security_cartographer.py
```

The demo uses that engine. It does not use a second demo copy.

---

# Part 1 — Try the demo

## What you need

- Windows, macOS, or Linux
- Python 3.10 or newer
- Permission to make files inside the extracted package

You do not need:

- an AI account;
- an API key;
- internet access; or
- extra Python packages.

## Step 1: Extract the ZIP

Do not run the demo while it is still inside the ZIP preview window.

Extract `Security_Cartographer_ICM_Backbone_v3.0.1b.zip`. Open the extracted folder. You should see:

```text
README.md
START_HERE.md
LICENSE
instructions/
context/
memory/
demo/
```

## Step 2: Start the demo

### Windows

Open `demo/` and double-click:

```text
RUN_DEMO.bat
```

If the window closes too fast, open Command Prompt in the `demo/` folder and type:

```text
RUN_DEMO.bat
```

### macOS or Linux

Open a terminal in the extracted package and type:

```sh
sh demo/run_demo.sh
```

## Step 3: Watch what happens

The first lines show the real module being used:

```text
ICM Backbone runtime: .../context/security-cartographer/runtime/security_cartographer.py
Security Cartographer version: 3.0.1b
The demo contains no duplicate engine; it is running the deployable module above.
```

The demo then does these jobs:

1. It maps several pretend attack paths.
2. It checks that Instructions, Context, and Memory all exist.
3. It approves a safe bulletin from a temporary website on your own computer.
4. It makes a checked ICM copy for the agent.
5. It changes the pretend website bulletin.
6. It notices that the new bulletin does not match.
7. It puts the changed bulletin in quarantine.
8. It blocks the unsafe action.
9. It checks a pretend agent handoff and blocks reuse.
10. It checks the audit record.

Nothing is uploaded. The bad instructions are not followed.

## Step 4: Look at the results

The demo creates:

```text
demo/demo_output/
```

Start with these files:

### The wider map

```text
demo/demo_output/00-attack-surface-map/map.html
```

Open it in a web browser. This is the map a later reader can wander.

### The checked ICM bundle

```text
demo/demo_output/01-verified-context/context-envelope.json
demo/demo_output/01-verified-context/trusted-context/<run-id>/icm/
```

Open the generated `<run-id>` folder. The `icm/` folder should contain:

```text
instructions/
context/
memory/
```

### The blocked change

```text
demo/demo_output/02-blocked-change/map.html
demo/demo_output/02-blocked-change/quarantine/
demo/demo_output/02-blocked-change/action-decision.json
```

These show what changed, what was quarantined, and why the action was blocked.

For a longer walkthrough, read `demo/DEMO_GUIDE.md`.

## Step 5: Run it again

Run the same launcher again. The demo replaces only its own `demo/demo_output/` folder.

## Step 6: Delete the demo

When you are finished:

1. Close the command window.
2. Close any map file open in your browser.
3. Delete the complete `demo/` folder.

Delete this:

```text
demo/
```

Do not delete these:

```text
instructions/
context/
memory/
```

Deleting `demo/` removes the pretend files, launchers, and demo results. It does not remove or change the
real ICM module.

---

# Part 2 — Install the real ICM module

## Before you start

The real installation changes how an agent starts and how it calls tools. The person doing this work must
be able to change the agent host or orchestrator.

Make a backup first.

Your existing agent must already have:

```text
YOUR_ICM/
├── instructions/
├── context/
└── memory/
```

You also need a protected folder outside the ICM. The agent must not be able to change this folder or read
the secret key inside it.

In the commands below:

- `PACKAGE` means the extracted Security Cartographer package.
- `YOUR_ICM` means the existing agent's ICM folder.
- `CONTROL` means the protected folder outside the agent.

Replace those example words with real paths. Do not type the placeholder words as if they were real
folders.

## Step 1: Copy the three module folders

Copy:

```text
PACKAGE/instructions/security-cartographer/
```

to:

```text
YOUR_ICM/instructions/security-cartographer/
```

Copy:

```text
PACKAGE/context/security-cartographer/
```

to:

```text
YOUR_ICM/context/security-cartographer/
```

Copy:

```text
PACKAGE/memory/security-cartographer/
```

to:

```text
YOUR_ICM/memory/security-cartographer/
```

Do not copy `demo/` into the agent. Do not erase other files already used by the agent.

## Step 2: Put the Python runtime in a protected place

The runtime starts here:

```text
YOUR_ICM/context/security-cartographer/runtime/
```

Copy that complete `runtime/` folder to protected staging outside the ICM. Install from the protected
copy, not from the live Context folder. This keeps Python build files out of Context.

### Windows example

```powershell
Copy-Item "C:\path\to\YOUR_ICM\context\security-cartographer\runtime" "C:\SecurityCartographer\runtime-source" -Recurse
py -3 -m venv C:\SecurityCartographer\runtime
C:\SecurityCartographer\runtime\Scripts\python.exe -m pip install --no-deps C:\SecurityCartographer\runtime-source
C:\SecurityCartographer\runtime\Scripts\security-cartographer.exe --version
```

### macOS or Linux example

```sh
cp -R /path/to/YOUR_ICM/context/security-cartographer/runtime /opt/security-cartographer-runtime-source
python3 -m venv /opt/security-cartographer-runtime
/opt/security-cartographer-runtime/bin/python -m pip install --no-deps /opt/security-cartographer-runtime-source
/opt/security-cartographer-runtime/bin/security-cartographer --version
```

The last command should say:

```text
security-cartographer 3.0.1b
```

The example protected paths may need to be created by the computer administrator. If a later command
cannot find `security-cartographer`, use the complete executable path shown in the example above.

## Step 3: Make the protected CONTROL folder

The CONTROL folder stays outside the ICM. It holds the rules, secret key, approved fingerprints, checked
run bundles, decisions, quarantine, and audit records.

Use this shape:

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

The agent must not be able to read `integrity.key` or change anything in CONTROL.

## Step 4: Make the rule file

Copy:

```text
YOUR_ICM/context/security-cartographer/templates/source-policy.template.json
```

to:

```text
CONTROL/source-policy.json
```

Open the new policy file. Replace:

```text
REPLACE_WITH_AGENT_ID
REPLACE_WITH_INTENT_ID
```

with the real agent name and the real job identifier. Add only the websites and tools the agent truly
needs.

Keep:

```json
"icm_mode": "required"
```

Start with no websites and no tools. Add one permission at a time. Do not use the template unchanged.

## Step 5: Make the secret key

Run:

```sh
security-cartographer init-key --key-file CONTROL/integrity.key
```

Keep this key away from the agent. Do not put it in Instructions, Context, Memory, a prompt, or source
control.

## Step 6: Make the first map

Run:

```sh
security-cartographer scan YOUR_ICM --policy CONTROL/source-policy.json --output CONTROL/preflight
```

Open:

```text
CONTROL/preflight/map.html
```

Review the Critical and High findings. Fix anything you do not accept.

## Step 7: Approve the starting point

After a person reviews the map and the exact files, run:

```sh
security-cartographer approve YOUR_ICM --policy CONTROL/source-policy.json --key-file CONTROL/integrity.key --output CONTROL/approved-baseline
```

Approval means: “These exact files, rules, and outside sources are the starting point I reviewed.”

Do not automatically approve a new starting point after a check fails.

The runtime contains safety-check words and may flag its own exact source files. If approval stops, do
not simply turn the warning off. Follow the review instructions in `DEPLOYMENT_GUIDE.md`. After an
accountable person reviews those exact files, `--reviewed` may be used once for that known starting
point. Never add `--reviewed` to automatic runs.

## Step 8: Check before every agent run

Before the agent starts, run:

```sh
security-cartographer verify YOUR_ICM --policy CONTROL/source-policy.json --manifest CONTROL/approved-baseline/security-manifest.json --seal CONTROL/approved-baseline/integrity-seal.json --key-file CONTROL/integrity.key --output CONTROL/verified-runs/RUN-001
```

For the next run, use a new run folder such as `RUN-002`.

If verification passes, the checked ICM copy is under:

```text
CONTROL/verified-runs/RUN-001/trusted-context/<run-id>/icm/
```

Give the agent only that checked `icm/` folder. Mount it read-only when possible.

Do not let the running agent:

- go back to the unchecked `YOUR_ICM` folder;
- fetch an approved website a second time;
- read the integrity key;
- change CONTROL; or
- continue after a failed check.

## Step 9: Put the gate in front of tools

The agent must propose an action before a tool performs it. The host then calls Security Cartographer's
action check. Only a separate, limited tool broker may carry out an allowed action.

The agent must not hold unrestricted credentials or have another path around the gate.

Use:

```text
instructions/security-cartographer/CALL_PROTOCOL.md
context/security-cartographer/INTEGRATION_CONTRACT.md
context/security-cartographer/ACTION_PROPOSAL_SCHEMA.json
```

for the exact connection rules and action format.

## Step 10: Test before real use

Use a staging agent with no production secrets or production write access. Check that:

- a missing ICM layer stops the run;
- a changed local file stops the run;
- a changed website stops the run;
- the changed content goes to quarantine;
- the agent receives only the checked ICM bundle;
- an unapproved tool action is blocked;
- the agent cannot read the key or change CONTROL; and
- the agent cannot bypass the gate.

Do not call the installation complete until these checks pass.

## The short version

```text
TRY:
Extract → run demo → inspect maps → delete demo/

INSTALL:
Back up → copy three ICM folders → install runtime from protected staging
→ create protected CONTROL → customize rules → make key → scan → review
→ approve → verify before every run → give agent only checked ICM
→ put the gate in front of every important tool
```

For full production instructions, read:

```text
instructions/security-cartographer/DEPLOYMENT_GUIDE.md
```
