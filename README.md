# Fenrir

**Azure identity enumeration & managed-identity exploitation toolkit.**

Fenrir is a command-line tool that walks the Azure attack path from a single
authenticated identity: enumerate what you can see in the tenant, decide
whether you can impersonate a **managed identity (MI)**, steal its tokens
through compute hosts (VMs, App Services, Logic Apps, Container Groups,
Automation Accounts), then enumerate — and optionally harvest data from —
everything that stolen identity controls.

---

## Legal / ethics notice

This tool performs credential abuse, command injection against compute
hosts, and data exfiltration in Azure. It is intended **only** for:

- authorized penetration tests and red-team engagements you have written
  permission to run;
- own-tenant / lab environments (e.g. subscription you control, sandboxes
  created for this purpose).

Running it against infrastructure you do not own, or without written
authorization, is illegal in most jurisdictions. You are responsible for how
you use it.

---

## Context: what problem does it solve?

Azure lets workloads authenticate without human passwords via **managed
identities** — an Azure-issued identity that a VM, App Service, Logic App, or
Container Group can use to obtain tokens. This is a common, powerful foothold
for an attacker who already has *control-plane* access:

| You hold at resource-group scope | Result |
|---|---|
| `Owner`, `Contributor` | Can run commands on compute hosts → reach the host's **IMDS** endpoint → request a token as the host's identity |
| `Virtual Machine Contributor`, `Website Contributor`, `Automation Contributor`, etc. | Same, restricted to one host type |
| `User Access Administrator` | Can assign roles (including to yourself) |
| `Managed Identity Operator` / `Contributor` | Can attach an existing **user-assigned identity (UAI)** to a host you control, then impersonate it |

Fenrir automates the whole chain and answers the question **"how far does a
compromised Azure user take me?"**

---

## Highlights

- **Multi-phase exploit readiness assessment** — a verdict (`READY` /
  `BLOCKED_NO_RIGHTS` / `BLOCKED_NO_TARGETS` / `UNVERIFIED`) telling you
  whether continuing the attack is worth it, plus specific
  **privilege-escalation opportunities** (self role-assignment, UAI
  auto-attach).
- **Multiple token-extraction paths**: VM RunCommand → IMDS, App Service
  **Kudu** command execution, Logic App callbacks, Container Group exec,
  Automation Account runbooks.
- **MI cross-referencing** — discover standalone user-assigned identities and
  extract their tokens through any host that has them assigned.
- **Post-exploitation enumeration** — for a stolen MI token, walk every
  subscription/resource-group the identity can see, its RBAC roles tenant-wide,
  and flag credential-bearing resources.
- **Data harvesting** — dump blobs / Azure Files from readable Storage
  accounts and pull images from readable Container Registries, gated on the
  identity's *resolved capabilities*.
- **State persistence** — `enumerate` saves everything to a JSON state file;
  `exploit` can resume from it without re-running discovery.

---

## Repository layout

```
├── pyproject.toml              # Packaging (hatchling), CLI entry point
├── src/fenrir/
│   ├── cli.py                  # typer root: login/logout/status/token/enumerate/
│   │                           #   exploit/post-exploit
│   ├── state.py                # ExploitResult <-> JSON state (save/load/convert)
│   ├── core/
│   │   ├── authenticator.py    # MSAL OAuth (device-code/interactive/ROPC), token cache
│   │   ├── logging_util.py
│   │   └── enumerate/
│   │       ├── collector.py    # Graph + ARM enumeration collectors
│   │       ├── models.py       # EnumerationResult & dataclasses
│   │       └── verdict.py      # Exploit-readiness verdict + opportunities
│   ├── exploit/
│   │   ├── arm_enum.py         # ARM dataclasses, role maps, enterprise-app lookup
│   │   ├── discovery.py        # Phase-1 discovery (subs, RGs, RBAC, resources)
│   │   ├── orchestrator.py     # Orchestration: extraction paths, MI cross-ref
│   │   ├── resource_exploit.py # Per-resource exploit helpers (Kudu, RunCommand, …)
│   │   ├── run_command.py      # VM RunCommand payloads
│   │   ├── imds_payload.py     # IMDS token payload + audiences
│   │   ├── identity_enum.py    # What can a stolen token access?
│   │   ├── post_exploit.py     # Tenant-wide post-exploitation enumerator
│   │   ├── storage.py          # Storage account blob/file harvesting
│   │   ├── acr.py              # Container registry image harvesting
│   │   ├── capabilities.py     # Data-plane capability resolution
│   │   ├── findings.py         # Secret-scanning findings on downloaded content
│   │   ├── token_cache.py      # Cached MI tokens (mi_tokens.json)
│   │   └── …
│   └── commands/               # typer command modules (login/logout/status/token/
│                               #   enumerate/exploit/post-exploit)
└── tests/                      # pytest suite (231 tests)
```

---

## Installation

Requires **Python ≥ 3.11** — nothing else.

```bash
# from the repo root
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

# verify
fenrir --help
fenrir --version
```

The default MSAL client ID is the Azure CLI public client
(`04b07795-...`), so **no app registration is required** for
`device-code`/`ropc` flows. For `interactive` browser flow, bring your own app
registration (needs `http://localhost` as a redirect URI).

---

## Authentication

All commands reuse a silent MSAL token cache at `~/.config/fenrir/token_cache.bin`.
Sign in once, and every command refreshes silently.

```bash
# Device code flow (default) — prints a URL + code to open in a browser
fenrir login -u user@contoso.com

# Interactive browser popup (needs your own --client-id + redirect URI)
fenrir login -u user@contoso.com --auth-flow interactive --client-id <app-id>

# ROPC (password grant — legacy, may be blocked by tenant policy)
fenrir login -u user@contoso.com -p 'password' --auth-flow ropc

# Sign out / clear cache
fenrir logout
```

Environment variables are read as defaults for every command:

| Variable | Purpose |
|---|---|
| `AZAUTH_USERNAME` | Default username |
| `AZAUTH_PASSWORD` | Default password (ROPC) |
| `AZAUTH_TENANT` | Tenant ID / domain |
| `AZAUTH_CLIENT_ID` | App registration client ID |
| `AZAUTH_SCOPES` | Comma-separated scopes (default Graph `.default`) |
| `AZAUTH_AUTH_FLOW` | `device-code`, `interactive`, or `ropc` |
| `FENRIR_STATE` | Override the exploit state file path |
| `FENRIR_MI_TOKEN_CACHE` | Override the MI token cache path |

Check state at any time:

```bash
fenrir status            # accounts + token expiry (add --json)
fenrir token --raw       # print just the access token (for piping)
```

---

## The end-to-end execution steps

### Step 0 — Verify auth

```bash
fenrir status
fenrir token --raw | jq -R 'split(".")[1] | @base64d'   # peek at claims
```

### Step 1 — Enumerate the tenant (`fenrir enumerate`)

This is the **reconnaissance + readiness gate**. It pulls from **Microsoft
Graph** (you, domains, directory roles, PIM roles, groups, owned apps /
service principals, managed devices) and **Azure Resource Manager**
(subscriptions → resource groups → resources), then produces an
**exploit-readiness verdict**.

```bash
fenrir enumerate                          # tree view (default)
fenrir enumerate -f json -o enum.json     # machine-readable
fenrir enumerate --no-resources           # skip ARM resource listing (faster)
```

Verdict meanings:

| Verdict | Meaning | Next step |
|---|---|---|
| `READY` (green) | You hold an exploit-relevant role at RG scope **and** there are MI-bearing resources to hit | `fenrir exploit` |
| `BLOCKED_NO_TARGETS` (yellow) | You have the rights but no MI-capable resource carries an identity right now | wait for an MI to be introduced, or use a UAI |
| `BLOCKED_NO_RIGHTS` (red) | No exploit-relevant role at RG scope — the attack stops here | pursue non-MI data access only |
| `UNVERIFIED` (yellow) | `--no-resources` was used, RG-level roles unknown | re-run without it |

The "interesting" (exploit-gating) roles are: **Owner, Contributor, User
Access Administrator, Virtual Machine Contributor, Managed Identity Operator,
Managed Identity Contributor, Website Contributor, Logic App Contributor,
Automation Contributor, Automation Operator, Azure Container Instances
Contributor Role.**

The verdict also lists **privilege-escalation opportunities**, e.g.:

- *Self role-assignment* — `Owner`/`User Access Administrator` lets you grant
  yourself data-plane roles (`Storage Blob Data Contributor`, `Key Vault
  Secrets User`, `AcrPull`, …).
- *Auto-attach UAI* — combining a UAI-assign role with a host-write role lets
  you attach an existing user-assigned identity to a host you control.

> When resource groups were enumerated, `enumerate` **automatically saves an
> exploit state file** (see [State persistence](#state-persistence)) so the
> exploit phase can skip discovery.

### Step 2 — Exploit (`fenrir exploit`)

Extracts managed-identity tokens through the compute hosts you control.

```bash
# Resume from the state saved by 'enumerate' (skips discovery entirely)
fenrir exploit

# Explicit state file, or force a fresh discovery instead
fenrir exploit --state /path/to/state.json
fenrir exploit --fresh

# Options
fenrir exploit -f json -o exploit.json          # machine-readable output
fenrir exploit --skip-run-command               # discovery only, no extraction
fenrir exploit -v                               # per-resource detail
fenrir exploit --no-dump-tokens                 # don't write fenrir_tokens/
fenrir exploit -t mytenant                      # dump sub-directory for tokens
```

What happens per interesting resource group:

1. **Direct extraction** on every MI-capable resource you control:
   - **VM** → RunCommand → IMDS → token
   - **App Service** → Kudu command execution → IMDS
   - **Logic App** → callback → token
   - **Container Group** → exec endpoint
   - **Automation Account** → runbook artifacts
2. **MI cross-referencing** — for each *user-assigned identity* discovered in
   the group, find any VM / App Service / Logic App that has it assigned and
   pull a token for that specific `client_id`.
3. For every successful extraction the token is exchanged against ARM to map
   **what the identity can access** (`enumerate_identity`).
4. Successful tokens are **cached** (for `post-exploit`) and, unless disabled,
   dumped to `fenrir_tokens/<tenant>/`.

The output tree annotates each resource with flags:

- `[TOKEN]` (red) — direct token extraction possible (VM)
- `[TOKEN]` / `[TOKEN-X]` (yellow/cyan) — possible but conditional (App
  Service, Logic App, Container Group)
- `[CREDS]` — credential-bearing resource (Storage, Key Vault, ACR, …)

### Step 3 — Post-exploit (`fenrir post-exploit`)

Take a cached (or injected) MI token and walk the whole tenant as that
identity.

```bash
fenrir post-exploit                     # interactive pick from cached tokens
fenrir post-exploit -m my-mi-name       # pick by managed-identity name
fenrir post-exploit -c <client-id>      # pick by client id
fenrir post-exploit -i 1                # pick by cache index

# Lab runs: inject tokens directly (no cache, no VM needed)
fenrir post-exploit --access-token "$ARM_TOKEN" \
                    --principal-id <mi-principal-id> \
                    --storage-token "$STORAGE_TOKEN" --acr-token "$ACR_TOKEN"

# Data harvesting (prompts for confirmation unless -y)
fenrir post-exploit --dump-blobs -o dump -y
fenrir post-exploit --dump-images -o dump -y
fenrir post-exploit --dump-blobs --dump-images --dry-run   # inventory only

# Output
fenrir post-exploit -f json -o post_exploit.json
```

It reports:

- the identity's **RBAC role assignments** anywhere in the tenant;
- every **subscription / resource group / resource** it can see, with
  read/write/action flags and a `[CREDS]`/`[TOKEN]` annotation;
- resolved **capabilities** (which data-plane actions are actually granted);
- with `--dump-blobs`: storage account contents (blobs + Azure Files) with a
  10 MiB per-object cap, secret-scanning **findings**, and a `manifest.json`;
- with `--dump-images`: registry repositories/images/layers with the same
  disclosure controls.

---

## State persistence

`fenrir enumerate` (without `--no-resources`) writes an **exploit state file**
so discovery doesn't have to run twice.

- **Path:** `~/.config/fenrir/state.json` (override with `FENRIR_STATE` or
  `--state`).
- **Contents** (version 1): `subscriptions`, `interesting_groups` (with MIs,
  VMs, App Services, Logic Apps, Automation Accounts, service principals,
  resources, and each group's roles), `errors`, `principal_id`, `saved_at`.
- The exploit phase **auto-detects** the file; with interesting groups present
  it loads them and skips discovery entirely (it still re-runs the cheap
  enterprise-app cross-reference when a Graph token is available, and warns if
  the file was saved by a different principal than the one authenticated).
- `exploit --fresh` ignores the state file and does a full re-discovery;
  `exploit --state <file>` points at a specific file and exits with code `3`
  if it's missing.

The same state also powers the verdict panel and is designed to be the single
handoff between the recon and attack phases.

---

## Outputs & artifacts

| Path | What it is |
|---|---|
| `~/.config/fenrir/token_cache.bin` | MSAL token cache (auth sessions) |
| `~/.config/fenrir/mi_tokens.json` | Cached stolen MI tokens (used by `post-exploit`) |
| `~/.config/fenrir/state.json` | Exploit state from `enumerate` |
| `fenrir_tokens/<tenant>/` | Raw access-token dumps + `manifest_*.json` from `exploit --dump-tokens` |
| `dump/` | Blobs, images and `manifest.json` from `post-exploit --dump-blobs/--dump-images` |

All secrets are stored locally in plaintext — keep the machine secure and
clean up `fenrir_tokens/` / `dump/` / `~/.config/fenrir/` after an engagement.

---

## Testing

```bash
python3 -m pytest tests/ -q        # 231 tests, no live Azure required
python3 -m pytest tests/test_state.py   # state round-trip + CLI resume tests
```

The suite covers the authenticator, enumerate/verdict logic, discovery and
orchestration (with mocked Azure APIs), every token-extraction path, IMDS
payloads, storage/ACR harvesting, the token cache, and the state feature.

---

## Notes & limitations

- **RG-scope only.** The exploit phase only acts on role assignments at the
  *resource-group* scope (direct assignments; no inheritance expansion).
  Subscription-scope roles are surfaced in the verdict as a note, not acted
  on.
- **RunCommand may be disabled** at policy/OS level; not every host is
  reachable. The orchestrator reports per-host errors (`--verbose` shows
  them).
- App Service token extraction is limited to plans that support **Kudu
  command execution** (Linux consumption plans don't).
- Storage/ACR harvesting is capability-gated: if the identity cannot read, no
  data is downloaded. `--dry-run` inventories without writing anything.
- This is a fast-moving research tool; check the tests and command `--help`
  output, which stay the most current source of truth.
