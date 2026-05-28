# NetAdmin Agent — Phase 1 Plan

## Goal

Turn the current generic SSH diagnostic prototype into a platform-aware read-only ops agent for:

- RHEL-family Linux (RHEL 7/8/9, Rocky, Alma, CentOS derivatives)
- Cisco IOS / Catalyst
- Cisco NX-OS

Alpine remains useful as a lightweight test target, but it is not the primary design center.

## Design direction

The agent should stop guessing from one global command map and instead work through these layers:

1. **Connection layer**
   - persistent SSH session lifecycle
   - key-first auth with password fallback
   - platform-specific shell/CLI behavior
   - Cisco pagination suppression

2. **Platform profile layer**
   - platform detection from fingerprint commands
   - safe per-platform command registry
   - platform-specific output expectations

3. **Intent layer**
   - user intent → platform-safe command(s)
   - single-command flows first
   - multi-step playbooks second

4. **Parser/summarizer layer**
   - turn noisy raw output into operator-friendly summaries
   - preserve raw output for audit/debug

## Repo scaffold added now

```text
agent/
  connection/
  intents/
  parsers/
  platforms/
```

Profiles currently scaffolded:

- `platforms/rhel.py`
- `platforms/alpine.py`
- `platforms/cisco_ios.py`
- `platforms/cisco_nxos.py`
- `platforms/registry.py`

## Phase 1 implementation order

### Step 1 — Platform detection

Add a dedicated fingerprint flow that runs one or two safe commands after login.

Recommended detection sequence:

#### Linux
- `cat /etc/os-release`
- `uname -a`

#### Cisco IOS / NX-OS
- `show version`

Detection output should be cached in the active session state.

### Step 2 — Session classes

Split the current single SSH behavior into session-aware adapters:

- `LinuxShellSession`
- `CiscoIosSession`
- `CiscoNxosSession`

Responsibilities:
- connect
- authenticate
- prepare session
- run safe commands
- normalize output
- close session

Cisco session preparation should include pager suppression:
- IOS: `terminal length 0`
- NX-OS: `terminal length 0`

### Step 3 — Intent registry

Replace ad-hoc freeform keyword mapping with a structured registry.

Initial common intents:

- `system_health`
- `cpu`
- `memory`
- `disk`
- `interfaces`
- `routes`
- `services`
- `logs`
- `neighbors`
- `vlans`

Each platform should explicitly declare which intents it supports.

### Step 4 — First platform targets

#### RHEL first
Why first:
- easier to test repeatedly
- teaches us session/prompt/output handling without Cisco CLI quirks
- high utility for real server operations

Recommended first RHEL commands:
- `hostnamectl`
- `uptime`
- `top -bn1`
- `free -h`
- `df -h`
- `ip -br addr`
- `ip route`
- `systemctl --type=service --state=running --no-pager`
- `journalctl -p err -n 50 --no-pager`

#### Cisco IOS second
Recommended initial IOS commands:
- `show version`
- `show interfaces status`
- `show ip interface brief`
- `show vlan brief`
- `show cdp neighbors detail`
- `show mac address-table`
- `show spanning-tree`
- `show logging`

#### Cisco NX-OS third
Recommended initial NX-OS commands:
- `show version`
- `show interface brief`
- `show ip interface vrf all`
- `show vlan brief`
- `show cdp neighbors detail`
- `show mac address-table`
- `show port-channel summary`
- `show vpc`
- `show logging last 50`

## Phase 1 deliverables

### Deliverable A — platform-aware detection
- connect to host
- fingerprint platform
- store active session platform metadata

### Deliverable B — safe command registry
- user asks an intent
- agent selects command from current platform profile
- no unsupported command should run silently

### Deliverable C — operator-friendly summaries
Per command, return:
- platform
- executed command
- short summary
- cleaned raw output

### Deliverable D — unsupported-intent behavior
If an intent is not supported on the current platform:
- say so clearly
- keep session alive
- suggest closest supported intents

## Nmap follow-up roadmap

1. **Service/version detection with safe presets**
   - default remains basic discovery only
   - add explicit `safe` and `deep` nmap service detection profiles
   - run service detection only after host/port discovery finds candidates
2. **Scan profiles**
   - `quick`, `default`, and `deep` subnet scan presets
   - make profile choice explicit in result output and audit data
3. **Allowlisted NSE bundles**
   - read-only curated bundles only (for example TLS, HTTP title, SSH hostkey, SNMP info)
   - never allow arbitrary NSE script execution from natural-language prompts
4. **Host role classification**
   - infer likely device type from ports/services
   - highlight management-plane endpoints and unusual exposures
5. **Inventory diffs for services**
   - track newly opened/closed services over time without permitting arbitrary scans

## Suggested next coding tasks

1. Add session state object with:
   - host
   - user
   - platform key
   - client/session handle
   - auth mode

2. Add fingerprint command execution after SSH login.

3. Wire `platforms.detect_platform()` into the live SSH session flow.

4. Replace current global safe-command map with:
   - generic fallback intents only
   - platform profile resolution first

5. Add first parser/summarizer for RHEL:
   - CPU
   - memory
   - disk
   - services

## Important guardrails

- Keep everything read-only.
- Cisco support should remain `show`-only plus pager settings.
- Do not let natural-language prompts execute arbitrary shell/Cisco CLI text by default.
- Prefer intent mapping over raw command execution.
- Raw explicit commands may remain as an advanced/debug path, but should be clearly separated from the normal safe workflow.

## Recommendation

The next actual coding milestone should be:

**Implement platform detection + session metadata, then switch RHEL intents over to the new platform profile path.**

That gives the agent a real architecture instead of adding more one-off rules.
