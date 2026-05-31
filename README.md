# NetAdmin Agent

A small network administrator assistant focused on safe, read-only diagnostics.

## Current capabilities

- Check one device for ICMP reachability and SSH TCP reachability
- Discover hosts in an allowed private subnet
- Compare each new scan against the previous `known_hosts.json` inventory
- SSH to a remote host, prompt for missing credentials, run a safe read-only diagnostic command, and clean the output
- Store inventory data in `known_hosts.json`
- Scaffold platform profiles for RHEL, Alpine, Cisco IOS, Cisco IOS-XE, and Cisco NX-OS

## Usage

Interactive mode:

```bash
python main.py
```

Single prompt mode:

```bash
python main.py --prompt "check 192.168.178.49"
```

Direct host check:

```bash
python main.py --host 192.168.178.49
```

Subnet discovery:

```bash
python main.py --scan 192.168.178.0/24 --ports 22,80,443
```

Subnet discovery with a safe profile:

```bash
python main.py --scan 192.168.178.0/24 --scan-profile quick
python main.py --scan 192.168.178.0/24 --scan-profile deep
```

Explicit masscan subnet discovery:

```bash
python main.py --scan 192.168.178.0/24 --ports 22,80,443 --scanner masscan
```

Subnet discovery with safe nmap service detection:

```bash
python main.py --scan 192.168.178.0/24 --ports 22,80,443 --service-detection safe
```

Deeper nmap service detection:

```bash
python main.py --scan 192.168.178.0/24 --ports 22,80,443 --service-detection deep
```

Remote SSH diagnostic:

```bash
python main.py --ssh-host 192.168.178.49 --ssh-user admin --ssh-cmd "uptime"
```

Remote SSH diagnostic on a custom port:

```bash
python main.py --ssh-host 127.0.0.1 --ssh-port 2222 --ssh-user admin --ssh-cmd "show version"
```

Natural-language SSH diagnostic:

```bash
python main.py --ssh-host 192.168.178.49 --ssh-user admin --ssh-request "show disk usage"
```

Interactive credential prompts also work in chat mode, for example:

```text
connect to 192.168.178.49
```

The agent will ask for the username if missing, then prompt for a password if key-based auth fails.

Once connected, you can also ask things like:

```text
session info
what can you do here?
what platform is this?
```

The agent will show the detected platform, session mode, and the safe intents it currently supports on that host.

When a live SSH session is active, the interactive prompt also changes to show the connected target, for example:

```text
netadmin-agent[cisco_ios:127.0.0.1:2222]>
```

That way the operator can immediately see they are working inside an active device session.

In interactive mode on Linux/macOS terminals, prompt history is also remembered in `.netadmin_history`, so:

- **Up/Down** walk through previous prompts
- **Left/Right** let you move within the current line and correct it like a normal shell
- long-running actions show a live **orange dotted spinner/status** so the CLI clearly looks busy instead of stuck
- when an action finishes, the CLI prints a clear **done/failed** line with elapsed time
- phase labels are more intentional now, e.g. **Planning action...**, **Collecting network inventory...**, **Collecting remote diagnostics...**, **Summarizing result...**

## Environment

Start from the example file:

```bash
cp .env.example .env
```

Required settings:

```env
GEMINI_API_KEY=your-key
OPENAI_API_KEY=your-openai-key
```

Optional settings:

```env
NETADMIN_PROVIDER=openai
NETADMIN_MODEL=gpt-4.1-mini
NETADMIN_ALLOW_SUDO=0
NETADMIN_DEFAULT_SCANNER=nmap
NETADMIN_NMAP_BIN=nmap
NETADMIN_MASSCAN_BIN=masscan
NETADMIN_SCAN_RATE=1000
NETADMIN_KNOWN_HOSTS_FILE=known_hosts.json
NETADMIN_SSH_BIN=ssh
NETADMIN_SSH_CONNECT_TIMEOUT=8
NETADMIN_SSH_COMMAND_TIMEOUT=20
```

The default provider is OpenAI. If an OpenAI generation request fails, the app falls back to Gemini.

To use Gemini directly:

```env
NETADMIN_PROVIDER=gemini
NETADMIN_MODEL=gemini-2.5-flash
```

## Cisco SSH simulator

For local testing, use the sibling simulator repository:

```bash
cd ../simulators
```

Start IOS:

```bash
python cisco_ssh_simulator.py --platform ios --port 2222
```

Start IOS-XE:

```bash
python cisco_ssh_simulator.py --platform iosxe --port 2224
```

Start NX-OS:

```bash
python cisco_ssh_simulator.py --platform nxos --port 2223
```

Default credentials:

- username: `admin`
- password: `admin`

You can point a plain SSH client at it for quick checks:

```bash
ssh -p 2222 admin@127.0.0.1 "show version"
ssh -p 2222 admin@127.0.0.1 "show interfaces status"
ssh -p 2224 admin@127.0.0.1 "show version"
ssh -p 2223 admin@127.0.0.1 "show vpc"
```

It is designed to match the agent's current `exec_command()` SSH workflow, including platform detection with `show version` and Cisco pager preparation with `terminal length 0`.

## Simulator integration demo

For day-to-day agent development, the main CLI can start a simulator backend for one command:

```bash
python main.py --simulator ios --ssh-request "show interfaces"
python main.py --simulator iosxe --ssh-request "show logs"
python main.py --simulator nxos --ssh-request "show vpc"
```

The CLI starts the fake device on a random local port, uses the default simulator credentials, runs through the normal SSH diagnostic path, prints JSON, and stops the simulator.

For a broader smoke test that starts the simulator and runs several checks against it:

```bash
python demos/simulator_integration_demo.py --platform ios --pretty
python demos/simulator_integration_demo.py --platform iosxe --pretty
python demos/simulator_integration_demo.py --platform nxos --pretty
```

That demo:

- starts the fake device on a random local port
- connects through the agent's real SSH path
- verifies platform detection/session prep
- runs a few safe commands and prints JSON summaries

## Notes

- Scans are restricted to RFC1918 private networks.
- Subnet discovery now defaults to `nmap`; use `masscan` only when you explicitly request it.
- `masscan` discovery still requires local availability of the binary and suitable privileges.
- `nmap` scans run in read-only discovery mode (`-sn` for host discovery, normal port scans for requested ports).
- Subnet discovery supports safe scan profiles: `quick` scans a lighter default port set (`22,443`), `default` keeps the normal default (`22,80,443`), and `deep` scans a broader read-only default (`1-1024`).
- Custom `--ports` overrides the profile's default port set; raw `nmap` arguments are intentionally not supported.
- Optional nmap service detection is explicit and limited to discovered hosts on the requested ports.
- Service detection supports `safe` (`-sV --version-light`) and `deep` (`-sV --version-all`) presets.
- Obvious host and subnet prompts are routed deterministically before falling back to the model.
- SSH execution is intentionally limited to safe read-only diagnostics and blocks shell chaining / destructive commands.
- Interactive scan/connectivity output should prefer a short human summary first; raw JSON is mainly for direct CLI flags or debugging.
- If an SSH request only asks to connect, the agent defaults to a safe `hostname` check.
- Scan results now include a comparison section with new, disappeared, and changed hosts.
- A platform-aware Phase 1 plan now lives in `PHASE1-PLAN.md`.
- The project now ignores `.venv/`; moving that environment outside the repo is still recommended.
