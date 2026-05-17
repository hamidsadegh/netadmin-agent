# AGENTS.md - NetAdmin Agent

This project is a small, safety-focused network administration assistant for read-only diagnostics.

## Working Directory

Use this directory as the project root:

```bash
/home/openclaw/.openclaw/workspace/netadmin-agent
```

The git repository root is one level above this project, so scope git commands to `netadmin-agent` paths when possible. Do not stage unrelated sibling workspace files.

## Test Command

Run the full test suite before handing off code changes:

```bash
python -m pytest
```

Targeted tests are fine while iterating, but the final verification should be the full suite.

## Safety Rules

- Keep diagnostics read-only.
- Do not add config-changing Cisco commands.
- Do not allow arbitrary shell or Cisco CLI execution through natural-language routing.
- Prefer intent resolution and platform allowlists over raw command execution.
- Scans must stay limited to allowed private networks.
- Treat inventory failures as warnings when scan data is still usable.

## Architecture Notes

The current direction is platform-aware diagnostics:

- `agent/platforms/` defines safe per-platform command profiles.
- `agent/tools/intents.py` maps user intent to allowlisted commands.
- `agent/tools/ssh.py` handles SSH connection, platform detection, session prep, execution, parsing, and summaries.
- `agent/skills/discovery.py` handles subnet discovery and inventory comparison.
- `agent/skills/port_scan.py` handles single-host TCP connect scans.
- `agent/cli/parsing.py` handles deterministic routing before model fallback.

When adding capabilities, update tests near the layer being changed instead of only testing through the CLI.

## Known Local Quirks

- `known_hosts.json` may be owned by another user in this workspace. Code should not let that break primary scan results.
- `.codex` may appear as an untracked local runtime file; ignore it unless explicitly asked.

