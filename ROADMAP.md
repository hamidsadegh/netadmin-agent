# NetAdmin Agent Roadmap

Work through these one by one.

1. Platform help - done
   - Add `help`, `?`, and `/`.
   - Show agent examples, current platform abilities, and mode switch commands.
2. Simulator command aliases - done
   - Add common Cisco variants such as `show interface status`, `show int status`, `sh int status`, and MAC table aliases.
   - Add safe output filters like `show logging | include Gi1/0/16`.
3. SSH mode completion - done
   - Complete common commands based on the detected platform.
4. Short-term session memory - done
   - Remember last interface, MAC, VLAN, scan, and device.
   - Support follow-ups like `check logs for same interface`.
5. Interface deep-dive playbook - done
   - One compact workflow for status, VLAN, neighbor, MACs, logs, errors, optics, and config snippet.
6. Raw output filters - done
   - Support safe `include` filters for show commands.
7. Config-safe diff view - done
   - Read-only comparison of running config snippets against expected templates.
8. Export report
   - Save interface/device troubleshooting reports as Markdown or JSON.
