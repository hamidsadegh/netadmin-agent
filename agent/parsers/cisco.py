from __future__ import annotations

import re


def _clean_lines(text: str) -> list[str]:
    return [line.rstrip() for line in text.splitlines() if line.strip()]


def parse_show_interfaces_status(text: str) -> list[dict]:
    lines = _clean_lines(text)
    entries = []
    status_tokens = {"connected", "notconnect", "disabled", "inactive", "sfpabsent", "err-disabled", "down", "up"}
    for line in lines:
        if line.lower().startswith("port "):
            continue
        if not re.match(r"^[A-Za-z]+[A-Za-z0-9/.-]+\s", line):
            continue
        raw_parts = line.split()
        if len(raw_parts) < 2:
            continue
        port = raw_parts[0]
        status_index = next((idx for idx, token in enumerate(raw_parts[1:], start=1) if token.lower() in status_tokens), None)
        if status_index is None:
            continue
        status = raw_parts[status_index]
        vlan = raw_parts[status_index + 1] if len(raw_parts) > status_index + 1 else None
        entries.append(
            {
                "port": port,
                "status": status,
                "vlan": vlan,
                "raw": line.strip(),
            }
        )
    return entries


def parse_show_ip_interface_brief(text: str) -> list[dict]:
    lines = _clean_lines(text)
    entries = []
    for line in lines:
        if line.lower().startswith("interface"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue

        status_start = 2
        if len(parts) >= 6 and parts[2].upper() in {"YES", "NO"}:
            status_start = 4

        status = " ".join(parts[status_start:-1]).strip()
        if not status:
            continue

        entries.append(
            {
                "interface": parts[0],
                "ip_address": parts[1],
                "status": status,
                "protocol": parts[-1],
                "raw": line.strip(),
            }
        )
    return entries


def parse_show_vlan_brief(text: str) -> list[dict]:
    lines = _clean_lines(text)
    entries = []
    for line in lines:
        if line.lower().startswith("vlan") or line.startswith("----"):
            continue
        match = re.match(r"^(\d+)\s+(\S+)\s+(\S+)", line.strip())
        if not match:
            continue
        entries.append(
            {
                "vlan_id": match.group(1),
                "name": match.group(2),
                "status": match.group(3),
                "raw": line.strip(),
            }
        )
    return entries


def parse_show_mac_address_table(text: str) -> list[dict]:
    lines = _clean_lines(text)
    entries = []
    mac_re = re.compile(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b")
    for line in lines:
        mac_match = mac_re.search(line)
        if not mac_match:
            continue
        parts = line.split()
        port = parts[-1] if parts else None
        vlan = None
        for token in parts:
            if token.isdigit():
                vlan = token
                break
        entries.append(
            {
                "mac": mac_match.group(0).lower(),
                "vlan": vlan,
                "port": port,
                "raw": line.strip(),
            }
        )
    return entries


def parse_show_cdp_neighbors_detail(text: str) -> list[dict]:
    blocks = [block.strip() for block in text.split("-------------------------") if block.strip()]
    entries = []
    for block in blocks:
        device = None
        local = None
        remote = None
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith("Device ID:"):
                device = stripped.split(":", 1)[1].strip()
            if "Interface:" in stripped and "Port ID" in stripped:
                match = re.search(r"Interface:\s*([^,]+),\s*Port ID .*?:\s*(.+)$", stripped)
                if match:
                    local = match.group(1).strip()
                    remote = match.group(2).strip()
        entries.append({"device_id": device, "local_interface": local, "remote_port": remote, "raw": block})
    return entries
