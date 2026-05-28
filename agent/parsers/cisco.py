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


def parse_show_port_channel_summary(text: str) -> list[dict]:
    lines = _clean_lines(text)
    entries = []
    port_channel_re = re.compile(r"\b(Po\d+)\(([^)]*)\)", re.IGNORECASE)
    member_re = re.compile(
        r"\b((?:Gi|GigabitEthernet|Te|TenGigabitEthernet|Tw|TwentyFiveGigE|Fo|FortyGigabitEthernet|Hu|HundredGigE|Eth|Ethernet|Fa|FastEthernet)\S*)\(([^)]*)\)",
        re.IGNORECASE,
    )

    for line in lines:
        port_channel_match = port_channel_re.search(line)
        if not port_channel_match:
            continue
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue

        protocol = None
        for token in parts:
            if token.upper() in {"LACP", "PAGP", "NONE", "-"}:
                protocol = token
                break

        entries.append(
            {
                "group": parts[0],
                "port_channel": port_channel_match.group(1),
                "flags": port_channel_match.group(2),
                "protocol": protocol,
                "members": [
                    {"interface": match.group(1), "flags": match.group(2)}
                    for match in member_re.finditer(line)
                ],
                "raw": line.strip(),
            }
        )
    return entries


def parse_show_interfaces_trunk(text: str) -> list[dict]:
    lines = _clean_lines(text)
    entries: dict[str, dict] = {}
    section = None
    status_header_re = re.compile(r"\bstatus\b.*\bnative\s+vlan\b", re.IGNORECASE)

    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if set(stripped) <= {"-"}:
            continue
        if status_header_re.search(lowered) or (lowered.startswith("port") and "native" in lowered and "status" in lowered):
            section = "status"
            continue
        if "vlans allowed on trunk" in lowered or "vlans allowed and active" in lowered:
            section = "allowed_active" if "active" in lowered else "allowed"
            continue
        if "spanning tree forwarding" in lowered or "stp forwarding" in lowered:
            section = "forwarding"
            continue
        if lowered.startswith("port ") or lowered.startswith("vlan ") or lowered in {"port", "vlan"}:
            continue

        parts = stripped.split()
        if len(parts) < 2 or not re.match(r"^[A-Za-z]+[A-Za-z0-9/.-]+\b", parts[0]):
            continue

        port = parts[0]
        entry = entries.setdefault(port, {"port": port, "raw_lines": []})
        entry["raw_lines"].append(line.strip())
        if section == "status":
            if len(parts) >= 5:
                entry.update(
                    {
                        "mode": parts[1],
                        "encapsulation": parts[2],
                        "status": parts[3],
                        "native_vlan": parts[4],
                    }
                )
            elif len(parts) >= 3:
                entry.update({"native_vlan": parts[1], "status": parts[2]})
                if len(parts) >= 4:
                    entry["port_channel"] = parts[3]
        elif section == "allowed":
            entry["allowed_vlans"] = parts[1]
        elif section == "allowed_active":
            entry["active_vlans"] = parts[1]
        elif section == "forwarding":
            entry["forwarding_vlans"] = parts[1]

    return list(entries.values())


def parse_show_vpc(text: str) -> dict:
    lines = _clean_lines(text)
    result = {"peer_status": None, "keepalive_status": None, "peer_link_status": None, "vpcs": [], "raw_lines": []}
    in_vpc_table = False
    vpc_row_re = re.compile(r"^(\d+)\s+(Po\d+)\s+(\S+)\s+(\S+)\s*(.*)$", re.IGNORECASE)

    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        result["raw_lines"].append(stripped)
        if lowered.startswith("peer status"):
            result["peer_status"] = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
        elif lowered.startswith("peer keep-alive status") or lowered.startswith("peer keepalive status"):
            result["keepalive_status"] = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
        elif lowered.startswith("vpc peer-link status"):
            result["peer_link_status"] = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
        elif lowered.startswith("id ") and "port" in lowered and "status" in lowered:
            in_vpc_table = True
            continue

        if in_vpc_table:
            match = vpc_row_re.match(stripped)
            if match:
                result["vpcs"].append(
                    {
                        "id": match.group(1),
                        "port_channel": match.group(2),
                        "status": match.group(3),
                        "consistency": match.group(4),
                        "reason": match.group(5).strip(),
                        "raw": stripped,
                    }
                )

    return result


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
