from agent.skills.ssh_diagnostics import run_remote_ssh_diagnostic_on_session

from .common import display_interface_name, filter_by_interface, normalize_interface_name


def _combine_step_statuses(*step_results: dict) -> str:
    statuses = [step.get("status") for step in step_results if step.get("status")]
    if not statuses:
        return "ok"
    if all(status == "ok" for status in statuses):
        return "ok"
    for preferred in ("ssh_auth_failed", "ssh_failed"):
        if preferred in statuses:
            return preferred
    return next(status for status in statuses if status != "ok")


def _interface_log_tokens(interface_name: str) -> set[str]:
    compact = str(interface_name or "").strip().replace(" ", "")
    normalized = normalize_interface_name(compact)
    tokens = {compact.lower(), normalized}
    expansions = {
        "gi": "gigabitethernet",
        "te": "tengigabitethernet",
        "tw": "twentyfivegige",
        "fo": "fortygigabitethernet",
        "hu": "hundredgige",
        "fa": "fastethernet",
        "eth": "ethernet",
        "po": "port-channel",
    }
    for short, long in expansions.items():
        if normalized.startswith(short):
            suffix = normalized[len(short) :]
            tokens.add(f"{long}{suffix}")
    return {token for token in tokens if token}


def _filter_logs_for_interface(log_output: str, interface_name: str, limit: int = 5) -> list[str]:
    tokens = _interface_log_tokens(interface_name)
    matches = []
    for line in str(log_output or "").splitlines():
        lowered = line.lower().replace(" ", "")
        if any(token in lowered for token in tokens):
            matches.append(line.strip())
        if len(matches) >= limit:
            break
    return matches


def _is_interface_down(status: str, l3_status: str = "", l3_protocol: str = "") -> bool:
    status = status.lower()
    l3_status = l3_status.lower()
    l3_protocol = l3_protocol.lower()
    if status in {"connected", "up"}:
        return False
    if status in {"notconnect", "down", "inactive", "disabled", "err-disabled", "administratively down"}:
        return True
    return l3_status == "down" or l3_protocol == "down"


def _possible_interface_down_reasons(
    status: str,
    has_neighbors: bool,
    has_mac_entries: bool,
    is_down: bool,
    interface_found: bool = True,
) -> list[str]:
    if not interface_found:
        return ["interface was not found in the current device output"]
    if not is_down:
        return ["current evidence does not show the interface is down"]
    status = status.lower()
    if status in {"notconnect", "down"}:
        reasons = ["cable/SFP/patch path disconnected", "endpoint powered off or NIC down"]
        if not has_neighbors:
            reasons.append("no neighbor device active on the link")
        if not has_mac_entries:
            reasons.append("no traffic seen from an attached device")
        return reasons[:4]
    if status in {"disabled", "administratively down"}:
        return ["interface is administratively disabled"]
    if status == "err-disabled":
        return ["port is error-disabled; check logs for the trigger"]
    return ["interface state is not healthy; compare physical link, endpoint, and recent logs"]


def _interface_down_recommendations(status: str, is_down: bool, interface_found: bool = True) -> list[str]:
    if not interface_found:
        return ["Verify the interface name and platform syntax, then list interfaces with show interface status."]
    if not is_down:
        return ["Treat this as not currently down; investigate performance, VLAN, or endpoint symptoms only if users still report impact."]
    status = status.lower()
    if status in {"notconnect", "down"}:
        return [
            "Check cable/SFP/patch panel and endpoint power/NIC.",
            "Verify the port/VLAN assignment matches the intended device.",
        ]
    if status in {"disabled", "administratively down"}:
        return ["Have an authorized operator confirm whether the port should be enabled."]
    if status == "err-disabled":
        return ["Review filtered logs and fix the root cause before any reset."]
    return ["Validate physical layer first, then compare config and neighbor/MAC evidence."]


def run_cisco_uplink_health_playbook(client, host: str, user: str, platform_key: str | None = None) -> dict:
    interface_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show interfaces", platform_key=platform_key
    )
    neighbor_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show neighbors", platform_key=platform_key
    )
    return {
        "skill": "cisco_uplink_health_playbook",
        "host": host,
        "user": user,
        "platform_key": platform_key,
        "status": _combine_step_statuses(interface_result, neighbor_result),
        "steps": {"interfaces": interface_result, "neighbors": neighbor_result},
        "summary": "Checked interface status and neighbor visibility for uplink-oriented troubleshooting.",
    }


def run_cisco_mac_lookup_playbook(client, host: str, user: str, mac: str, platform_key: str | None = None) -> dict:
    mac_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show mac table", platform_key=platform_key
    )
    parsed = ((mac_result.get("result") or {}).get("parsed") or {}).get("mac_table", [])
    normalized = mac.lower().replace(":", "").replace("-", "")
    matches = [entry for entry in parsed if entry.get("mac", "").replace(".", "") == normalized]
    return {
        "skill": "cisco_mac_lookup_playbook",
        "host": host,
        "user": user,
        "platform_key": platform_key,
        "status": _combine_step_statuses(mac_result),
        "mac": mac,
        "matches": matches,
        "steps": {"mac_table": mac_result},
        "summary": f"Found {len(matches)} matching MAC table entries for {mac}.",
    }


def run_cisco_interface_mac_table_playbook(
    client,
    host: str,
    user: str,
    interface_name: str,
    platform_key: str | None = None,
) -> dict:
    mac_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show mac table", platform_key=platform_key
    )
    parsed = ((mac_result.get("result") or {}).get("parsed") or {}).get("mac_table", [])
    matches = filter_by_interface(parsed, "port", interface_name=interface_name)
    display_name = display_interface_name(interface_name)
    return {
        "skill": "cisco_interface_mac_table_playbook",
        "host": host,
        "user": user,
        "platform_key": platform_key,
        "status": _combine_step_statuses(mac_result),
        "interface": interface_name,
        "matches": matches,
        "steps": {"mac_table": mac_result},
        "summary": f"Found {len(matches)} MAC table entr{'y' if len(matches) == 1 else 'ies'} on {display_name}.",
    }


def run_cisco_vlan_check_playbook(client, host: str, user: str, vlan_id: str, platform_key: str | None = None) -> dict:
    vlan_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show vlans", platform_key=platform_key
    )
    parsed = ((vlan_result.get("result") or {}).get("parsed") or {}).get("vlans", [])
    matches = [entry for entry in parsed if entry.get("vlan_id") == str(vlan_id)]
    return {
        "skill": "cisco_vlan_check_playbook",
        "host": host,
        "user": user,
        "platform_key": platform_key,
        "status": _combine_step_statuses(vlan_result),
        "vlan_id": str(vlan_id),
        "matches": matches,
        "steps": {"vlans": vlan_result},
        "summary": f"Found {len(matches)} matching VLAN entries for VLAN {vlan_id}.",
    }


def run_cisco_interface_check_playbook(
    client,
    host: str,
    user: str,
    interface_name: str,
    platform_key: str | None = None,
) -> dict:
    interface_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show interfaces", platform_key=platform_key
    )
    ip_interface_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show ip interfaces", platform_key=platform_key
    )
    neighbor_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show neighbors", platform_key=platform_key
    )
    mac_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show mac table", platform_key=platform_key
    )

    interface_entries = filter_by_interface(
        ((interface_result.get("result") or {}).get("parsed") or {}).get("interfaces", []),
        "port",
        interface_name=interface_name,
    )
    ip_entries = filter_by_interface(
        ((ip_interface_result.get("result") or {}).get("parsed") or {}).get("ip_interfaces", []),
        "interface",
        interface_name=interface_name,
    )
    neighbor_entries = filter_by_interface(
        ((neighbor_result.get("result") or {}).get("parsed") or {}).get("neighbors", []),
        "local_interface",
        interface_name=interface_name,
    )
    mac_entries = filter_by_interface(
        ((mac_result.get("result") or {}).get("parsed") or {}).get("mac_table", []),
        "port",
        interface_name=interface_name,
    )

    status_bits = []
    if interface_entries:
        status_bits.append(f"switchport status {interface_entries[0].get('status')}")
    if ip_entries:
        status_bits.append(f"L3 status {ip_entries[0].get('status')}/{ip_entries[0].get('protocol')}")
    if neighbor_entries:
        neighbor_ports = ", ".join(display_interface_name(entry.get("remote_port")) for entry in neighbor_entries[:2])
        status_bits.append(f"{len(neighbor_entries)} neighbor(s) seen" + (f" via {neighbor_ports}" if neighbor_ports else ""))
    if mac_entries:
        status_bits.append(f"{len(mac_entries)} MAC entry/entries learned")
    summary = (
        f"Interface {interface_name}: " + ", ".join(status_bits)
        if status_bits
        else f"Interface {interface_name}: no matching parsed entries found in current summaries."
    )

    return {
        "skill": "cisco_interface_check_playbook",
        "host": host,
        "user": user,
        "platform_key": platform_key,
        "status": _combine_step_statuses(interface_result, ip_interface_result, neighbor_result, mac_result),
        "interface": interface_name,
        "matches": {
            "interfaces": interface_entries,
            "ip_interfaces": ip_entries,
            "neighbors": neighbor_entries,
            "mac_table": mac_entries,
        },
        "steps": {
            "interfaces": interface_result,
            "ip_interfaces": ip_interface_result,
            "neighbors": neighbor_result,
            "mac_table": mac_result,
        },
        "summary": summary,
    }


def run_cisco_interface_down_playbook(
    client,
    host: str,
    user: str,
    interface_name: str,
    platform_key: str | None = None,
) -> dict:
    result = run_cisco_interface_check_playbook(
        client, host=host, user=user, interface_name=interface_name, platform_key=platform_key
    )
    log_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show logs", platform_key=platform_key
    )
    matches = result.get("matches", {})
    interface_entries = matches.get("interfaces", [])
    ip_entries = matches.get("ip_interfaces", [])
    neighbor_entries = matches.get("neighbors", [])
    mac_entries = matches.get("mac_table", [])

    observations = []
    if interface_entries:
        status = str(interface_entries[0].get("status", "unknown")).lower()
        vlan = interface_entries[0].get("vlan")
        observations.append(f"switchport state is {status}")
        if vlan:
            observations.append(f"VLAN field shows {vlan}")
        if status in {"down", "notconnect", "inactive", "disabled", "err-disabled"}:
            observations.append("link appears down from switchport status")
    else:
        observations.append("interface not present in interface status summary")

    if ip_entries:
        observations.append(f"L3 state is {ip_entries[0].get('status')}/{ip_entries[0].get('protocol')}")
    if neighbor_entries:
        observations.append(f"CDP sees {len(neighbor_entries)} neighbor(s)")
    else:
        observations.append("no CDP neighbor seen on that interface")
    if mac_entries:
        observations.append(f"MAC table has {len(mac_entries)} learned entry/entries on that port")
    else:
        observations.append("no MAC addresses currently learned on that port")

    log_stdout = ((log_result.get("result") or {}).get("stdout")) or ""
    log_matches = _filter_logs_for_interface(log_stdout, interface_name)
    if log_matches:
        observations.append(f"{len(log_matches)} related log line(s) found")
    else:
        observations.append("no related log lines found in current buffer")

    status = str((interface_entries[0] if interface_entries else {}).get("status", "unknown"))
    l3_status = str((ip_entries[0] if ip_entries else {}).get("status", "unknown"))
    l3_protocol = str((ip_entries[0] if ip_entries else {}).get("protocol", "unknown"))
    interface_found = bool(interface_entries or ip_entries)
    is_down = _is_interface_down(status, l3_status, l3_protocol) if interface_found else False
    result["skill"] = "cisco_interface_down_playbook"
    result["interface_found"] = interface_found
    result["interface_is_down"] = is_down
    result["observations"] = observations
    result["log_matches"] = log_matches
    result["possible_reasons"] = _possible_interface_down_reasons(
        status,
        has_neighbors=bool(neighbor_entries),
        has_mac_entries=bool(mac_entries),
        is_down=is_down,
        interface_found=interface_found,
    )
    result["recommendations"] = _interface_down_recommendations(status, is_down, interface_found)
    result.setdefault("steps", {})["logs"] = log_result
    result["status"] = _combine_step_statuses(result, log_result)
    result["summary"] = f"Interface {interface_name} troubleshooting: " + "; ".join(observations) + "."
    return result
