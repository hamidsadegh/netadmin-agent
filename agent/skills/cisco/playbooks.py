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


def _filter_lines_for_interface(output: str, interface_name: str, limit: int = 5) -> list[str]:
    tokens = _interface_log_tokens(interface_name)
    matches = []
    for line in str(output or "").splitlines():
        lowered = line.lower().replace(" ", "")
        if any(token in lowered for token in tokens):
            matches.append(line.strip())
        if len(matches) >= limit:
            break
    return matches


def _find_port_channel_memberships(port_channels: list[dict], interface_name: str) -> list[dict]:
    wanted = normalize_interface_name(interface_name)
    matches = []
    for entry in port_channels:
        for member in entry.get("members", []):
            if normalize_interface_name(member.get("interface")) == wanted:
                matches.append({**entry, "matched_member": member})
                break
    return matches


def _find_entries_by_port(entries: list[dict], interface_name: str) -> list[dict]:
    wanted = normalize_interface_name(interface_name)
    return [entry for entry in entries if normalize_interface_name(entry.get("port")) == wanted]


def _port_channel_health(memberships: list[dict]) -> str:
    if not memberships:
        return "not a parsed port-channel member"
    member_flags = [str(entry.get("matched_member", {}).get("flags", "")) for entry in memberships]
    if all("P" in flags for flags in member_flags):
        return "bundled"
    if any(flag for flags in member_flags for flag in flags if flag in {"s", "D", "I", "H", "M", "w"}):
        return "not bundled"
    return "unknown"


def _parse_vlan_list(value: str | None) -> set[int] | None:
    text = str(value or "").strip().lower()
    if not text or text in {"none", "-", "n/a"}:
        return set()
    if text in {"all", "1-4094"}:
        return set(range(1, 4095))

    vlans = set()
    for token in text.replace(" ", "").split(","):
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if start_text.isdigit() and end_text.isdigit():
                start = max(1, int(start_text))
                end = min(4094, int(end_text))
                if start <= end:
                    vlans.update(range(start, end + 1))
            continue
        if token.isdigit():
            vlan_id = int(token)
            if 1 <= vlan_id <= 4094:
                vlans.add(vlan_id)
    return vlans


def _summarize_vlan_delta(left: set[int], right: set[int], limit: int = 8) -> str:
    values = sorted(left - right)
    if not values:
        return "none"
    preview = ", ".join(str(vlan_id) for vlan_id in values[:limit])
    return preview if len(values) <= limit else f"{preview}, +{len(values) - limit} more"


def _analyze_trunk_vlans(trunk_entries: list[dict], is_trunk: bool) -> dict:
    if not trunk_entries:
        return {
            "status": "missing" if is_trunk else "not_trunking",
            "observations": ["no trunk allowance entry matched the interface"],
            "risks": ["trunk allowance could not be verified from show interface trunk"] if is_trunk else [],
        }

    trunk = trunk_entries[0]
    status = str(trunk.get("status", "")).lower()
    allowed = _parse_vlan_list(trunk.get("allowed_vlans"))
    active = _parse_vlan_list(trunk.get("active_vlans"))
    forwarding = _parse_vlan_list(trunk.get("forwarding_vlans"))
    observations = []
    risks = []

    if status:
        observations.append(f"trunk command reports status {status}")
        if status != "trunking":
            risks.append("interface is present in trunk output but is not trunking")
    if trunk.get("native_vlan"):
        observations.append(f"native VLAN is {trunk.get('native_vlan')}")
    if trunk.get("allowed_vlans"):
        observations.append(f"allowed VLANs are {trunk.get('allowed_vlans')}")
    if trunk.get("active_vlans"):
        observations.append(f"allowed-and-active VLANs are {trunk.get('active_vlans')}")
    if trunk.get("forwarding_vlans"):
        observations.append(f"STP forwarding/not-pruned VLANs are {trunk.get('forwarding_vlans')}")

    if allowed is not None and active is not None:
        active_not_allowed = active - allowed
        allowed_not_active = allowed - active
        if active_not_allowed:
            risks.append(f"active VLANs not allowed on trunk: {_summarize_vlan_delta(active, allowed)}")
        if allowed and active and allowed_not_active:
            observations.append(f"allowed VLANs not active locally include {_summarize_vlan_delta(allowed, active)}")
    if active is not None and forwarding is not None:
        active_not_forwarding = active - forwarding
        if active_not_forwarding:
            risks.append(f"allowed active VLANs not forwarding or pruned by STP: {_summarize_vlan_delta(active, forwarding)}")

    return {"status": "attention" if risks else "ok", "entry": trunk, "observations": observations, "risks": risks}


def _filter_vpc_lines(vpc_output: str, targets: list[str], limit: int = 8) -> list[str]:
    token_sets = [_interface_log_tokens(target) for target in targets if target]
    matches = []
    for line in str(vpc_output or "").splitlines():
        compact = line.lower().replace(" ", "")
        if any(any(token in compact for token in tokens) for tokens in token_sets):
            matches.append(line.strip())
        if len(matches) >= limit:
            break
    return matches


def _analyze_vpc(vpc_result: dict, targets: list[str]) -> dict:
    parsed = ((vpc_result.get("result") or {}).get("parsed") or {}).get("vpc") or {}
    output = ((vpc_result.get("result") or {}).get("stdout")) or ""
    target_lines = _filter_vpc_lines(output, targets)
    observations = []
    risks = []

    for key, label in (
        ("peer_status", "peer status"),
        ("keepalive_status", "keepalive"),
        ("peer_link_status", "peer-link"),
    ):
        value = parsed.get(key)
        if value:
            observations.append(f"vPC {label}: {value}")
            lowered = str(value).lower()
            if any(term in lowered for term in ("down", "not ok", "failed", "not operational", "suspended")):
                risks.append(f"vPC {label} is unhealthy: {value}")

    wanted = {normalize_interface_name(target) for target in targets if target}
    matched_vpcs = [
        entry
        for entry in parsed.get("vpcs", [])
        if normalize_interface_name(entry.get("port_channel")) in wanted
    ]
    for entry in matched_vpcs:
        observations.append(
            f"vPC {entry.get('id')} {display_interface_name(entry.get('port_channel'))} status {entry.get('status')} consistency {entry.get('consistency')}"
        )
        if str(entry.get("status", "")).lower() != "up":
            risks.append(f"vPC {entry.get('id')} is not up")
        if str(entry.get("consistency", "")).lower() not in {"success", "successful", "ok"}:
            risks.append(f"vPC {entry.get('id')} consistency is {entry.get('consistency')}")
    if target_lines and not matched_vpcs:
        observations.append(f"{len(target_lines)} vPC line(s) mention the uplink target")

    return {
        "status": "attention" if risks else "ok",
        "matches": matched_vpcs,
        "lines": target_lines,
        "observations": observations,
        "risks": risks,
    }


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


def run_cisco_trunk_uplink_playbook(
    client,
    host: str,
    user: str,
    interface_name: str,
    platform_key: str | None = None,
) -> dict:
    interface_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show interfaces", platform_key=platform_key
    )
    neighbor_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show neighbors", platform_key=platform_key
    )
    spanning_tree_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show spanning tree", platform_key=platform_key
    )
    port_channel_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show port-channel", platform_key=platform_key
    )
    trunk_result = run_remote_ssh_diagnostic_on_session(
        client, host=host, user=user, request="show interface trunk", platform_key=platform_key
    )
    vpc_result = None
    if platform_key == "cisco_nxos":
        vpc_result = run_remote_ssh_diagnostic_on_session(
            client, host=host, user=user, request="show vpc", platform_key=platform_key
        )

    interface_entries = filter_by_interface(
        ((interface_result.get("result") or {}).get("parsed") or {}).get("interfaces", []),
        "port",
        interface_name=interface_name,
    )
    neighbor_entries = filter_by_interface(
        ((neighbor_result.get("result") or {}).get("parsed") or {}).get("neighbors", []),
        "local_interface",
        interface_name=interface_name,
    )
    port_channels = ((port_channel_result.get("result") or {}).get("parsed") or {}).get("port_channels", [])
    port_channel_matches = _find_port_channel_memberships(port_channels, interface_name)
    stp_output = ((spanning_tree_result.get("result") or {}).get("stdout")) or ""
    stp_lines = _filter_lines_for_interface(stp_output, interface_name)
    trunk_entries = _find_entries_by_port(
        ((trunk_result.get("result") or {}).get("parsed") or {}).get("interface_trunks", []),
        interface_name,
    )

    display_name = display_interface_name(interface_name)
    interface_status = str((interface_entries[0] if interface_entries else {}).get("status", "unknown")).lower()
    vlan_field = str((interface_entries[0] if interface_entries else {}).get("vlan", "unknown")).lower()
    is_trunk = vlan_field == "trunk"
    is_connected = interface_status in {"connected", "up"}
    bundle_health = _port_channel_health(port_channel_matches)
    trunk_vlan_analysis = _analyze_trunk_vlans(trunk_entries, is_trunk=is_trunk)
    port_channel_targets = [entry.get("port_channel") for entry in port_channel_matches if entry.get("port_channel")]
    vpc_analysis = _analyze_vpc(vpc_result, [interface_name, *port_channel_targets]) if vpc_result else None

    observations = []
    if interface_entries:
        observations.append(f"switchport state is {interface_status} with VLAN field {vlan_field}")
    else:
        observations.append("interface not present in interface status summary")
    observations.append("interface is shown as a trunk" if is_trunk else "interface is not shown as a trunk")
    if neighbor_entries:
        observations.append(f"CDP sees {len(neighbor_entries)} neighbor(s) on the link")
    else:
        observations.append("no CDP neighbor seen on the link")
    if stp_lines:
        observations.append(f"{len(stp_lines)} spanning-tree line(s) mention the interface")
    else:
        observations.append("no spanning-tree lines matched the interface")
    observations.append(f"port-channel membership is {bundle_health}")
    observations.extend(trunk_vlan_analysis.get("observations", []))
    if vpc_analysis:
        observations.extend(vpc_analysis.get("observations", []))

    risks = []
    if not interface_entries:
        risks.append("interface was not found in parsed interface status output")
    if interface_entries and not is_connected:
        risks.append("uplink is not connected")
    if interface_entries and not is_trunk:
        risks.append("uplink is not currently listed as trunk")
    if not neighbor_entries:
        risks.append("expected upstream/downstream neighbor is not visible via CDP")
    if bundle_health == "not bundled":
        risks.append("interface appears in a port-channel but is not bundled")
    if not stp_lines:
        risks.append("STP evidence for this interface was not found in current output")
    risks.extend(trunk_vlan_analysis.get("risks", []))
    if vpc_analysis:
        risks.extend(vpc_analysis.get("risks", []))

    recommendations = []
    if not interface_entries:
        recommendations.append("Verify the interface name and platform syntax, then list interfaces with show interface status.")
    if interface_entries and not is_connected:
        recommendations.append("Check physical link/SFP/cabling before changing any trunk or bundle configuration.")
    if interface_entries and not is_trunk:
        recommendations.append("Compare intended trunk design with the running configuration before any change.")
    if bundle_health == "not bundled":
        recommendations.append("Check the peer bundle state and LACP/PAgP compatibility on both ends.")
    if trunk_vlan_analysis.get("risks"):
        recommendations.append("Compare allowed, active, and STP-forwarding VLAN lists with the intended uplink design on both peers.")
    if vpc_analysis and vpc_analysis.get("risks"):
        recommendations.append("For NX-OS vPC uplinks, check peer-link, keepalive, vPC consistency, and the peer port-channel state before any change.")
    if not neighbor_entries:
        recommendations.append("Confirm the peer has CDP enabled or use an approved neighbor source for that platform.")
    if not recommendations:
        recommendations.append("Evidence is healthy; compare VLAN allowance/STP root placement only if symptoms persist.")
    step_results = [interface_result, neighbor_result, spanning_tree_result, port_channel_result, trunk_result]
    if vpc_result:
        step_results.append(vpc_result)

    return {
        "skill": "cisco_trunk_uplink_playbook",
        "host": host,
        "user": user,
        "platform_key": platform_key,
        "status": _combine_step_statuses(*step_results),
        "interface": interface_name,
        "assessment": "attention" if risks else "healthy",
        "matches": {
            "interfaces": interface_entries,
            "neighbors": neighbor_entries,
            "spanning_tree": stp_lines,
            "port_channels": port_channel_matches,
            "interface_trunks": trunk_entries,
            "vpc": vpc_analysis if vpc_analysis else None,
        },
        "trunk_vlan_analysis": trunk_vlan_analysis,
        "vpc_analysis": vpc_analysis,
        "observations": observations,
        "risks": risks,
        "recommendations": recommendations,
        "steps": {
            "interfaces": interface_result,
            "neighbors": neighbor_result,
            "spanning_tree": spanning_tree_result,
            "port_channel": port_channel_result,
            "interface_trunk": trunk_result,
            **({"vpc": vpc_result} if vpc_result else {}),
        },
        "summary": f"Trunk/uplink {display_name}: " + "; ".join(observations) + ".",
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
