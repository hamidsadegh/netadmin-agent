import json
from pathlib import Path

from agent.skills.cisco.common import display_interface_name
from agent.tools import get_supported_intents

IDENTITY_FILE = Path(__file__).resolve().parents[2] / "IDENTITY.md"


PLATFORM_EXAMPLES = {
    "cisco_ios": [
        "show version",
        "show interfaces status",
        "check trunk uplink Gi1/0/1",
        "troubleshoot interface Gi1/0/1",
        "why is Gi1/0/1 down?",
        "mac table for int Gi1/0/1",
        "find mac 0011.2233.4455",
        "check vlan 10",
        "show neighbors",
        "show logs",
    ],
    "cisco_ios_xe": [
        "show version",
        "show interfaces status",
        "check trunk uplink Gi1/0/1",
        "troubleshoot interface Gi1/0/1",
        "why is Gi1/0/1 down?",
        "mac table for int Gi1/0/1",
        "find mac 0011.2233.4455",
        "check vlan 10",
        "show neighbors",
        "show logs",
    ],
    "cisco_nxos": [
        "show version",
        "show interface status",
        "check trunk uplink Eth1/1",
        "troubleshoot interface Eth1/1",
        "why is Eth1/1 down?",
        "mac table for int Eth1/1",
        "find mac 0011.2233.4455",
        "check vlan 10",
        "show neighbors",
        "show logs",
    ],
}


def _read_identity_file() -> str:
    try:
        return IDENTITY_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return (
            "# NetAdmin Agent Identity\n\n"
            "I am NetAdmin Agent, a safety-focused network administration assistant "
            "for read-only diagnostics."
        )


def _strip_markdown_heading(line: str) -> str:
    return line.lstrip("#").strip()


def format_identity_response(session: dict | None = None) -> str:
    identity = _read_identity_file()
    lines = []
    for line in identity.splitlines():
        if line.startswith("# "):
            lines.append(_strip_markdown_heading(line))
        elif line.startswith("## "):
            lines.extend(["", _strip_markdown_heading(line) + ":"])
        else:
            lines.append(line)

    if session:
        platform_key = session.get("platform_key") or "unknown"
        lines.extend(
            [
                "",
                "Current session:",
                f"- Target: {session.get('user')}@{session.get('host')}:{session.get('port') or 22}",
                f"- Platform: {platform_key}",
                f"- Mode: {session.get('session_mode') or 'unknown'}",
            ]
        )
        supported_intents = get_supported_intents(session.get("platform_key"))
        if supported_intents:
            lines.append(f"- Supported intents now: {', '.join(supported_intents)}")

    return "\n".join(lines).strip()


def format_help_response(session: dict | None = None, mode: str = "agent") -> str:
    lines = [
        "NetAdmin Agent Help",
        "",
        "Modes:",
        "- agent mode: ask troubleshooting questions and run safe playbooks.",
        "- ssh mode: send read-only commands directly to the active SSH device.",
        "",
        "Mode commands:",
        "- ssh mode",
        "- agent mode",
        "- exit",
    ]

    if session:
        platform_key = session.get("platform_key") or "unknown"
        target = f"{session.get('user')}@{session.get('host')}:{session.get('port') or 22}"
        lines.extend(
            [
                "",
                "Current session:",
                f"- Target: {target}",
                f"- Platform: {platform_key}",
                f"- Current mode: {mode}",
            ]
        )
        supported_intents = get_supported_intents(session.get("platform_key"))
        if supported_intents:
            lines.extend(["", "Agent abilities:", "- " + ", ".join(supported_intents)])
        examples = PLATFORM_EXAMPLES.get(platform_key, [])
        if examples:
            lines.extend(["", "Examples:", *(f"- {example}" for example in examples[:8])])
    else:
        lines.extend(
            [
                "",
                "Examples:",
                "- check 192.168.178.49",
                "- scan 192.168.178.0/24",
                "- connect to 127.0.0.1:2222 with user admin",
                "- list all scanned hosts",
            ]
        )

    lines.extend(
        [
            "",
            "More:",
            "- who are you?",
            "- session info",
            "- what can I do on this platform?",
        ]
    )
    return "\n".join(lines)


def format_result_for_fallback(result: dict) -> str:
    if isinstance(result, dict) and result.get("skill") == "run_remote_ssh_diagnostic":
        ssh = result.get("result", {})
        host = result.get("host")
        port = result.get("port") or ssh.get("port")
        user = result.get("user")
        status = result.get("status")
        command = ssh.get("command")
        stdout_text = ssh.get("cleaned_stdout") or "(no stdout)"
        stderr_text = ssh.get("cleaned_stderr")
        error_text = ssh.get("error")

        platform_key = result.get("platform_key") or ssh.get("platform_key")
        summary = ssh.get("summary")
        lines = [f"SSH {status}: {user}@{host}{':' + str(port) if port and int(port) != 22 else ''}"]
        if platform_key:
            lines.append(f"Platform: {platform_key}")
        lines.append(f"Command: {command}")
        if summary:
            lines.extend(["", "Summary:", summary])
        lines.extend(["", "Output:", stdout_text])

        if stderr_text:
            lines.extend(["", "Stderr:", stderr_text])
        if error_text:
            lines.extend(["", "Error:", str(error_text)])

        return "\n".join(lines)

    if isinstance(result, dict) and result.get("skill") == "discover_network_hosts":
        cidr = result.get("cidr")
        ports = result.get("ports")
        status = result.get("status")
        host_count = result.get("host_count", 0)
        checks = result.get("checks", {})
        compare = checks.get("compare", {})
        new_hosts = compare.get("new_hosts", [])
        disappeared_hosts = compare.get("disappeared_hosts", [])
        changed_hosts = compare.get("changed_hosts", [])

        scanner = result.get("scanner")
        scan_profile = result.get("scan_profile")
        service_detection = result.get("service_detection")
        service_scan = checks.get("service_scan", {})
        lines = [f"Network scan {status}: {cidr}"]
        if scanner:
            lines.append(f"Scanner: {scanner}")
        if scan_profile:
            lines.append(f"Scan profile: {scan_profile}")
        if service_detection:
            lines.append(f"Service detection: {service_detection}")
        lines.append(f"Ports: {ports}" if ports else "Ports: ping-only")
        lines.append(f"Hosts found: {host_count}")

        if new_hosts or disappeared_hosts or changed_hosts:
            lines.extend(["", "Inventory changes:", f"- new: {len(new_hosts)}", f"- disappeared: {len(disappeared_hosts)}", f"- changed: {len(changed_hosts)}"])

        if host_count:
            hosts = result.get("hosts", {})
            preview = []
            for ip in sorted(hosts)[:10]:
                info = hosts.get(ip, {})
                hostname = info.get("hostname")
                rendered_ports = []
                for item in info.get("ports", []):
                    port_text = str(item.get("port"))
                    service_bits = [item.get("service"), item.get("product"), item.get("version")]
                    service_text = " ".join(bit for bit in service_bits if bit)
                    if service_text:
                        port_text = f"{port_text}/{service_text}"
                    rendered_ports.append(port_text)
                port_list = ", ".join(rendered_ports) or "none"
                suffix = f" ({hostname})" if hostname else ""
                preview.append(f"- {ip}{suffix} ports: {port_list}")
            lines.extend(["", "Hosts:", *preview])
            if len(result.get("hosts", {})) > 10:
                lines.append(f"- ... and {len(result.get('hosts', {})) - 10} more")

        warnings = list(checks.get("warnings", []))
        recommendation = None
        for label, scan in (("ICMP", checks.get("icmp_scan", {})), ("Port scan", checks.get("port_scan", {})), ("Service detection", service_scan)):
            stderr_text = (scan.get("stderr") or "").strip()
            error_text = scan.get("error")
            if error_text:
                warnings.append(f"{label}: {error_text}")
            elif stderr_text and ("fail" in stderr_text.lower() or "permission denied" in stderr_text.lower()):
                interesting_lines = []
                for line in stderr_text.splitlines():
                    compact = line.strip()
                    if not compact:
                        continue
                    lowered = compact.lower()
                    if any(token in lowered for token in ("fail", "permission denied", "need to sudo", "no such file", "init:")):
                        interesting_lines.append(compact)
                first_line = interesting_lines[0] if interesting_lines else stderr_text.splitlines()[0]
                warnings.append(f"{label}: {first_line}")

                lowered = stderr_text.lower()
                if "permission denied" in lowered or "need to sudo" in lowered:
                    recommendation = "Run the scan with elevated privileges, or switch to an unprivileged connect-scan mode."
                elif "init:" in lowered:
                    recommendation = "Set the correct network interface/source IP before scanning."

        if service_detection and service_scan.get("success") and not service_scan.get("skipped"):
            lines.append(f"Service matches: {service_scan.get('count', 0)} host(s)")

        if status == "ok" and host_count == 0 and not recommendation:
            recommendation = "If you expected results, verify target ownership, routing/firewall reachability, and whether the port is actually exposed."

        if warnings:
            lines.extend(["", "Warnings:", *(f"- {warning}" for warning in warnings)])
        if recommendation:
            lines.extend(["", "Recommended next step:", recommendation])

        return "\n".join(lines)

    if isinstance(result, dict) and result.get("skill") == "check_device_connectivity":
        host = result.get("host")
        status = result.get("status")
        checks = result.get("checks", {})
        ping = checks.get("ping", {})
        ssh = checks.get("ssh", {})
        lines = [
            f"Connectivity {status}: {host}",
            f"- ping reachable: {'yes' if ping.get('reachable') else 'no'}",
            f"- ssh port 22 open: {'yes' if ssh.get('open') else 'no'}",
        ]
        if ping.get("error"):
            lines.append(f"- ping error: {ping.get('error')}")
        if ssh.get("error"):
            lines.append(f"- ssh error: {ssh.get('error')}")
        return "\n".join(lines)

    if isinstance(result, dict) and result.get("skill") == "scan_host_tcp_ports":
        host = result.get("host")
        ports = result.get("ports")
        status = result.get("status")
        checks = result.get("checks", {})
        ping = checks.get("ping", {})
        scan = checks.get("port_scan", {})
        findings = scan.get("findings", [])
        open_ports = ", ".join(str(item.get("port")) for item in findings) or "none"
        lines = [
            f"TCP port scan {status}: {host}",
            f"- ports: {ports}",
            f"- scanned: {scan.get('scanned_count', 0)}",
            f"- requested: {scan.get('requested_count', scan.get('scanned_count', 0))}",
            f"- open: {scan.get('open_count', 0)}",
            f"- ping reachable: {'yes' if ping.get('reachable') else 'no'}",
            f"- open ports: {open_ports}",
        ]
        if scan.get("timed_out_count"):
            lines.append(f"- timed out: {scan.get('timed_out_count')}")
        if scan.get("error"):
            lines.append(f"- scan error: {scan.get('error')}")
        if ping.get("error"):
            lines.append(f"- ping error: {ping.get('error')}")
        return "\n".join(lines)

    return json.dumps(result, indent=2)


def format_scan_memory(scan_result: dict | None) -> str:
    if not scan_result:
        return "No scan results in this session yet. Run a scan first, for example: scan 192.168.178.0/24"

    hosts = scan_result.get("hosts") or {}
    cidr = scan_result.get("cidr") or "unknown scope"
    ports = scan_result.get("ports")
    lines = [
        f"Last Scan Hosts: {cidr}",
        f"Hosts: {len(hosts)}",
        f"Ports: {ports if ports else 'ping-only'}",
    ]
    if not hosts:
        lines.extend(["", "No hosts were found in the last scan."])
        return "\n".join(lines)

    lines.append("")
    for ip in sorted(hosts):
        info = hosts.get(ip, {})
        hostname = info.get("hostname")
        port_entries = []
        for item in info.get("ports", []):
            port = item.get("port")
            if port is None:
                continue
            service = item.get("service")
            state = item.get("state")
            label = str(port)
            if service:
                label = f"{label}/{service}"
            if state and state not in {"open", "unknown"}:
                label = f"{label} {state}"
            port_entries.append(label)
        suffix = f" ({hostname})" if hostname else ""
        ports_text = ", ".join(port_entries) if port_entries else "no open scanned ports"
        alive = "alive" if info.get("alive_icmp") else "seen by port scan"
        lines.append(f"- {ip}{suffix}: {alive}; {ports_text}")
    return "\n".join(lines)


def format_playbook_result(result: dict) -> str:
    if result.get("skill") == "cisco_mac_lookup_playbook":
        mac = result.get("mac") or "MAC"
        matches = result.get("matches") or []
        lines = [
            f"MAC Lookup: {mac}",
            f"Host: {result.get('user')}@{result.get('host')}",
        ]
        if result.get("platform_key"):
            lines.append(f"Platform: {result.get('platform_key')}")
        lines.extend(["", "Findings:", f"- Entries: {len(matches)}", "", "Entries:"])
        if matches:
            lines.extend(
                f"- VLAN {entry.get('vlan', 'unknown')} {entry.get('mac', 'unknown')} {entry.get('type', '').strip() or 'dynamic'} on {display_interface_name(entry.get('port')) or 'unknown'}"
                for entry in matches[:10]
            )
            if len(matches) > 10:
                lines.append(f"- ... and {len(matches) - 10} more")
        else:
            lines.append("- No matching MAC entries found.")
        return "\n".join(lines)

    if result.get("skill") == "cisco_interface_mac_table_playbook":
        interface = display_interface_name(result.get("interface")) or "interface"
        matches = result.get("matches") or []
        lines = [
            f"MAC Table: {interface}",
            f"Host: {result.get('user')}@{result.get('host')}",
        ]
        if result.get("platform_key"):
            lines.append(f"Platform: {result.get('platform_key')}")
        lines.extend(["", "Findings:", f"- Entries: {len(matches)}"])
        if matches:
            lines.extend(["", "Entries:"])
            lines.extend(
                f"- VLAN {entry.get('vlan', 'unknown')} {entry.get('mac', 'unknown')} {entry.get('type', '').strip() or 'dynamic'} on {display_interface_name(entry.get('port')) or interface}"
                for entry in matches[:10]
            )
            if len(matches) > 10:
                lines.append(f"- ... and {len(matches) - 10} more")
        else:
            lines.extend(["", "Entries:", "- No MAC addresses learned on this interface."])
        return "\n".join(lines)

    if result.get("skill") in {"cisco_interface_check_playbook", "cisco_interface_down_playbook"}:
        matches = result.get("matches") or {}
        interfaces = matches.get("interfaces") or []
        ip_interfaces = matches.get("ip_interfaces") or []
        neighbors = matches.get("neighbors") or []
        mac_table = matches.get("mac_table") or []
        interface = display_interface_name(result.get("interface")) or "interface"
        sw = interfaces[0] if interfaces else {}
        l3 = ip_interfaces[0] if ip_interfaces else {}
        interface_found = result.get("interface_found")
        if interface_found is None:
            interface_found = bool(interfaces or ip_interfaces)
        interface_is_down = result.get("interface_is_down")
        if interface_is_down is None:
            sw_status = str(sw.get("status", "")).lower()
            l3_status = str(l3.get("status", "")).lower()
            l3_protocol = str(l3.get("protocol", "")).lower()
            interface_is_down = bool(interface_found) and (
                sw_status in {"notconnect", "down", "inactive", "disabled", "err-disabled"}
                or (sw_status not in {"connected", "up"} and (l3_status == "down" or l3_protocol == "down"))
            )
        assessment = "not found" if not interface_found else ("down" if interface_is_down else "not down")

        lines = [
            f"Troubleshooting: {interface}",
            f"Host: {result.get('user')}@{result.get('host')}",
        ]
        if result.get("platform_key"):
            lines.append(f"Platform: {result.get('platform_key')}")

        lines.extend(
            [
                "",
                "Findings:",
                f"- Assessment: interface is {assessment}",
                f"- Switchport: {display_interface_name(sw.get('port')) or interface}: {sw.get('status', 'not found')} VLAN {sw.get('vlan', 'unknown')}",
                f"- L3 state: {display_interface_name(l3.get('interface')) or interface}: {l3.get('status', 'not found')}/{l3.get('protocol', 'unknown')}",
                f"- Neighbors: {len(neighbors)}",
                f"- MAC entries: {len(mac_table)}",
            ]
        )

        if result.get("skill") == "cisco_interface_down_playbook":
            log_matches = result.get("log_matches") or []
            lines.extend(["", "Logs:"])
            if log_matches:
                lines.extend(f"- {line}" for line in log_matches[:3])
            else:
                lines.append("- No matching log lines for this interface.")

        lines.extend(
            [
                "",
                "Steps:",
                "- Checked interface status, L3 state, neighbors, and MAC table.",
                "- Down means status is down/notconnect/disabled, or L3 is down with no healthy switchport evidence.",
            ]
        )

        if result.get("skill") == "cisco_interface_check_playbook":
            if neighbors:
                neighbor = neighbors[0]
                lines.extend(
                    [
                        "",
                        "Neighbor:",
                        f"- {neighbor.get('device_id', 'unknown')} via {display_interface_name(neighbor.get('remote_port')) or 'unknown'}",
                    ]
                )
            if mac_table:
                lines.extend(
                    [
                        "",
                        "MAC Table:",
                        *(
                            f"- {entry.get('mac', 'unknown')} VLAN {entry.get('vlan', 'unknown')} on {display_interface_name(entry.get('port')) or 'unknown'}"
                            for entry in mac_table[:3]
                        ),
                    ]
                )
            return "\n".join(lines)

        reasons = result.get("possible_reasons") or []
        if reasons:
            lines.extend(["", "Possible Reasons:"])
            lines.extend(f"- {reason}" for reason in reasons[:4])

        recommendations = result.get("recommendations") or []
        if recommendations:
            lines.extend(["", "Recommendations:"])
            lines.extend(f"- {item}" for item in recommendations[:3])
        return "\n".join(lines)

    if result.get("skill") == "cisco_trunk_uplink_playbook":
        matches = result.get("matches") or {}
        interfaces = matches.get("interfaces") or []
        neighbors = matches.get("neighbors") or []
        stp_lines = matches.get("spanning_tree") or []
        port_channels = matches.get("port_channels") or []
        trunk_entries = matches.get("interface_trunks") or []
        vpc_analysis = result.get("vpc_analysis") or matches.get("vpc") or {}
        interface = display_interface_name(result.get("interface")) or "interface"
        sw = interfaces[0] if interfaces else {}
        trunk = trunk_entries[0] if trunk_entries else {}

        lines = [
            f"Trunk/Uplink: {interface}",
            f"Host: {result.get('user')}@{result.get('host')}",
        ]
        if result.get("platform_key"):
            lines.append(f"Platform: {result.get('platform_key')}")
        lines.extend(
            [
                "",
                "Findings:",
                f"- Assessment: {result.get('assessment', 'unknown')}",
                f"- Switchport: {display_interface_name(sw.get('port')) or interface}: {sw.get('status', 'not found')} VLAN {sw.get('vlan', 'unknown')}",
                f"- Neighbors: {len(neighbors)}",
                f"- STP matches: {len(stp_lines)}",
                f"- Port-channel memberships: {len(port_channels)}",
                f"- Trunk allowance entries: {len(trunk_entries)}",
            ]
        )
        if trunk:
            lines.append(
                f"- Allowed VLANs: {trunk.get('allowed_vlans', 'unknown')}; active: {trunk.get('active_vlans', 'unknown')}; forwarding: {trunk.get('forwarding_vlans', 'unknown')}"
            )
        if vpc_analysis:
            lines.append(f"- vPC matches: {len(vpc_analysis.get('matches') or [])}")

        if neighbors:
            lines.extend(["", "Neighbor:"])
            lines.extend(
                f"- {entry.get('device_id', 'unknown')} via {display_interface_name(entry.get('remote_port')) or 'unknown'}"
                for entry in neighbors[:3]
            )
        if port_channels:
            lines.extend(["", "Port-Channel:"])
            lines.extend(
                f"- {display_interface_name(entry.get('port_channel')) or entry.get('port_channel', 'unknown')} flags {entry.get('flags', 'unknown')} member {display_interface_name(entry.get('matched_member', {}).get('interface')) or interface}({entry.get('matched_member', {}).get('flags', 'unknown')})"
                for entry in port_channels[:3]
            )
        if stp_lines:
            lines.extend(["", "Spanning Tree:"])
            lines.extend(f"- {line}" for line in stp_lines[:3])
        if trunk_entries:
            lines.extend(["", "Trunk VLANs:"])
            lines.extend(
                f"- {display_interface_name(entry.get('port')) or interface}: native {entry.get('native_vlan', 'unknown')}, allowed {entry.get('allowed_vlans', 'unknown')}, active {entry.get('active_vlans', 'unknown')}, forwarding {entry.get('forwarding_vlans', 'unknown')}"
                for entry in trunk_entries[:3]
            )
        if vpc_analysis:
            lines.extend(["", "vPC:"])
            vpc_observations = vpc_analysis.get("observations") or []
            vpc_lines = vpc_analysis.get("lines") or []
            if vpc_observations:
                lines.extend(f"- {item}" for item in vpc_observations[:5])
            elif vpc_lines:
                lines.extend(f"- {line}" for line in vpc_lines[:5])
            else:
                lines.append("- No vPC match for this uplink target.")

        risks = result.get("risks") or []
        if risks:
            lines.extend(["", "Risks:"])
            lines.extend(f"- {risk}" for risk in risks[:5])

        recommendations = result.get("recommendations") or []
        if recommendations:
            lines.extend(["", "Recommendations:"])
            lines.extend(f"- {item}" for item in recommendations[:5])
        return "\n".join(lines)

    lines = [f"Playbook: {result.get('skill')}", f"Host: {result.get('user')}@{result.get('host')}"]
    if result.get("platform_key"):
        lines.append(f"Platform: {result.get('platform_key')}")
    if result.get("summary"):
        lines.extend(["", "Summary:", result.get("summary")])
    if result.get("matches") is not None:
        lines.extend(["", "Matches:", json.dumps(result.get("matches"), indent=2)])
    return "\n".join(lines)


def format_active_session_status(session: dict | None) -> str:
    if not session:
        return "No active SSH session. Connect to a host first."

    platform_key = session.get("platform_key") or "unknown"
    supported_intents = get_supported_intents(session.get("platform_key"))
    lines = [
        f"Active SSH session: {session.get('user')}@{session.get('host')}",
        f"Port: {session.get('port') or 22}",
        f"Platform: {platform_key}",
        f"Session mode: {session.get('session_mode') or 'unknown'}",
        f"Prepared: {'yes' if session.get('prepared') else 'no'}",
    ]
    if supported_intents:
        lines.extend(["", "Supported intents:", ", ".join(supported_intents)])
    examples = PLATFORM_EXAMPLES.get(platform_key, [])
    if examples:
        lines.extend(["", "Examples:", *(f"- {example}" for example in examples)])
    fingerprint = session.get("fingerprint")
    if fingerprint:
        useful_fingerprint = [
            line
            for line in str(fingerprint).splitlines()
            if "invalid input detected" not in line.lower()
            and not line.strip().lower().startswith(("cat /etc/os-release", "uname -a"))
        ]
        if useful_fingerprint:
            lines.extend(["", "Fingerprint:", "\n".join(useful_fingerprint)])
    return "\n".join(lines)


def build_interactive_prompt(session: dict | None, mode: str = "agent") -> str:
    if not session:
        return "\nnetadmin-agent> "

    host = session.get("host") or "unknown-host"
    port = session.get("port") or 22
    platform_key = session.get("platform_key") or "unknown"
    target = f"{host}:{port}" if int(port) != 22 else str(host)
    mode_prefix = "ssh:" if mode == "ssh" else ""
    return f"\nnetadmin-agent[{mode_prefix}{platform_key}:{target}]> "
