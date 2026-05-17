import json

from agent.tools import get_supported_intents


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

        lines = [f"Network scan {status}: {cidr}"]
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
                port_list = ", ".join(str(item.get("port")) for item in info.get("ports", [])) or "none"
                suffix = f" ({hostname})" if hostname else ""
                preview.append(f"- {ip}{suffix} ports: {port_list}")
            lines.extend(["", "Hosts:", *preview])
            if len(result.get("hosts", {})) > 10:
                lines.append(f"- ... and {len(result.get('hosts', {})) - 10} more")

        warnings = list(checks.get("warnings", []))
        recommendation = None
        for label, scan in (("ICMP", checks.get("icmp_scan", {})), ("Port scan", checks.get("port_scan", {}))):
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


def format_playbook_result(result: dict) -> str:
    if result.get("skill") == "cisco_interface_down_playbook":
        matches = result.get("matches") or {}
        interfaces = matches.get("interfaces") or []
        ip_interfaces = matches.get("ip_interfaces") or []
        neighbors = matches.get("neighbors") or []
        mac_table = matches.get("mac_table") or []
        interface = result.get("interface") or "interface"
        sw = interfaces[0] if interfaces else {}
        l3 = ip_interfaces[0] if ip_interfaces else {}

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
                f"- Switchport: {sw.get('status', 'not found')} VLAN {sw.get('vlan', 'unknown')}",
                f"- L3 state: {l3.get('status', 'not found')}/{l3.get('protocol', 'unknown')}",
                f"- Neighbors: {len(neighbors)}",
                f"- MAC entries: {len(mac_table)}",
            ]
        )

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
                "- Checked interface status, L3 state, neighbors, MAC table, and logs.",
                "- Link is down if status is down/notconnect and no neighbor/MAC is present.",
            ]
        )

        reasons = result.get("possible_reasons") or []
        if reasons:
            lines.extend(["", "Possible Reasons:"])
            lines.extend(f"- {reason}" for reason in reasons[:4])

        recommendations = result.get("recommendations") or []
        if recommendations:
            lines.extend(["", "Recommendations:"])
            lines.extend(f"- {item}" for item in recommendations[:3])
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
    fingerprint = session.get("fingerprint")
    if fingerprint:
        lines.extend(["", "Fingerprint:", fingerprint])
    return "\n".join(lines)


def build_interactive_prompt(session: dict | None) -> str:
    if not session:
        return "\nnetadmin-agent> "

    host = session.get("host") or "unknown-host"
    port = session.get("port") or 22
    platform_key = session.get("platform_key") or "unknown"
    target = f"{host}:{port}" if int(port) != 22 else str(host)
    return f"\nnetadmin-agent[{platform_key}:{target}]> "
