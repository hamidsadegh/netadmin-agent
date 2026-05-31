from agent.config import SSH_COMMAND_TIMEOUT, SSH_CONNECT_TIMEOUT
from agent.parsers import (
    parse_show_cdp_neighbors_detail,
    parse_show_interfaces_status,
    parse_show_interfaces_trunk,
    parse_show_ip_interface_brief,
    parse_show_mac_address_table,
    parse_show_port_channel_summary,
    parse_show_vpc,
    parse_show_vlan_brief,
)
from agent.platforms import detect_platform

from .intents import infer_intent, resolve_remote_command
from .network import clean_remote_output
from .safety import validate_host, validate_read_only_command, validate_ssh_port, validate_ssh_user


CISCO_RAW_READ_ONLY_PREFIXES = (
    "show",
    "sh",
    "terminal length",
    "terminal width",
    "ping",
    "traceroute",
    "dir",
    "more",
)
SAFE_OUTPUT_FILTER_PATTERN = " include "


def _best_effort_resolve_command(
    command: str | None = None,
    request: str | None = None,
    platform_key: str | None = None,
) -> str | None:
    try:
        return resolve_remote_command(command=command, request=request, platform_key=platform_key)
    except Exception:
        normalized = str(command or "").strip()
        return normalized or None


def get_paramiko():
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("paramiko is not installed. Install project dependencies first.") from exc
    return paramiko


def _build_ssh_client(host: str, user: str, password: str | None = None, port: int | None = None):
    host = validate_host(host)
    user = validate_ssh_user(user)
    port = validate_ssh_port(port)

    paramiko = get_paramiko()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": user,
        "timeout": SSH_CONNECT_TIMEOUT,
        "banner_timeout": SSH_CONNECT_TIMEOUT,
        "auth_timeout": SSH_CONNECT_TIMEOUT,
        "look_for_keys": password is None,
        "allow_agent": password is None,
    }
    if password is not None:
        connect_kwargs["password"] = password

    return client, paramiko, connect_kwargs


def _run_ssh_command(client, command: str) -> dict:
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=min(SSH_COMMAND_TIMEOUT, 10))
        stdout_text = stdout.read().decode(errors="replace")
        stderr_text = stderr.read().decode(errors="replace")
        _ = stdout.channel.recv_exit_status()
        return {
            "command": command,
            "stdout": clean_remote_output(stdout_text),
            "stderr": clean_remote_output(stderr_text),
        }
    except Exception as exc:
        return {"command": command, "error": str(exc)}


def _append_fingerprint_output(combined: list[str], result: dict) -> None:
    stdout_text = result.get("stdout", "")
    stderr_text = result.get("stderr", "")
    if stdout_text.strip():
        combined.append(stdout_text.strip())
    if stderr_text.strip() and "invalid input detected" not in stderr_text.lower():
        combined.append(stderr_text.strip())


def prepare_platform_session(client, platform_key: str | None, skip_commands: set[str] | None = None) -> dict:
    commands = []
    results = []
    skip_commands = skip_commands or set()

    if platform_key in {"cisco_ios", "cisco_ios_xe", "cisco_nxos"}:
        commands.append("terminal length 0")

    commands = [command for command in commands if command not in skip_commands]

    for command in commands:
        results.append(_run_ssh_command(client, command))

    return {"prepared": bool(commands), "preparation_results": results}


def detect_platform_on_ssh_session(client) -> dict:
    combined = []
    pre_run_commands = set()
    preparation_results = []
    profile = None

    for command in ("cat /etc/os-release", "uname -a"):
        result = _run_ssh_command(client, command)
        _append_fingerprint_output(combined, result)
        fingerprint_text = "\n".join(combined)
        profile = detect_platform(fingerprint_text) if fingerprint_text else None
        if profile:
            break

    if not profile:
        pager_result = _run_ssh_command(client, "terminal length 0")
        pre_run_commands.add("terminal length 0")
        preparation_results.append(pager_result)

        version_result = _run_ssh_command(client, "show version")
        _append_fingerprint_output(combined, version_result)
        fingerprint_text = "\n".join(combined)
        profile = detect_platform(fingerprint_text) if fingerprint_text else None

    fingerprint_text = "\n".join(combined)
    preparation = prepare_platform_session(
        client,
        profile.key if profile else None,
        skip_commands=pre_run_commands,
    )
    preparation_results.extend(preparation.get("preparation_results", []))
    return {
        "platform_key": profile.key if profile else None,
        "platform_label": profile.label if profile else None,
        "fingerprint": clean_remote_output(fingerprint_text, max_lines=80, max_chars=6000),
        "prepared": bool(preparation_results) or preparation.get("prepared", False),
        "preparation_results": preparation_results,
    }


def connect_ssh_session(host: str, user: str, password: str | None = None, port: int | None = None) -> dict:
    host = validate_host(host)
    user = validate_ssh_user(user)
    port = validate_ssh_port(port)
    target = f"{user}@{host}:{port}" if port != 22 else f"{user}@{host}"

    client, paramiko, connect_kwargs = _build_ssh_client(host, user, password=password, port=port)
    try:
        client.connect(**connect_kwargs)
        metadata = detect_platform_on_ssh_session(client)
        return {
            "success": True,
            "client": client,
            "host": host,
            "port": port,
            "user": user,
            "target": target,
            "auth_failed": False,
            "used_password": password is not None,
            "platform_key": metadata.get("platform_key"),
            "platform_label": metadata.get("platform_label"),
            "fingerprint": metadata.get("fingerprint"),
            "prepared": metadata.get("prepared", False),
            "preparation_results": metadata.get("preparation_results", []),
            "session_mode": "cisco_cli" if metadata.get("platform_key") in {"cisco_ios", "cisco_ios_xe", "cisco_nxos"} else "linux_shell",
        }
    except paramiko.AuthenticationException:
        client.close()
        return {
            "success": False,
            "client": None,
            "host": host,
            "port": port,
            "user": user,
            "target": target,
            "error": "SSH authentication failed",
            "auth_failed": True,
            "used_password": password is not None,
        }
    except paramiko.SSHException as exc:
        client.close()
        error_text = str(exc)
        auth_failed = "auth" in error_text.lower() or "authentication" in error_text.lower()
        return {
            "success": False,
            "client": None,
            "host": host,
            "port": port,
            "user": user,
            "target": target,
            "error": error_text,
            "auth_failed": auth_failed,
            "used_password": password is not None,
        }
    except Exception as exc:
        client.close()
        error_text = str(exc)
        auth_failed = "auth" in error_text.lower() or "authentication" in error_text.lower()
        return {
            "success": False,
            "client": None,
            "host": host,
            "port": port,
            "user": user,
            "target": target,
            "error": error_text,
            "auth_failed": auth_failed,
            "used_password": password is not None,
        }


def summarize_rhel_result(intent: str | None, stdout_text: str, stderr_text: str) -> str | None:
    if stderr_text.strip():
        return None

    lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    if not lines:
        return None

    if intent == "memory":
        for line in lines:
            if line.lower().startswith("mem:"):
                parts = line.split()
                if len(parts) >= 7:
                    return f"Memory used {parts[2]} of {parts[1]}, available {parts[6]}."
    elif intent == "disk":
        mounts = []
        for line in lines[1:4]:
            parts = line.split()
            if len(parts) >= 6:
                mounts.append(f"{parts[5]} {parts[4]} used")
        if mounts:
            return "Disk usage: " + ", ".join(mounts) + "."
    elif intent == "services":
        count = max(0, len(lines) - 1) if lines and "UNIT " in lines[0] else len(lines)
        return f"Found {count} running services in systemd output."
    elif intent == "interfaces":
        return f"Found {len(lines)} interface entries."
    elif intent == "routes":
        return f"Found {len(lines)} route entries."
    elif intent == "cpu":
        for line in lines:
            if "load average" in line.lower():
                return f"CPU snapshot captured: {line}."
        return f"CPU snapshot captured with {len(lines)} lines of output."
    elif intent in {"errors", "logs"}:
        return f"Collected {len(lines)} recent log/error lines."
    elif intent == "system_health":
        return f"Collected combined system health snapshot with {len(lines)} lines."

    return None


def parse_cisco_result(intent: str | None, command: str, stdout_text: str) -> dict | None:
    if intent == "interfaces":
        return {"interfaces": parse_show_interfaces_status(stdout_text)}
    if intent == "interface_trunk":
        return {"interface_trunks": parse_show_interfaces_trunk(stdout_text)}
    if intent == "ip_interfaces":
        return {"ip_interfaces": parse_show_ip_interface_brief(stdout_text)}
    if intent == "vlans":
        return {"vlans": parse_show_vlan_brief(stdout_text)}
    if intent == "mac_table":
        return {"mac_table": parse_show_mac_address_table(stdout_text)}
    if intent == "neighbors":
        return {"neighbors": parse_show_cdp_neighbors_detail(stdout_text)}
    if intent == "port_channel":
        return {"port_channels": parse_show_port_channel_summary(stdout_text)}
    if intent == "vpc":
        return {"vpc": parse_show_vpc(stdout_text)}
    return None


def summarize_cisco_result(platform_key: str | None, intent: str | None, stdout_text: str, stderr_text: str) -> str | None:
    if stderr_text.strip():
        return None

    parsed = parse_cisco_result(intent, "", stdout_text) or {}
    lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    if not lines:
        return None

    if intent == "system_health":
        return f"Collected platform/version output with {len(lines)} lines from {platform_key}."
    if intent == "interfaces":
        entries = parsed.get("interfaces", [])
        up_count = sum(1 for item in entries if str(item.get("status", "")).lower() in {"connected", "up"})
        return f"Found {len(entries)} interface entries; {up_count} appear connected."
    if intent == "interface_trunk":
        entries = parsed.get("interface_trunks", [])
        trunking_count = sum(1 for item in entries if str(item.get("status", "")).lower() == "trunking")
        return f"Found {len(entries)} trunk entries; {trunking_count} report trunking."
    if intent == "ip_interfaces":
        entries = parsed.get("ip_interfaces", [])
        up_count = sum(1 for item in entries if str(item.get("status", "")).lower() == "up")
        return f"Found {len(entries)} L3 interfaces; {up_count} report status up."
    if intent == "vlans":
        entries = parsed.get("vlans", [])
        active_count = sum(1 for item in entries if str(item.get("status", "")).lower() == "active")
        return f"Found {len(entries)} VLAN entries; {active_count} are active."
    if intent == "neighbors":
        return f"Found {len(parsed.get('neighbors', []))} neighbor detail blocks."
    if intent == "mac_table":
        return f"Found {len(parsed.get('mac_table', []))} MAC table entries."
    if intent == "routes":
        return f"Collected routing table output with {len(lines)} lines."
    if intent == "spanning_tree":
        return f"Collected spanning-tree state with {len(lines)} lines."
    if intent == "port_channel":
        return f"Found {len(parsed.get('port_channels', []))} port-channel summary entries."
    if intent == "vpc":
        parsed_vpc = parsed.get("vpc", {})
        return f"Collected vPC state with {len(parsed_vpc.get('vpcs', []))} vPC entries."
    if intent == "logs":
        return f"Collected {len(lines)} log lines from device buffer."
    if intent == "running_config":
        return f"Collected running configuration with {len(lines)} lines."
    return None


def summarize_remote_result(platform_key: str | None, request: str | None, command: str, stdout_text: str, stderr_text: str) -> str | None:
    intent = infer_intent(request or command or "")
    if platform_key == "rhel":
        return summarize_rhel_result(intent, stdout_text, stderr_text)
    if platform_key in {"cisco_ios", "cisco_ios_xe", "cisco_nxos"}:
        return summarize_cisco_result(platform_key, intent, stdout_text, stderr_text)
    return None


def run_command_on_ssh_session(
    client,
    host: str,
    user: str,
    port: int | None = None,
    command: str | None = None,
    request: str | None = None,
    platform_key: str | None = None,
) -> dict:
    host = validate_host(host)
    user = validate_ssh_user(user)
    port = validate_ssh_port(port)
    selected_command = resolve_remote_command(command=command, request=request, platform_key=platform_key)
    target = f"{user}@{host}:{port}" if port != 22 else f"{user}@{host}"

    try:
        _stdin, stdout, stderr = client.exec_command(selected_command, timeout=SSH_COMMAND_TIMEOUT)
        stdout_text = stdout.read().decode(errors="replace")
        stderr_text = stderr.read().decode(errors="replace")
        return_code = stdout.channel.recv_exit_status()
        intent = infer_intent(request or selected_command)
        parsed = parse_cisco_result(intent, selected_command, stdout_text) if platform_key in {"cisco_ios", "cisco_ios_xe", "cisco_nxos"} else None
        return {
            "tool": "execute_remote_ssh_command",
            "host": host,
            "port": port,
            "user": user,
            "command": selected_command,
            "intent": intent,
            "success": return_code == 0,
            "return_code": return_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "cleaned_stdout": clean_remote_output(stdout_text),
            "cleaned_stderr": clean_remote_output(stderr_text),
            "summary": summarize_remote_result(platform_key, request, selected_command, stdout_text, stderr_text),
            "parsed": parsed,
            "target": target,
            "auth_failed": False,
            "platform_key": platform_key,
        }
    except Exception as exc:
        error_text = str(exc)
        auth_failed = "auth" in error_text.lower() or "authentication" in error_text.lower()
        return {
            "tool": "execute_remote_ssh_command",
            "host": host,
            "port": port,
            "user": user,
            "command": selected_command,
            "intent": infer_intent(request or selected_command),
            "success": False,
            "error": error_text,
            "cleaned_stdout": "",
            "cleaned_stderr": "",
            "summary": None,
            "parsed": None,
            "target": target,
            "auth_failed": auth_failed,
            "platform_key": platform_key,
        }


def validate_raw_ssh_command(command: str, platform_key: str | None = None) -> str:
    selected_command = validate_read_only_command(_split_output_filter(command)[0])
    lowered = selected_command.lower()
    if platform_key in {"cisco_ios", "cisco_ios_xe", "cisco_nxos"}:
        if not any(lowered == prefix or lowered.startswith(f"{prefix} ") for prefix in CISCO_RAW_READ_ONLY_PREFIXES):
            raise ValueError("Raw SSH mode only allows read-only Cisco commands like show, ping, traceroute, dir, and terminal length/width")
    return selected_command


def _split_output_filter(command: str) -> tuple[str, str | None]:
    text = str(command or "").strip()
    parts = [part.strip() for part in text.split("|")]
    if len(parts) == 1:
        return text, None
    if len(parts) != 2:
        raise ValueError("Only one safe output filter is supported")
    filter_text = parts[1].lower()
    if filter_text.startswith("include "):
        pattern = parts[1][len("include ") :].strip()
    elif filter_text.startswith("i "):
        pattern = parts[1][len("i ") :].strip()
    else:
        raise ValueError("Only '| include <text>' filters are supported")
    if not pattern or any(token in pattern for token in ("\n", "\r", "|", ";", "&&", "||", "$(", "`", ">", "<")):
        raise ValueError("Invalid output filter text")
    return parts[0], pattern


def _apply_output_filter(output: str, pattern: str | None) -> str:
    if not pattern:
        return output
    needle = pattern.lower()
    lines = [line for line in str(output or "").splitlines() if needle in line.lower()]
    return "\n".join(lines) + ("\n" if lines else "")


def run_raw_command_on_ssh_session(
    client,
    host: str,
    user: str,
    command: str,
    port: int | None = None,
    platform_key: str | None = None,
) -> dict:
    host = validate_host(host)
    user = validate_ssh_user(user)
    port = validate_ssh_port(port)
    base_command, include_filter = _split_output_filter(command)
    selected_command = validate_raw_ssh_command(base_command, platform_key=platform_key)
    target = f"{user}@{host}:{port}" if port != 22 else f"{user}@{host}"

    try:
        _stdin, stdout, stderr = client.exec_command(selected_command, timeout=SSH_COMMAND_TIMEOUT)
        stdout_text = stdout.read().decode(errors="replace")
        stderr_text = stderr.read().decode(errors="replace")
        return_code = stdout.channel.recv_exit_status()
        filtered_stdout = _apply_output_filter(stdout_text, include_filter)
        filtered_stderr = _apply_output_filter(stderr_text, include_filter)
        return {
            "tool": "execute_raw_ssh_command",
            "host": host,
            "port": port,
            "user": user,
            "command": command,
            "executed_command": selected_command,
            "output_filter": include_filter,
            "success": return_code == 0,
            "return_code": return_code,
            "stdout": filtered_stdout,
            "stderr": filtered_stderr,
            "raw_stdout": stdout_text,
            "raw_stderr": stderr_text,
            "target": target,
            "platform_key": platform_key,
        }
    except Exception as exc:
        return {
            "tool": "execute_raw_ssh_command",
            "host": host,
            "port": port,
            "user": user,
            "command": selected_command,
            "success": False,
            "error": str(exc),
            "stdout": "",
            "stderr": "",
            "target": target,
            "platform_key": platform_key,
        }


def execute_remote_ssh_command(
    host: str,
    user: str,
    port: int | None = None,
    command: str | None = None,
    request: str | None = None,
    password: str | None = None,
    platform_key: str | None = None,
) -> dict:
    port = validate_ssh_port(port)
    session = connect_ssh_session(host=host, user=user, password=password, port=port)
    if not session.get("success"):
        return {
            "tool": "execute_remote_ssh_command",
            "host": session.get("host", host),
            "port": session.get("port", port),
            "user": session.get("user", user),
            "command": _best_effort_resolve_command(command=command, request=request, platform_key=platform_key),
            "success": False,
            "error": session.get("error"),
            "cleaned_stdout": "",
            "cleaned_stderr": "",
            "target": session.get("target"),
            "auth_failed": session.get("auth_failed", False),
            "used_password": password is not None,
        }

    client = session["client"]
    try:
        result = run_command_on_ssh_session(
            client,
            host=host,
            port=port,
            user=user,
            command=command,
            request=request,
            platform_key=platform_key or session.get("platform_key"),
        )
        result["used_password"] = password is not None
        return result
    finally:
        client.close()
