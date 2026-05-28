import json
import re


CIDR_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*\b")
IP_WITH_PORT_PATTERN = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b")
GENERIC_HOST_WITH_PORT_PATTERN = re.compile(r"\b([a-zA-Z0-9][a-zA-Z0-9._-]*):(\d{1,5})\b")
PORTS_PATTERN = re.compile(r"\bports?\s*[:=]?\s*([0-9,\-\s]+)", re.IGNORECASE)
FIRST_PORTS_PATTERN = re.compile(r"\bfirst\s+(\d{1,5})\s+ports?\b", re.IGNORECASE)
PING_ONLY_HINTS = ("ping", "icmp")
SSH_USER_PATTERN = re.compile(r"\b(?:with\s+)?(?:user|username)\s*[:=]?\s*([a-zA-Z0-9._-]+)\b", re.IGNORECASE)
SSH_USER_AFTER_NAME_PATTERN = re.compile(r"\b([a-zA-Z0-9._-]+)\s+user\b", re.IGNORECASE)
SSH_PORT_PATTERN = re.compile(r"\bport\s*[:=]?\s*(\d{1,5})\b", re.IGNORECASE)
SSH_PASSWORD_PATTERN = re.compile(r"(?:\b(?:with\s+)?(?:pass|password)\s*[:=]?\s*)([^\s,;]+)", re.IGNORECASE)
QUOTED_COMMAND_PATTERN = re.compile(r"[\"']([^\"']+)[\"']")
DIRECT_SCAN_HINTS = ("scan", "discover", "subnet", "network", "inventory")
DIRECT_HOST_HINTS = ("check", "host", "device", "ping", "reach", "connect")
PORT_SCAN_HINTS = ("port scan", "scan port", "ports", "open ports")
SSH_HINTS = ("ssh", "remote", "run", "execute", "command", "connect")
SCANNER_HINTS = ("nmap", "masscan")
SESSION_INFO_HINTS = (
    "session info",
    "session status",
    "show session",
    "ssh session",
    "connection info",
    "where am i connected",
    "what platform",
    "supported intents",
    "examples",
    "abilities",
    "ability",
    "what can i",
    "what i can",
    "what can user",
    "what ability",
    "what can you do here",
    "what can you do",
    "what can you do on this host",
    "what can i do on this platform",
    "what i can on this platform",
    "what i can on this paltform",
)
RESERVED_HOST_TOKENS = {
    "and",
    "check",
    "command",
    "connect",
    "for",
    "host",
    "hostname",
    "icmp",
    "into",
    "of",
    "on",
    "ping",
    "port",
    "ports",
    "remote",
    "run",
    "scan",
    "ssh",
    "subnet",
    "the",
    "to",
    "user",
    "username",
    "with",
}
RESERVED_FOLLOW_UP_USER_TOKENS = {
    "and",
    "as",
    "login",
    "please",
    "the",
    "use",
    "user",
    "username",
    "with",
}
MAC_ADDRESS_PATTERN = re.compile(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b|\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
VLAN_ID_PATTERN = re.compile(r"\bvlan\s+(\d{1,4})\b", re.IGNORECASE)
INTERFACE_PATTERN = re.compile(
    r"\b(?:gi(?:gabitethernet)?|gigabitethernet|te(?:ngigabitethernet)?|tengigabitethernet|tw(?:entyfivegige)?|twentyfivegige|twentyfivegigabitethernet|fo(?:rtygige)?|fortygige|fortygigabitethernet|hu(?:ndredgige)?|hundredgige|hundredgigabitethernet|fa(?:stethernet)?|fastethernet|eth(?:ernet)?|ethernet|po(?:rt-channel)?|port-channel|portchannel)\s*\d+(?:/\d+)*(?:\.\d+)?\b",
    re.IGNORECASE,
)


def extract_json(text: str) -> dict | None:
    text = text.strip()

    if text.startswith("```json"):
        text = text.removeprefix("```json").removesuffix("```").strip()
    elif text.startswith("```"):
        text = text.removeprefix("```").removesuffix("```").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def normalize_skill_call(skill_call: dict | None) -> dict | None:
    if not isinstance(skill_call, dict):
        return None

    skill = skill_call.get("skill")
    args = skill_call.get("args", {})

    if skill not in {"check_device_connectivity", "discover_network_hosts", "scan_host_tcp_ports", "run_remote_ssh_diagnostic"}:
        return None
    if not isinstance(args, dict):
        return None

    return {"skill": skill, "args": args}


def extract_explicit_ssh_command(text: str, user_match) -> str | None:
    quoted = QUOTED_COMMAND_PATTERN.search(text)
    if quoted:
        return quoted.group(1).strip()

    tail = text[user_match.end() :] if user_match else text
    patterns = [
        r"\brun\s+(?:the\s+command\s+)?(.+)$",
        r"\bexecute\s+(?:the\s+command\s+)?(.+)$",
        r"\bcommand\s+(.+)$",
    ]
    for pattern in patterns:
        match = re.search(pattern, tail, re.IGNORECASE)
        if match:
            candidate = match.group(1).strip(" .,:-")
            if candidate:
                return candidate
    return None


def _looks_like_host(candidate: str | None) -> bool:
    if not candidate:
        return False
    lowered = candidate.lower().strip(" .,")
    if not lowered or lowered in RESERVED_HOST_TOKENS:
        return False
    return not lowered.isdigit()


def _extract_hostname_candidate(text: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1).strip(" .,")
        if _looks_like_host(candidate):
            return candidate
    return None


def _extract_ssh_target(text: str) -> tuple[str | None, str | None]:
    patterns = (
        r"\bssh\s+(?:(?:to|into)\s+)?(?:(?P<user>[a-zA-Z0-9._-]+)@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9._-]*)\b",
        r"\bconnect\s+to\s+(?:(?P<user>[a-zA-Z0-9._-]+)@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9._-]*)\b",
        r"\bremote\s+to\s+(?:(?P<user>[a-zA-Z0-9._-]+)@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9._-]*)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            continue
        host = match.group("host").strip(" .,")
        user = match.group("user")
        if _looks_like_host(host):
            return host, user
    return None, None


def _extract_follow_up_token(text: str, *, reserved: set[str]) -> str | None:
    for match in HOST_PATTERN.finditer(text):
        candidate = match.group(0).strip(" .,")
        lowered = candidate.lower()
        if not candidate or lowered in reserved:
            continue
        if lowered.isdigit():
            continue
        return candidate
    return None


def _extract_scanner_hint(lowered: str) -> str | None:
    for scanner in SCANNER_HINTS:
        if scanner in lowered:
            return scanner
    return None


def parse_direct_skill_request(user_input: str) -> dict | None:
    text = user_input.strip()
    lowered = text.lower()
    scanner = _extract_scanner_hint(lowered)

    hostport_match = IP_WITH_PORT_PATTERN.search(text)
    generic_hostport_match = GENERIC_HOST_WITH_PORT_PATTERN.search(text)
    ip_match = IP_PATTERN.search(text)
    ssh_host, ssh_inline_user = _extract_ssh_target(text)
    if (ip_match or ssh_host or generic_hostport_match) and any(hint in lowered for hint in SSH_HINTS):
        user_match = SSH_USER_PATTERN.search(text)
        user_after_name_match = SSH_USER_AFTER_NAME_PATTERN.search(text)
        port_match = SSH_PORT_PATTERN.search(text)
        password_match = SSH_PASSWORD_PATTERN.search(text)
        explicit_command = extract_explicit_ssh_command(text, user_match)
        host = hostport_match.group(1) if hostport_match else (ip_match.group(0) if ip_match else ssh_host)
        if host is None and generic_hostport_match:
            host = generic_hostport_match.group(1)
        port = int(port_match.group(1)) if port_match else None
        if port is None:
            if hostport_match:
                port = int(hostport_match.group(2))
            elif generic_hostport_match and generic_hostport_match.group(1) == host:
                port = int(generic_hostport_match.group(2))
        user = ssh_inline_user
        if not user and user_match and user_match.group(1).lower() != "and":
            user = user_match.group(1)
        elif not user and user_after_name_match and user_after_name_match.group(1).lower() != "with":
            user = user_after_name_match.group(1)
        return {
            "skill": "run_remote_ssh_diagnostic",
            "args": {
                "host": host,
                "port": port,
                "user": user,
                "password": password_match.group(1) if password_match else None,
                "command": explicit_command,
                "request": text,
            },
        }

    cidr_match = CIDR_PATTERN.search(text)
    if cidr_match and (text == cidr_match.group(0) or any(hint in lowered for hint in DIRECT_SCAN_HINTS)):
        ports_match = PORTS_PATTERN.search(text)
        first_ports_match = FIRST_PORTS_PATTERN.search(text)
        ping_only = any(hint in lowered for hint in PING_ONLY_HINTS) and not ports_match and not first_ports_match
        if ping_only:
            ports = None
        elif first_ports_match:
            ports = f"1-{int(first_ports_match.group(1))}"
        elif ports_match:
            ports = ports_match.group(1).replace(" ", "")
        else:
            ports = "22,80,443"
        args = {"cidr": cidr_match.group(0), "ports": ports}
        if scanner:
            args["scanner"] = scanner
        return {"skill": "discover_network_hosts", "args": args}

    ip_match = IP_PATTERN.search(text)
    port_scan_host = _extract_hostname_candidate(
        text,
        (
            r"\b(?:scan|check)\s+(?:the\s+)?(?:first\s+\d+\s+)?ports?\s+(?:on|of)\s+([a-zA-Z0-9][a-zA-Z0-9._-]*)\b",
            r"\bport\s+scan\s+([a-zA-Z0-9][a-zA-Z0-9._-]*)\b",
            r"\bscan\s+([a-zA-Z0-9][a-zA-Z0-9._-]*)\s+ports?\b",
        ),
    )
    first_ports_match = FIRST_PORTS_PATTERN.search(text)
    ports_match = PORTS_PATTERN.search(text)
    if (ip_match or port_scan_host) and (
        first_ports_match
        or ports_match
        or any(hint in lowered for hint in PORT_SCAN_HINTS)
    ):
        if first_ports_match:
            end_port = int(first_ports_match.group(1))
            ports = f"1-{end_port}"
        elif ports_match:
            ports = ports_match.group(1).replace(" ", "")
        else:
            ports = "1-1024"
        return {"skill": "scan_host_tcp_ports", "args": {"host": ip_match.group(0) if ip_match else port_scan_host, "ports": ports}}

    direct_host = ip_match.group(0) if ip_match else _extract_hostname_candidate(
        text,
        (
            r"\bcheck\s+([a-zA-Z0-9][a-zA-Z0-9._-]*)\b",
            r"\bping\s+([a-zA-Z0-9][a-zA-Z0-9._-]*)\b",
            r"^\s*([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*$",
        ),
    )
    if direct_host and (
        text == direct_host
        or any(hint in lowered for hint in DIRECT_HOST_HINTS)
        or not any(hint in lowered for hint in SSH_HINTS + DIRECT_SCAN_HINTS)
    ):
        return {"skill": "check_device_connectivity", "args": {"host": direct_host}}

    return None


def detect_ambiguous_follow_up(user_input: str) -> dict | None:
    text = user_input.strip()
    lowered = text.lower()

    if any(hint in lowered for hint in DIRECT_SCAN_HINTS) and not CIDR_PATTERN.search(text):
        return {
            "skill": "discover_network_hosts",
            "args": {"ports": None} if any(hint in lowered for hint in PING_ONLY_HINTS) else {},
            "missing": ["cidr"],
            "question": "Which subnet should I scan? Give me a CIDR like 192.168.1.0/24.",
        }

    if any(hint in lowered for hint in SSH_HINTS):
        user_match = SSH_USER_PATTERN.search(text)
        user_after_name_match = SSH_USER_AFTER_NAME_PATTERN.search(text)
        if not user_match and not user_after_name_match:
            parsed = parse_direct_skill_request(text)
            if parsed and parsed.get("skill") == "run_remote_ssh_diagnostic" and parsed.get("args", {}).get("host"):
                return {
                    "skill": parsed["skill"],
                    "args": parsed["args"],
                    "missing": ["user"],
                    "question": f"Which SSH username should I use for {parsed['args']['host']}?",
                }

    if any(hint in lowered for hint in PORT_SCAN_HINTS) and not IP_PATTERN.search(text):
        return {
            "skill": "scan_host_tcp_ports",
            "args": {},
            "missing": ["host"],
            "question": "Which host should I port-scan? Give me an IP or hostname.",
        }

    if (
        any(hint in lowered for hint in DIRECT_HOST_HINTS)
        and not any(hint in lowered for hint in SSH_HINTS)
        and not IP_PATTERN.search(text)
        and not CIDR_PATTERN.search(text)
    ):
        return {
            "skill": "check_device_connectivity",
            "args": {},
            "missing": ["host"],
            "question": "Which host should I check? Give me an IP or hostname.",
        }

    if any(hint in lowered for hint in SSH_HINTS) and not IP_PATTERN.search(text):
        return {
            "skill": "run_remote_ssh_diagnostic",
            "args": {},
            "missing": ["host"],
            "question": "Which host should I connect to over SSH? Give me an IP or hostname.",
        }

    return None


def complete_follow_up(pending: dict, user_input: str) -> dict | None:
    text = user_input.strip()
    skill = pending.get("skill")
    args = dict(pending.get("args", {}))
    missing = list(pending.get("missing", []))

    for field in missing:
        if field == "cidr":
            cidr_match = CIDR_PATTERN.search(text)
            if not cidr_match:
                return None
            args["cidr"] = cidr_match.group(0)
            ports_match = PORTS_PATTERN.search(text)
            first_ports_match = FIRST_PORTS_PATTERN.search(text)
            ping_only = any(hint in text.lower() for hint in PING_ONLY_HINTS)
            if first_ports_match:
                args["ports"] = f"1-{int(first_ports_match.group(1))}"
            elif ports_match:
                args["ports"] = ports_match.group(1).replace(" ", "")
            elif ping_only:
                args["ports"] = None
            else:
                args["ports"] = args.get("ports", "22,80,443")
            scanner = _extract_scanner_hint(text.lower())
            if scanner:
                args["scanner"] = scanner
        elif field == "host":
            hostport_match = IP_WITH_PORT_PATTERN.search(text)
            generic_hostport_match = GENERIC_HOST_WITH_PORT_PATTERN.search(text)
            ip_match = IP_PATTERN.search(text)
            ssh_host, ssh_inline_user = _extract_ssh_target(text)
            if hostport_match:
                args["host"] = hostport_match.group(1)
                args["port"] = int(hostport_match.group(2))
            elif generic_hostport_match:
                args["host"] = generic_hostport_match.group(1)
                args["port"] = int(generic_hostport_match.group(2))
            elif ip_match:
                args["host"] = ip_match.group(0)
            elif ssh_host:
                args["host"] = ssh_host
                if ssh_inline_user and not args.get("user"):
                    args["user"] = ssh_inline_user
            else:
                candidate = _extract_follow_up_token(
                    text,
                    reserved=RESERVED_HOST_TOKENS | {"please", "is", "use"},
                )
                if not candidate:
                    return None
                args["host"] = candidate
        elif field == "user":
            ssh_host, ssh_inline_user = _extract_ssh_target(text)
            user_match = SSH_USER_PATTERN.search(text)
            user_after_name_match = SSH_USER_AFTER_NAME_PATTERN.search(text)
            if ssh_inline_user:
                args["user"] = ssh_inline_user
                if ssh_host and not args.get("host"):
                    args["host"] = ssh_host
            elif user_match and user_match.group(1).lower() != "and":
                args["user"] = user_match.group(1)
            elif user_after_name_match and user_after_name_match.group(1).lower() != "with":
                args["user"] = user_after_name_match.group(1)
            else:
                candidate = _extract_follow_up_token(text, reserved=RESERVED_FOLLOW_UP_USER_TOKENS)
                if not candidate:
                    return None
                args["user"] = candidate

    return {"skill": skill, "args": args}


def is_session_info_request(user_input: str) -> bool:
    lowered = user_input.strip().lower()
    return any(hint in lowered for hint in SESSION_INFO_HINTS)
