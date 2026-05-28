import re

from agent.platforms import PLATFORM_REGISTRY

from .safety import UnsupportedIntentError, validate_read_only_command


INTENT_KEYWORDS = {
    "system_health": ("health", "status overview", "system health", "version"),
    "cpu": ("cpu",),
    "memory": ("memory", "ram"),
    "disk": ("disk", "filesystem", "storage"),
    "interfaces": ("interface", "interfaces", "interface status"),
    "interface_trunk": ("interface trunk", "interfaces trunk", "trunk allowed", "allowed vlan", "allowed vlans"),
    "ip_interfaces": ("ip interface", "ip interfaces", "interface brief"),
    "routes": ("route", "routes", "routing"),
    "services": ("service", "services"),
    "logs": ("log", "logs", "errors"),
    "running_config": ("sh run", "show run", "show running-config", "running config", "running-config"),
    "neighbors": ("neighbor", "neighbors", "cdp", "lldp"),
    "vlans": ("vlan", "vlans"),
    "mac_table": ("mac table", "mac address", "mac addresses"),
    "spanning_tree": ("spanning tree", "stp"),
    "port_channel": ("port-channel", "port channel", "etherchannel"),
    "vpc": ("vpc",),
}

SAFE_REMOTE_COMMAND_MAP = {
    "uptime": "uptime",
    "hostname": "hostname",
    "whoami": "whoami",
    "kernel": "uname -a",
    "os": "cat /etc/os-release",
    "disk": "df -h",
    "memory": "free -h",
    "cpu": "top -bn1",
    "ip": "ip addr show",
    "address": "ip addr show",
    "routes": "ip route",
    "services": "service --status-all",
    "service": "service --status-all",
    "listening ports": "ss -tulpn",
    "docker": "docker ps --format '{{.Names}}\t{{.Status}}'",
    "containers": "docker ps --format '{{.Names}}\t{{.Status}}'",
}


def infer_intent(request: str) -> str | None:
    lowered = str(request).strip().lower()
    matches = []
    for intent, keywords in INTENT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in lowered:
                matches.append((len(keyword), intent))
    if not matches:
        return None
    matches.sort(key=lambda item: (-item[0], item[1]))
    return matches[0][1]


def get_platform_profile(platform_key: str | None):
    if not platform_key:
        return None
    for profile in PLATFORM_REGISTRY:
        if profile.key == platform_key:
            return profile
    return None


def get_supported_intents(platform_key: str | None) -> list[str]:
    profile = get_platform_profile(platform_key)
    if not profile:
        return []
    return sorted(profile.safe_commands.keys())


def suggest_supported_intents(platform_key: str | None, request: str | None = None) -> list[str]:
    supported = get_supported_intents(platform_key)
    if not request:
        return supported[:5]

    lowered = str(request).lower()
    ranked = []
    for intent in supported:
        keywords = INTENT_KEYWORDS.get(intent, ())
        score = sum(1 for keyword in keywords if keyword in lowered)
        ranked.append((score, intent))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    ordered = [intent for score, intent in ranked if score > 0]
    if ordered:
        return ordered[:5]
    return supported[:5]


def resolve_platform_command(request: str, platform_key: str | None = None) -> str | None:
    intent = infer_intent(request)
    if not intent or not platform_key:
        return None

    profile = get_platform_profile(platform_key)
    if profile and profile.supports_intent(intent):
        spec = profile.get_command(intent)
        return spec.command if spec else None
    if profile:
        suggestions = suggest_supported_intents(platform_key, request)
        suggestion_text = ", ".join(suggestions) if suggestions else "none"
        raise UnsupportedIntentError(
            f"Intent '{intent}' is not supported on platform {platform_key}. Supported intents include: {suggestion_text}"
        )
    return None


def infer_safe_remote_command(request: str, platform_key: str | None = None) -> str:
    lowered = str(request).strip().lower()
    if not lowered:
        raise ValueError("Remote request is empty")

    platform_command = resolve_platform_command(lowered, platform_key=platform_key)
    if platform_command:
        return platform_command

    if not platform_key:
        for key, command in SAFE_REMOTE_COMMAND_MAP.items():
            if key in lowered:
                return command

    if any(word in lowered for word in ("connect", "login", "ssh")):
        return "hostname"

    raise ValueError("Could not infer a safe read-only command from request")


def _normalize_command_text(command: str) -> str:
    return " ".join(str(command).strip().split())


def _resolve_platform_explicit_command(command: str, platform_key: str) -> str:
    profile = get_platform_profile(platform_key)
    if not profile:
        raise ValueError(f"Unknown platform profile: {platform_key}")

    normalized = _normalize_command_text(command)
    for spec in profile.safe_commands.values():
        if _normalize_command_text(spec.command) == normalized:
            return spec.command

    suggestions = suggest_supported_intents(platform_key, command)
    suggestion_text = ", ".join(suggestions) if suggestions else "none"
    raise UnsupportedIntentError(
        f"Explicit command '{command}' is not in the safe allowlist for platform {platform_key}. "
        f"Supported intents include: {suggestion_text}"
    )


def resolve_remote_command(command: str | None = None, request: str | None = None, platform_key: str | None = None) -> str:
    normalized = str(command or "").strip()
    normalized = re.sub(
        r"^(and\s+|then\s+|run\s+|execute\s+|command\s+)+",
        "",
        normalized,
        flags=re.IGNORECASE,
    )

    if normalized:
        try:
            return infer_safe_remote_command(normalized, platform_key=platform_key)
        except UnsupportedIntentError:
            raise
        except ValueError:
            pass

        if platform_key:
            try:
                return _resolve_platform_explicit_command(normalized, platform_key)
            except UnsupportedIntentError:
                if request:
                    return infer_safe_remote_command(request, platform_key=platform_key)
                raise

        try:
            return validate_read_only_command(normalized)
        except ValueError:
            if request:
                return infer_safe_remote_command(request, platform_key=platform_key)
            raise

    return infer_safe_remote_command(request or "", platform_key=platform_key)
