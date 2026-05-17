import ipaddress
import re
import socket

from agent.config import SSH_PORT


ALLOWED_SCAN_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("194.55.34.0/24"),
]

BLOCKED_SHELL_TOKENS = (";", "&&", "||", "|", ">", "<", "$(", "`", "\n")
BLOCKED_COMMAND_WORDS = {
    "rm",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "init",
    "mkfs",
    "dd",
    "mv",
    "cp",
    "chmod",
    "chown",
    "useradd",
    "usermod",
    "userdel",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "apk",
    "systemctl",
    "service",
    "docker rm",
    "docker stop",
    "docker restart",
    "kubectl delete",
}


class UnsupportedIntentError(ValueError):
    pass


def validate_host(host: str) -> str:
    host = host.strip()

    if not host:
        raise ValueError("Host is empty")

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        socket.gethostbyname(host)
        return host
    except socket.gaierror as exc:
        raise ValueError(f"Invalid or unresolvable host: {host}") from exc


def validate_scan_target(cidr: str) -> str:
    network = ipaddress.ip_network(cidr, strict=False)

    if not any(network.subnet_of(allowed) for allowed in ALLOWED_SCAN_NETWORKS):
        raise ValueError(f"Scan target not allowed: {cidr}")

    return str(network)


def validate_ssh_user(user: str) -> str:
    user = str(user).strip()
    if not user or not re.fullmatch(r"[a-zA-Z0-9._-]+", user):
        raise ValueError("Invalid SSH user")
    return user


def validate_ssh_port(port: int | str | None) -> int:
    if port is None:
        return SSH_PORT
    port = int(port)
    if port < 1 or port > 65535:
        raise ValueError("Invalid SSH port")
    return port


def validate_read_only_command(command: str) -> str:
    command = str(command).strip()
    if not command:
        raise ValueError("Remote command is empty")

    for token in BLOCKED_SHELL_TOKENS:
        if token in command:
            raise ValueError(f"Blocked shell token in remote command: {token}")

    lowered = command.lower()
    for word in BLOCKED_COMMAND_WORDS:
        if lowered == word or lowered.startswith(f"{word} "):
            raise ValueError(f"Blocked remote command: {word}")

    return command


def validate_ports(ports: str) -> str:
    if not ports or not str(ports).strip():
        raise ValueError("Ports value is empty")

    normalized = []
    seen = set()

    for raw in str(ports).split(","):
        item = raw.strip()
        if not item:
            continue

        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {item}")
            token = f"{start}-{end}"
        else:
            port = int(item)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {item}")
            token = str(port)

        if token not in seen:
            seen.add(token)
            normalized.append(token)

    if not normalized:
        raise ValueError("No valid ports provided")

    return ",".join(normalized)
