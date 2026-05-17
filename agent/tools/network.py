import ipaddress
import platform
import socket
import subprocess

from .safety import validate_host


def clean_remote_output(text: str, max_lines: int = 60, max_chars: int = 4000) -> str:
    raw_lines = str(text).splitlines()
    cleaned = []
    previous_blank = False

    for line in raw_lines:
        line = line.rstrip()
        if not line.strip():
            if not previous_blank:
                cleaned.append("")
            previous_blank = True
            continue

        compact = " ".join(line.split())
        cleaned.append(compact)
        previous_blank = False

    while cleaned and cleaned[0] == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1] == "":
        cleaned.pop()

    result_lines = cleaned[:max_lines]
    result = "\n".join(result_lines)
    if len(cleaned) > max_lines:
        result += "\n...[truncated lines]"
    if len(result) > max_chars:
        result = result[: max_chars - 20].rstrip() + "\n...[truncated]"
    return result


def ping_host(host: str, count: int = 3) -> dict:
    host = validate_host(host)
    count = max(1, min(int(count), 5))

    param = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", param, str(count), host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {
            "tool": "ping_host",
            "host": host,
            "reachable": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"tool": "ping_host", "host": host, "reachable": False, "error": "Ping command timed out"}
    except FileNotFoundError:
        return {"tool": "ping_host", "host": host, "reachable": False, "error": "ping binary not found"}


def check_tcp_port(host: str, port: int, timeout: float = 3.0) -> dict:
    host = validate_host(host)
    port = int(port)

    if port < 1 or port > 65535:
        raise ValueError("Invalid TCP port")

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"tool": "check_tcp_port", "host": host, "port": port, "open": True}
    except socket.timeout:
        return {
            "tool": "check_tcp_port",
            "host": host,
            "port": port,
            "open": False,
            "error": "Connection timed out",
        }
    except OSError as exc:
        return {
            "tool": "check_tcp_port",
            "host": host,
            "port": port,
            "open": False,
            "error": str(exc),
        }


def reverse_dns_lookup(ip: str) -> dict:
    ipaddress.ip_address(ip)

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return {
            "tool": "reverse_dns_lookup",
            "ip": ip,
            "found": True,
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }
    except socket.herror:
        return {"tool": "reverse_dns_lookup", "ip": ip, "found": False, "hostname": None}
