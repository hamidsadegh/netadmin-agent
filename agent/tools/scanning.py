import errno
import json
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

from agent.config import ALLOW_SUDO, DEFAULT_SCAN_RATE, MASSCAN_BINARY

from .safety import validate_host, validate_ports, validate_scan_target


MAX_CONNECT_SCAN_PORTS = 1024
_FATAL_CONNECT_ERRNOS = {
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.ENETDOWN,
    errno.EHOSTDOWN,
}


def _expand_ports(ports: str) -> list[int]:
    normalized = validate_ports(ports)
    expanded = []

    for item in normalized.split(","):
        if "-" in item:
            start, end = (int(part) for part in item.split("-", 1))
            expanded.extend(range(start, end + 1))
        else:
            expanded.append(int(item))

    if len(expanded) > MAX_CONNECT_SCAN_PORTS:
        raise ValueError(f"Connect scan is limited to {MAX_CONNECT_SCAN_PORTS} ports")

    return expanded


def run_tcp_connect_scan(host: str, ports: str, timeout: float = 0.5) -> dict:
    host = validate_host(host)
    normalized_ports = validate_ports(ports)
    port_numbers = _expand_ports(normalized_ports)
    timeout = max(0.1, min(float(timeout), 3.0))

    findings = []
    closed_count = 0
    timed_out_count = 0
    errors = {}
    fatal_error = None

    for port in port_numbers:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                findings.append({"port": port, "proto": "tcp", "open": True})
        except ConnectionRefusedError as exc:
            closed_count += 1
            error_text = str(exc)
            errors[error_text] = errors.get(error_text, 0) + 1
        except socket.timeout as exc:
            timed_out_count += 1
            error_text = str(exc) or "Connection timed out"
            errors[error_text] = errors.get(error_text, 0) + 1
        except OSError as exc:
            if exc.errno in _FATAL_CONNECT_ERRNOS:
                fatal_error = str(exc)
                errors[fatal_error] = errors.get(fatal_error, 0) + 1
                break

            closed_count += 1
            error_text = str(exc)
            errors[error_text] = errors.get(error_text, 0) + 1

    scanned_count = len(findings) + closed_count + timed_out_count
    if fatal_error:
        scanned_count += 1

    return {
        "tool": "run_tcp_connect_scan",
        "host": host,
        "ports": normalized_ports,
        "scanned_count": scanned_count,
        "requested_count": len(port_numbers),
        "open_count": len(findings),
        "closed_count": closed_count,
        "timed_out_count": timed_out_count,
        "findings": findings,
        "errors": errors,
        "success": fatal_error is None,
        "error": fatal_error,
    }


def _build_masscan_base_cmd() -> list[str]:
    binary = shutil.which(MASSCAN_BINARY)
    if not binary:
        raise RuntimeError(f"masscan binary not found: {MASSCAN_BINARY}")

    cmd = []
    if ALLOW_SUDO:
        sudo_binary = shutil.which("sudo")
        if not sudo_binary:
            raise RuntimeError("sudo requested but not available")
        cmd.append(sudo_binary)

    cmd.append(binary)
    return cmd


def _read_masscan_output(path: Path) -> list:
    if not path.exists():
        return []

    raw = path.read_text().strip()
    if not raw:
        return []

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def _run_masscan(args: list[str], timeout: int = 120) -> tuple[subprocess.CompletedProcess | None, str | None]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result, None
    except subprocess.TimeoutExpired:
        return None, "masscan timed out"
    except FileNotFoundError:
        return None, "masscan binary not found"
    except Exception as exc:  # pragma: no cover
        return None, str(exc)


def run_masscan_ports(cidr: str, ports: str = "22,80,443", rate: int = DEFAULT_SCAN_RATE) -> dict:
    cidr = validate_scan_target(cidr)
    ports = validate_ports(ports)
    rate = max(100, min(int(rate), 5000))

    with tempfile.NamedTemporaryFile(prefix="masscan-ports-", suffix=".json", delete=False) as tmp:
        output_file = Path(tmp.name)

    cmd = _build_masscan_base_cmd() + [
        cidr,
        f"-p{ports}",
        "--rate",
        str(rate),
        "--wait",
        "5",
        "--output-format",
        "json",
        "--output-filename",
        str(output_file),
    ]

    result, error = _run_masscan(cmd)
    findings = _read_masscan_output(output_file)
    output_file.unlink(missing_ok=True)

    return {
        "tool": "run_masscan_ports",
        "cidr": cidr,
        "ports": ports,
        "rate": rate,
        "success": bool(result and result.returncode == 0),
        "findings": findings,
        "count": len(findings),
        "stdout": result.stdout if result else "",
        "stderr": result.stderr if result else "",
        "error": error,
        "command": cmd,
    }


def run_masscan_icmp(cidr: str, rate: int = DEFAULT_SCAN_RATE) -> dict:
    cidr = validate_scan_target(cidr)
    rate = max(100, min(int(rate), 5000))

    with tempfile.NamedTemporaryFile(prefix="masscan-icmp-", suffix=".json", delete=False) as tmp:
        output_file = Path(tmp.name)

    cmd = _build_masscan_base_cmd() + [
        cidr,
        "--ping",
        "--rate",
        str(rate),
        "--wait",
        "5",
        "--output-format",
        "json",
        "--output-filename",
        str(output_file),
    ]

    result, error = _run_masscan(cmd)
    findings = _read_masscan_output(output_file)
    output_file.unlink(missing_ok=True)

    alive_hosts = sorted({item.get("ip") for item in findings if item.get("ip")})

    return {
        "tool": "run_masscan_icmp",
        "cidr": cidr,
        "rate": rate,
        "success": bool(result and result.returncode == 0),
        "alive_hosts": alive_hosts,
        "count": len(alive_hosts),
        "stdout": result.stdout if result else "",
        "stderr": result.stderr if result else "",
        "error": error,
        "command": cmd,
    }
