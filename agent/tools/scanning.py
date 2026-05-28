import errno
import json
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from agent.config import ALLOW_SUDO, DEFAULT_SCAN_RATE, MASSCAN_BINARY, NMAP_BINARY

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


def _build_nmap_base_cmd() -> list[str]:
    binary = shutil.which(NMAP_BINARY)
    if not binary:
        raise RuntimeError(f"nmap binary not found: {NMAP_BINARY}")

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


def _parse_nmap_xml(xml_text: str) -> ET.Element | None:
    if not xml_text.strip():
        return None

    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        return None


def _read_nmap_hosts(xml_text: str) -> list[dict]:
    root = _parse_nmap_xml(xml_text)
    if root is None:
        return []

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address = host.find("address[@addrtype='ipv4']")
        if address is None or not address.get("addr"):
            continue

        hostnames = [
            entry.get("name")
            for entry in host.findall("hostnames/hostname")
            if entry.get("name")
        ]
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid")
            if not port_id:
                continue
            ports.append(
                {
                    "port": int(port_id),
                    "proto": port.get("protocol", "tcp"),
                }
            )

        hosts.append({"ip": address.get("addr"), "hostnames": hostnames, "ports": ports})

    return hosts


def _run_command(args: list[str], timeout: int = 120, tool_name: str = "command") -> tuple[subprocess.CompletedProcess | None, str | None]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result, None
    except subprocess.TimeoutExpired:
        return None, f"{tool_name} timed out"
    except FileNotFoundError:
        return None, f"{tool_name} binary not found"
    except Exception as exc:  # pragma: no cover
        return None, str(exc)


def _run_masscan(args: list[str], timeout: int = 120) -> tuple[subprocess.CompletedProcess | None, str | None]:
    return _run_command(args, timeout=timeout, tool_name="masscan")


def _run_nmap(args: list[str], timeout: int = 180) -> tuple[subprocess.CompletedProcess | None, str | None]:
    return _run_command(args, timeout=timeout, tool_name="nmap")


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


def run_nmap_host_discovery(cidr: str) -> dict:
    cidr = validate_scan_target(cidr)
    cmd = _build_nmap_base_cmd() + ["-sn", "-n", "-oX", "-", cidr]

    result, error = _run_nmap(cmd)
    stdout = result.stdout if result else ""
    hosts = _read_nmap_hosts(stdout)
    alive_hosts = sorted({item.get("ip") for item in hosts if item.get("ip")})

    return {
        "tool": "run_nmap_host_discovery",
        "cidr": cidr,
        "success": bool(result and result.returncode == 0),
        "alive_hosts": alive_hosts,
        "count": len(alive_hosts),
        "stdout": stdout,
        "stderr": result.stderr if result else "",
        "error": error,
        "command": cmd,
    }


def run_nmap_ports(cidr: str, ports: str = "22,80,443") -> dict:
    cidr = validate_scan_target(cidr)
    ports = validate_ports(ports)
    cmd = _build_nmap_base_cmd() + ["-n", "-Pn", "-p", ports, "-oX", "-", cidr]

    result, error = _run_nmap(cmd)
    stdout = result.stdout if result else ""
    hosts = _read_nmap_hosts(stdout)
    findings = [{"ip": item["ip"], "ports": item["ports"]} for item in hosts if item.get("ports")]

    return {
        "tool": "run_nmap_ports",
        "cidr": cidr,
        "ports": ports,
        "success": bool(result and result.returncode == 0),
        "findings": findings,
        "count": len(findings),
        "stdout": stdout,
        "stderr": result.stderr if result else "",
        "error": error,
        "command": cmd,
    }
