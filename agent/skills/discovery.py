from agent.config import DEFAULT_NETWORK_SCANNER
from agent.tools import (
    compare_known_hosts,
    load_known_hosts,
    reverse_dns_lookup,
    run_masscan_icmp,
    run_masscan_ports,
    run_nmap_host_discovery,
    run_nmap_ports,
    run_nmap_service_detection,
    store_known_hosts,
)


_SKIPPED_INVENTORY_RESULT = {
    "tool": "inventory",
    "success": False,
    "skipped": True,
    "reason": "scan_incomplete",
}
_ALLOWED_SCANNERS = {"nmap", "masscan"}
_ALLOWED_SERVICE_DETECTION = {None, "none", "safe", "deep"}
_ALLOWED_SCAN_PROFILES = {"quick", "default", "deep"}
_PROFILE_PORTS_SENTINEL = object()
SCAN_PROFILE_DEFAULT_PORTS = {
    "quick": "22,443",
    "default": "22,80,443",
    "deep": "1-1024",
}


def _normalize_scanner(scanner: str | None) -> str:
    normalized = (scanner or DEFAULT_NETWORK_SCANNER or "nmap").strip().lower()
    if normalized not in _ALLOWED_SCANNERS:
        raise ValueError(f"Unsupported scanner: {scanner}")
    return normalized


def _normalize_service_detection(profile: str | None) -> str | None:
    if profile is None:
        return None
    normalized = profile.strip().lower()
    if normalized not in _ALLOWED_SERVICE_DETECTION:
        raise ValueError(f"Unsupported service detection profile: {profile}")
    return None if normalized == "none" else normalized


def _normalize_scan_profile(profile: str | None) -> str:
    normalized = (profile or "default").strip().lower()
    if normalized not in _ALLOWED_SCAN_PROFILES:
        raise ValueError(f"Unsupported scan profile: {profile}")
    return normalized


def _resolve_profile_ports(ports: str | None | object, scan_profile: str) -> str | None:
    if ports is _PROFILE_PORTS_SENTINEL or ports == "profile":
        return SCAN_PROFILE_DEFAULT_PORTS[scan_profile]
    return ports


def _run_discovery_scan(scanner: str, cidr: str) -> dict:
    if scanner == "masscan":
        return run_masscan_icmp(cidr=cidr)
    return run_nmap_host_discovery(cidr=cidr)


def _run_port_scan(scanner: str, cidr: str, ports: str) -> dict:
    if scanner == "masscan":
        return run_masscan_ports(cidr=cidr, ports=ports)
    return run_nmap_ports(cidr=cidr, ports=ports)


def _merge_port_details(host_record: dict, port_entries: list[dict]) -> None:
    existing = {
        (item.get("port"), item.get("proto", "tcp")): dict(item)
        for item in host_record.get("ports", [])
        if item.get("port") is not None
    }

    for entry in port_entries:
        key = (entry.get("port"), entry.get("proto", "tcp"))
        if key == (None, None):
            continue
        merged = existing.get(key, {}).copy()
        merged.update({k: v for k, v in entry.items() if v not in (None, "")})
        if key[0] is not None:
            merged.setdefault("port", key[0])
        merged.setdefault("proto", key[1] or "tcp")
        existing[key] = merged

    host_record["ports"] = sorted(existing.values(), key=lambda item: (item.get("port", 0), item.get("proto", "tcp")))


def discover_network_hosts(
    cidr: str,
    ports: str | None | object = _PROFILE_PORTS_SENTINEL,
    scanner: str | None = None,
    scan_profile: str | None = None,
    service_detection: str | None = None,
) -> dict:
    scanner = _normalize_scanner(scanner)
    scan_profile = _normalize_scan_profile(scan_profile)
    ports = _resolve_profile_ports(ports, scan_profile)
    service_detection = _normalize_service_detection(service_detection)

    try:
        previous_hosts = load_known_hosts()
    except Exception:
        previous_hosts = {}

    try:
        icmp_scan = _run_discovery_scan(scanner, cidr)
        port_scan = _run_port_scan(scanner, cidr, ports) if ports else {
            "tool": f"run_{scanner}_ports",
            "cidr": cidr,
            "ports": None,
            "success": True,
            "findings": [],
            "count": 0,
            "stdout": "",
            "stderr": "",
            "error": None,
            "command": [],
            "skipped": True,
        }
    except Exception as exc:
        return {
            "skill": "discover_network_hosts",
            "cidr": cidr,
            "ports": ports,
            "scanner": scanner,
            "scan_profile": scan_profile,
            "service_detection": service_detection,
            "host_count": 0,
            "hosts": {},
            "status": "scan_failed",
            "error": str(exc),
        }

    hosts = {}
    warnings = []

    for ip in icmp_scan.get("alive_hosts", []):
        hosts[ip] = {"hostname": None, "alive_icmp": True, "ports": []}

    for item in port_scan.get("findings", []):
        ip = item.get("ip")
        if not ip:
            continue

        hosts.setdefault(ip, {"hostname": None, "alive_icmp": False, "ports": []})
        _merge_port_details(hosts[ip], item.get("ports", []))

    icmp_success = bool(icmp_scan.get("success"))
    port_scan_skipped = bool(port_scan.get("skipped"))
    port_scan_success = bool(port_scan.get("success")) or port_scan_skipped
    primary_scan_complete = icmp_success and port_scan_success

    discovery_tool = icmp_scan.get("tool") or f"run_{scanner}_host_discovery"
    port_tool = port_scan.get("tool") or f"run_{scanner}_ports"
    discovery_label = discovery_tool.replace("run_", "").replace("_", " ")
    port_label = port_tool.replace("run_", "").replace("_", " ")

    if not icmp_success:
        warnings.append(f"Discovery scan failed ({discovery_label}): {icmp_scan.get('error') or 'scan returned an error'}")
    if not port_scan_success:
        warnings.append(f"Port scan failed ({port_label}): {port_scan.get('error') or 'scan returned an error'}")

    service_scan = {
        "tool": "run_nmap_service_detection",
        "success": True,
        "skipped": True,
        "profile": service_detection,
        "findings": [],
        "count": 0,
        "stdout": "",
        "stderr": "",
        "error": None,
        "command": [],
    }
    if service_detection:
        if scanner != "nmap":
            service_scan.update({
                "success": False,
                "error": "service detection is only supported with the nmap scanner",
                "reason": "scanner_unsupported",
            })
            warnings.append("Service detection was requested but skipped because it is only supported with nmap scans.")
        elif not ports:
            service_scan.update({
                "success": False,
                "error": "service detection requires a port scan",
                "reason": "ports_required",
            })
            warnings.append("Service detection was requested but skipped because ping-only scans have no port targets.")
        elif not port_scan_success:
            service_scan.update({
                "success": False,
                "error": "service detection skipped because the port scan did not complete cleanly",
                "reason": "port_scan_incomplete",
            })
            warnings.append("Service detection was skipped because the port scan did not complete cleanly.")
        else:
            service_hosts = sorted(ip for ip, info in hosts.items() if info.get("ports"))
            try:
                service_scan = run_nmap_service_detection(service_hosts, ports=ports, profile=service_detection)
            except Exception as exc:
                service_scan = {
                    "tool": "run_nmap_service_detection",
                    "success": False,
                    "skipped": False,
                    "profile": service_detection,
                    "findings": [],
                    "count": 0,
                    "stdout": "",
                    "stderr": "",
                    "error": str(exc),
                    "command": [],
                }

            if service_scan.get("success"):
                for item in service_scan.get("findings", []):
                    ip = item.get("ip")
                    if not ip or ip not in hosts:
                        continue
                    _merge_port_details(hosts[ip], item.get("ports", []))
            else:
                warnings.append(
                    f"Service detection failed: {service_scan.get('error') or 'nmap returned an error'}"
                )

    dns_results = {}
    for ip in hosts:
        previous_info = previous_hosts.get(ip, {}) if isinstance(previous_hosts, dict) else {}
        try:
            dns_result = reverse_dns_lookup(ip)
        except Exception as exc:
            dns_result = {
                "tool": "reverse_dns_lookup",
                "ip": ip,
                "found": False,
                "hostname": None,
                "error": str(exc),
            }
            warnings.append(f"Reverse DNS lookup failed for {ip}: {exc}")
        dns_results[ip] = dns_result
        hosts[ip]["hostname"] = dns_result.get("hostname") or previous_info.get("hostname")
        if port_scan_skipped and not hosts[ip]["ports"]:
            hosts[ip]["ports"] = list(previous_info.get("ports", []))

    if primary_scan_complete:
        try:
            compare_result = compare_known_hosts(
                hosts,
                preserve_hostname_when_missing=True,
                preserve_ports_when_missing=port_scan_skipped,
                scope_cidr=cidr,
            )
        except Exception as exc:
            compare_result = {
                "tool": "compare_known_hosts",
                "success": False,
                "error": str(exc),
                "new_hosts": [],
                "disappeared_hosts": [],
                "changed_hosts": [],
            }
            warnings.append(f"Inventory comparison failed: {exc}")

        try:
            store_result = store_known_hosts(
                hosts,
                preserve_hostname_when_missing=True,
                preserve_ports_when_missing=port_scan_skipped,
            )
        except Exception as exc:
            store_result = {
                "tool": "store_known_hosts",
                "success": False,
                "error": str(exc),
                "added": 0,
                "updated": 0,
            }
            warnings.append(f"Known-hosts update failed: {exc}")
    else:
        compare_result = dict(_SKIPPED_INVENTORY_RESULT, tool="compare_known_hosts")
        store_result = dict(_SKIPPED_INVENTORY_RESULT, tool="store_known_hosts")
        warnings.append("Inventory compare/store skipped because the scan did not complete cleanly.")

    if primary_scan_complete:
        status = "ok_with_warnings" if warnings else "ok"
    elif hosts:
        status = "partial_scan"
    else:
        status = "scan_failed"

    return {
        "skill": "discover_network_hosts",
        "cidr": cidr,
        "ports": ports,
        "scanner": scanner,
        "scan_profile": scan_profile,
        "service_detection": service_detection,
        "host_count": len(hosts),
        "hosts": hosts,
        "status": status,
        "checks": {
            "icmp_scan": icmp_scan,
            "port_scan": port_scan,
            "service_scan": service_scan,
            "dns": dns_results,
            "compare": compare_result,
            "store": store_result,
            "warnings": warnings,
        },
    }
