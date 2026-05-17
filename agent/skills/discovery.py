from agent.tools import (
    compare_known_hosts,
    load_known_hosts,
    reverse_dns_lookup,
    run_masscan_icmp,
    run_masscan_ports,
    store_known_hosts,
)


_SKIPPED_INVENTORY_RESULT = {
    "tool": "inventory",
    "success": False,
    "skipped": True,
    "reason": "scan_incomplete",
}


def discover_network_hosts(cidr: str, ports: str | None = "22,80,443") -> dict:
    try:
        previous_hosts = load_known_hosts()
    except Exception:
        previous_hosts = {}

    try:
        icmp_scan = run_masscan_icmp(cidr=cidr)
        port_scan = run_masscan_ports(cidr=cidr, ports=ports) if ports else {
            "tool": "run_masscan_ports",
            "cidr": cidr,
            "ports": None,
            "rate": None,
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

        for port_info in item.get("ports", []):
            hosts[ip]["ports"].append(
                {"port": port_info.get("port"), "proto": port_info.get("proto", "tcp")}
            )

    icmp_success = bool(icmp_scan.get("success"))
    port_scan_skipped = bool(port_scan.get("skipped"))
    port_scan_success = bool(port_scan.get("success")) or port_scan_skipped
    primary_scan_complete = icmp_success and port_scan_success

    if not icmp_success:
        warnings.append(f"ICMP scan failed: {icmp_scan.get('error') or 'masscan returned an error'}")
    if not port_scan_success:
        warnings.append(f"Port scan failed: {port_scan.get('error') or 'masscan returned an error'}")

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
        "host_count": len(hosts),
        "hosts": hosts,
        "status": status,
        "checks": {
            "icmp_scan": icmp_scan,
            "port_scan": port_scan,
            "dns": dns_results,
            "compare": compare_result,
            "store": store_result,
            "warnings": warnings,
        },
    }
