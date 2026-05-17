from agent.tools import ping_host, reverse_dns_lookup, run_tcp_connect_scan


def scan_host_tcp_ports(host: str, ports: str = "1-1024") -> dict:
    ping_result = ping_host(host, count=1)
    port_scan = run_tcp_connect_scan(host=host, ports=ports)
    dns_result = reverse_dns_lookup(host) if host.replace(".", "").isdigit() else {}

    if not port_scan.get("success"):
        status = "scan_failed"
    elif port_scan.get("open_count", 0):
        status = "open_ports_found"
    else:
        status = "no_open_ports_found"

    return {
        "skill": "scan_host_tcp_ports",
        "host": host,
        "ports": port_scan.get("ports", ports),
        "status": status,
        "checks": {
            "ping": ping_result,
            "dns": dns_result,
            "port_scan": port_scan,
        },
    }
