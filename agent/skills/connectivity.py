from agent.tools import check_tcp_port, ping_host


def check_device_connectivity(host: str) -> dict:
    ping_result = ping_host(host, count=3)
    ssh_result = check_tcp_port(host, port=22)

    if ping_result.get("reachable") and ssh_result.get("open"):
        status = "reachable_and_ssh_open"
    elif ping_result.get("reachable") and not ssh_result.get("open"):
        status = "reachable_but_ssh_closed"
    elif not ping_result.get("reachable") and ssh_result.get("open"):
        status = "icmp_blocked_but_ssh_open"
    else:
        status = "not_reachable"

    return {
        "skill": "check_device_connectivity",
        "host": host,
        "status": status,
        "checks": {"ping": ping_result, "ssh": ssh_result},
    }
