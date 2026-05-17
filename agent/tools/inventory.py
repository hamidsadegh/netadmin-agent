import ipaddress
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agent.config import KNOWN_HOSTS_FILE


def _normalize_ports(ports: list[dict] | None) -> list[dict]:
    normalized = []
    seen = set()

    for item in ports or []:
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue

        proto = str(item.get("proto", "tcp")).lower()
        key = (port, proto)
        if key in seen:
            continue

        seen.add(key)
        normalized.append({"port": port, "proto": proto})

    return sorted(normalized, key=lambda item: (item["port"], item["proto"]))


def _normalize_host_info(info: dict) -> dict:
    return {
        "hostname": info.get("hostname"),
        "alive_icmp": bool(info.get("alive_icmp", False)),
        "ports": _normalize_ports(info.get("ports")),
    }


def _prepare_hosts_for_inventory(
    hosts: dict,
    previous_hosts: dict,
    *,
    preserve_hostname_when_missing: bool = False,
    preserve_ports_when_missing: bool = False,
) -> dict:
    prepared = {}

    for ip, info in hosts.items():
        normalized = _normalize_host_info(info)
        previous = _normalize_host_info(previous_hosts.get(ip, {}))

        if preserve_hostname_when_missing and not normalized["hostname"]:
            normalized["hostname"] = previous.get("hostname")

        if preserve_ports_when_missing and not normalized["ports"]:
            normalized["ports"] = previous.get("ports", [])

        prepared[ip] = normalized

    return prepared


def _filter_hosts_by_scope(hosts: dict, scope_cidr: str | None) -> dict:
    if not scope_cidr:
        return hosts

    network = ipaddress.ip_network(scope_cidr, strict=False)
    filtered = {}

    for ip, info in hosts.items():
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address in network:
            filtered[ip] = info

    return filtered


def load_known_hosts() -> dict:
    if not KNOWN_HOSTS_FILE.exists():
        return {}

    try:
        loaded = json.loads(KNOWN_HOSTS_FILE.read_text())
    except json.JSONDecodeError:
        return {}

    return loaded if isinstance(loaded, dict) else {}


def save_known_hosts(data: dict) -> None:
    destination = Path(KNOWN_HOSTS_FILE)
    destination.parent.mkdir(parents=True, exist_ok=True)

    rendered = json.dumps(data, indent=2, sort_keys=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        delete=False,
    ) as tmp:
        tmp.write(rendered.encode())
        tmp.flush()
        temp_path = Path(tmp.name)

    temp_path.replace(destination)


def store_known_hosts(
    hosts: dict,
    *,
    preserve_hostname_when_missing: bool = False,
    preserve_ports_when_missing: bool = False,
) -> dict:
    db = load_known_hosts()
    prepared_hosts = _prepare_hosts_for_inventory(
        hosts,
        db,
        preserve_hostname_when_missing=preserve_hostname_when_missing,
        preserve_ports_when_missing=preserve_ports_when_missing,
    )
    now = datetime.now(timezone.utc).isoformat()

    added = 0
    updated = 0
    unchanged = 0

    for ip, normalized_info in prepared_hosts.items():
        previous_info = _normalize_host_info(db.get(ip, {}))

        if ip not in db:
            added += 1
            db[ip] = {"ip": ip, "first_seen": now}
        elif previous_info != normalized_info:
            updated += 1
        else:
            unchanged += 1

        db[ip].update(
            {
                "last_seen": now,
                "hostname": normalized_info["hostname"],
                "alive_icmp": normalized_info["alive_icmp"],
                "ports": normalized_info["ports"],
                "source": "netadmin-agent",
            }
        )

    save_known_hosts(db)

    return {
        "tool": "store_known_hosts",
        "file": str(KNOWN_HOSTS_FILE),
        "added": added,
        "updated": updated,
        "unchanged": unchanged,
        "total_known_hosts": len(db),
    }


def compare_known_hosts(
    current_hosts: dict,
    *,
    preserve_hostname_when_missing: bool = False,
    preserve_ports_when_missing: bool = False,
    scope_cidr: str | None = None,
) -> dict:
    previous_hosts = load_known_hosts()
    scoped_previous_hosts = _filter_hosts_by_scope(previous_hosts, scope_cidr)
    prepared_hosts = _prepare_hosts_for_inventory(
        current_hosts,
        previous_hosts,
        preserve_hostname_when_missing=preserve_hostname_when_missing,
        preserve_ports_when_missing=preserve_ports_when_missing,
    )

    previous_ips = set(scoped_previous_hosts)
    current_ips = set(prepared_hosts)

    new_hosts = sorted(current_ips - previous_ips)
    disappeared_hosts = sorted(previous_ips - current_ips)
    changed_hosts = []

    for ip in sorted(current_ips & previous_ips):
        previous = _normalize_host_info(scoped_previous_hosts.get(ip, {}))
        current = prepared_hosts.get(ip, _normalize_host_info({}))

        change = {}
        if previous.get("hostname") != current.get("hostname"):
            change["hostname"] = {
                "previous": previous.get("hostname"),
                "current": current.get("hostname"),
            }
        if previous.get("alive_icmp") != current.get("alive_icmp"):
            change["alive_icmp"] = {
                "previous": previous.get("alive_icmp"),
                "current": current.get("alive_icmp"),
            }
        if previous.get("ports", []) != current.get("ports", []):
            change["ports"] = {
                "previous": previous.get("ports", []),
                "current": current.get("ports", []),
            }

        if change:
            changed_hosts.append({"ip": ip, "changes": change})

    return {
        "tool": "compare_known_hosts",
        "file": str(KNOWN_HOSTS_FILE),
        "scope_cidr": scope_cidr,
        "new_hosts": new_hosts,
        "disappeared_hosts": disappeared_hosts,
        "changed_hosts": changed_hosts,
        "current_count": len(prepared_hosts),
        "previous_count": len(scoped_previous_hosts),
    }
