from agent.cli.parsing import parse_direct_skill_request
from agent.cli.formatting import format_result_for_fallback
from agent.skills.discovery import discover_network_hosts
from agent.tools import inventory

import json


def test_parse_direct_skill_request_ping_only_scan_sets_ports_none():
    parsed = parse_direct_skill_request("scan 192.168.178.0/24 for ping")
    assert parsed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.178.0/24", "ports": None},
    }


def test_parse_direct_skill_request_subnet_first_ports_uses_requested_range():
    parsed = parse_direct_skill_request("scan 192.168.178.0/24 first 100 ports")
    assert parsed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.178.0/24", "ports": "1-100"},
    }


def test_parse_direct_skill_request_supports_explicit_masscan():
    parsed = parse_direct_skill_request("masscan 192.168.178.0/24 ports 22,80,443")
    assert parsed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.178.0/24", "ports": "22,80,443", "scanner": "masscan"},
    }


def test_discover_network_hosts_uses_nmap_by_default(monkeypatch):
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: {"alive_hosts": ["192.168.1.10"], "success": True, "tool": "run_nmap_host_discovery"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_ports",
        lambda cidr, ports: (_ for _ in ()).throw(AssertionError("port scan should be skipped")),
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_masscan_icmp",
        lambda cidr: (_ for _ in ()).throw(AssertionError("masscan should not be used by default")),
    )
    monkeypatch.setattr("agent.skills.discovery.reverse_dns_lookup", lambda ip: {"hostname": None})
    monkeypatch.setattr("agent.skills.discovery.compare_known_hosts", lambda hosts, **kwargs: {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": []})
    monkeypatch.setattr("agent.skills.discovery.store_known_hosts", lambda hosts, **kwargs: {"added": 0, "updated": 0})

    result = discover_network_hosts("192.168.1.0/24", ports=None)
    assert result["scanner"] == "nmap"
    assert result["ports"] is None
    assert result["checks"]["port_scan"]["skipped"] is True
    assert result["host_count"] == 1


def test_discover_network_hosts_honors_explicit_masscan(monkeypatch):
    monkeypatch.setattr(
        "agent.skills.discovery.run_masscan_icmp",
        lambda cidr: {"alive_hosts": ["192.168.1.10"], "success": True, "tool": "run_masscan_icmp"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_masscan_ports",
        lambda cidr, ports: {"findings": [], "success": True, "tool": "run_masscan_ports"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: (_ for _ in ()).throw(AssertionError("nmap should not be used when masscan was requested")),
    )
    monkeypatch.setattr("agent.skills.discovery.reverse_dns_lookup", lambda ip: {"hostname": None})
    monkeypatch.setattr("agent.skills.discovery.compare_known_hosts", lambda hosts, **kwargs: {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": []})
    monkeypatch.setattr("agent.skills.discovery.store_known_hosts", lambda hosts, **kwargs: {"added": 0, "updated": 0})

    result = discover_network_hosts("192.168.1.0/24", ports="22", scanner="masscan")
    assert result["scanner"] == "masscan"
    assert result["status"] == "ok"


def test_discover_network_hosts_ping_only_preserves_existing_inventory_details(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(inventory, "KNOWN_HOSTS_FILE", db_path)
    db_path.write_text(
        json.dumps(
            {
                "192.168.1.10": {
                    "hostname": "switch.local",
                    "alive_icmp": True,
                    "ports": [{"port": 22, "proto": "tcp"}],
                }
            }
        )
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: {"alive_hosts": ["192.168.1.10"], "success": True, "tool": "run_nmap_host_discovery"},
    )
    monkeypatch.setattr("agent.skills.discovery.reverse_dns_lookup", lambda ip: {"hostname": None})

    result = discover_network_hosts("192.168.1.0/24", ports=None)

    assert result["status"] == "ok"
    assert result["checks"]["compare"]["changed_hosts"] == []
    assert result["hosts"]["192.168.1.10"]["hostname"] == "switch.local"
    assert result["hosts"]["192.168.1.10"]["ports"] == [{"port": 22, "proto": "tcp"}]
    saved = json.loads(db_path.read_text())
    assert saved["192.168.1.10"]["hostname"] == "switch.local"
    assert saved["192.168.1.10"]["ports"] == [{"port": 22, "proto": "tcp"}]


def test_discover_network_hosts_full_scan_preserves_hostname_when_reverse_dns_is_empty(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(inventory, "KNOWN_HOSTS_FILE", db_path)
    db_path.write_text(
        json.dumps(
            {
                "192.168.1.10": {
                    "hostname": "switch.local",
                    "alive_icmp": True,
                    "ports": [{"port": 22, "proto": "tcp"}],
                }
            }
        )
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: {"alive_hosts": ["192.168.1.10"], "success": True, "tool": "run_nmap_host_discovery"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_ports",
        lambda cidr, ports: {"findings": [{"ip": "192.168.1.10", "ports": [{"port": 22, "proto": "tcp"}]}], "success": True, "tool": "run_nmap_ports"},
    )
    monkeypatch.setattr("agent.skills.discovery.reverse_dns_lookup", lambda ip: {"hostname": None})

    result = discover_network_hosts("192.168.1.0/24", ports="22")

    assert result["status"] == "ok"
    assert result["checks"]["compare"]["changed_hosts"] == []
    assert result["hosts"]["192.168.1.10"]["hostname"] == "switch.local"
    saved = json.loads(db_path.read_text())
    assert saved["192.168.1.10"]["hostname"] == "switch.local"


def test_discover_network_hosts_keeps_scan_results_when_auxiliary_steps_fail(monkeypatch):
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: {"alive_hosts": ["192.168.1.10"], "success": True, "tool": "run_nmap_host_discovery"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_ports",
        lambda cidr, ports: {"findings": [], "success": True, "tool": "run_nmap_ports"},
    )

    def fake_reverse_dns_lookup(ip):
        raise RuntimeError("dns backend unavailable")

    monkeypatch.setattr("agent.skills.discovery.reverse_dns_lookup", fake_reverse_dns_lookup)
    monkeypatch.setattr(
        "agent.skills.discovery.compare_known_hosts",
        lambda hosts, **kwargs: (_ for _ in ()).throw(PermissionError("known_hosts.json is read-only")),
    )
    monkeypatch.setattr(
        "agent.skills.discovery.store_known_hosts",
        lambda hosts, **kwargs: (_ for _ in ()).throw(PermissionError("known_hosts.json is read-only")),
    )

    result = discover_network_hosts("192.168.1.0/24", ports="22")
    assert result["status"] == "ok_with_warnings"
    assert result["host_count"] == 1
    assert result["hosts"]["192.168.1.10"]["hostname"] is None
    assert "dns backend unavailable" in result["checks"]["dns"]["192.168.1.10"]["error"]
    assert result["checks"]["compare"]["success"] is False
    assert result["checks"]["store"]["success"] is False
    assert len(result["checks"]["warnings"]) == 3


def test_discover_network_hosts_marks_partial_scan_and_skips_inventory_on_primary_failure(monkeypatch):
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: {"alive_hosts": ["192.168.1.10"], "success": True, "tool": "run_nmap_host_discovery"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_ports",
        lambda cidr, ports: {"findings": [], "success": False, "error": "permission denied", "stderr": "need to sudo", "tool": "run_nmap_ports"},
    )
    monkeypatch.setattr("agent.skills.discovery.reverse_dns_lookup", lambda ip: {"hostname": None})
    monkeypatch.setattr(
        "agent.skills.discovery.compare_known_hosts",
        lambda hosts: (_ for _ in ()).throw(AssertionError("inventory compare should be skipped")),
    )
    monkeypatch.setattr(
        "agent.skills.discovery.store_known_hosts",
        lambda hosts: (_ for _ in ()).throw(AssertionError("inventory store should be skipped")),
    )

    result = discover_network_hosts("192.168.1.0/24", ports="22")
    assert result["status"] == "partial_scan"
    assert result["host_count"] == 1
    assert result["checks"]["compare"]["skipped"] is True
    assert result["checks"]["store"]["skipped"] is True
    assert "Inventory compare/store skipped" in result["checks"]["warnings"][-1]


def test_discover_network_hosts_marks_full_primary_failure_without_inventory_churn(monkeypatch):
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: {"alive_hosts": [], "success": False, "error": "permission denied", "stderr": "need to sudo", "tool": "run_nmap_host_discovery"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_ports",
        lambda cidr, ports: {"findings": [], "success": False, "error": "permission denied", "stderr": "need to sudo", "tool": "run_nmap_ports"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.compare_known_hosts",
        lambda hosts: (_ for _ in ()).throw(AssertionError("inventory compare should be skipped")),
    )
    monkeypatch.setattr(
        "agent.skills.discovery.store_known_hosts",
        lambda hosts: (_ for _ in ()).throw(AssertionError("inventory store should be skipped")),
    )

    result = discover_network_hosts("192.168.1.0/24", ports="22")
    assert result["status"] == "scan_failed"
    assert result["host_count"] == 0
    assert result["checks"]["compare"]["skipped"] is True
    assert result["checks"]["store"]["skipped"] is True


def test_discover_network_hosts_compares_inventory_within_scanned_cidr(monkeypatch):
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_host_discovery",
        lambda cidr: {"alive_hosts": ["192.168.1.10"], "success": True, "tool": "run_nmap_host_discovery"},
    )
    monkeypatch.setattr(
        "agent.skills.discovery.run_nmap_ports",
        lambda cidr, ports: {"findings": [], "success": True, "tool": "run_nmap_ports"},
    )
    monkeypatch.setattr("agent.skills.discovery.reverse_dns_lookup", lambda ip: {"hostname": None})

    compare_calls = []

    def fake_compare(hosts, **kwargs):
        compare_calls.append(kwargs)
        return {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": [], "scope_cidr": kwargs.get("scope_cidr")}

    monkeypatch.setattr("agent.skills.discovery.compare_known_hosts", fake_compare)
    monkeypatch.setattr("agent.skills.discovery.store_known_hosts", lambda hosts, **kwargs: {"added": 0, "updated": 0})

    result = discover_network_hosts("192.168.1.0/24", ports="22")

    assert result["status"] == "ok"
    assert compare_calls[0]["scope_cidr"] == "192.168.1.0/24"


def test_format_result_for_fallback_marks_ping_only():
    text = format_result_for_fallback(
        {
            "skill": "discover_network_hosts",
            "cidr": "192.168.1.0/24",
            "ports": None,
            "scanner": "nmap",
            "host_count": 1,
            "status": "ok",
            "hosts": {"192.168.1.10": {"hostname": None, "ports": []}},
            "checks": {
                "icmp_scan": {},
                "port_scan": {"skipped": True},
                "compare": {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": []},
            },
        }
    )
    assert "Scanner: nmap" in text
    assert "Ports: ping-only" in text


def test_format_result_for_fallback_shows_preserved_inventory_details_for_ping_only_scan():
    text = format_result_for_fallback(
        {
            "skill": "discover_network_hosts",
            "cidr": "192.168.1.0/24",
            "ports": None,
            "scanner": "nmap",
            "host_count": 1,
            "status": "ok",
            "hosts": {
                "192.168.1.10": {
                    "hostname": "switch.local",
                    "ports": [{"port": 22, "proto": "tcp"}],
                }
            },
            "checks": {
                "icmp_scan": {},
                "port_scan": {"skipped": True},
                "compare": {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": []},
            },
        }
    )
    assert "- 192.168.1.10 (switch.local) ports: 22" in text


def test_format_result_for_fallback_surfaces_auxiliary_scan_warnings():
    text = format_result_for_fallback(
        {
            "skill": "discover_network_hosts",
            "cidr": "192.168.1.0/24",
            "ports": "22",
            "scanner": "nmap",
            "host_count": 1,
            "status": "ok_with_warnings",
            "hosts": {"192.168.1.10": {"hostname": None, "ports": []}},
            "checks": {
                "icmp_scan": {},
                "port_scan": {},
                "compare": {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": []},
                "warnings": [
                    "Reverse DNS lookup failed for 192.168.1.10: dns backend unavailable",
                    "Known-hosts update failed: known_hosts.json is read-only",
                ],
            },
        }
    )
    assert "Warnings:" in text
    assert "Reverse DNS lookup failed for 192.168.1.10" in text
    assert "Known-hosts update failed: known_hosts.json is read-only" in text
