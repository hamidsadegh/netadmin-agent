from main import (
    build_interactive_prompt,
    complete_interactive_input,
    extract_explicit_ssh_command,
    extract_json,
    format_active_session_status,
    format_help_response,
    format_identity_response,
    format_playbook_result,
    format_result_for_fallback,
    format_scan_memory,
    get_interactive_completion_candidates,
    get_history_file,
    get_skill_status_message,
    is_casual_greeting,
    is_help_request,
    is_identity_request,
    is_scan_memory_request,
    is_session_info_request,
    maybe_run_cisco_playbook,
    normalize_skill_call,
    parse_direct_skill_request,
    run_with_status,
    save_interactive_history,
    setup_interactive_history,
)
from agent.cli import app as cli_app
from agent.skills.cisco.common import display_interface_name
from agent.cli import history as cli_history
from agent.cli import status as cli_status


def test_extract_json_from_fenced_block():
    payload = '```json\n{"skill": "check_device_connectivity", "args": {"host": "1.1.1.1"}}\n```'
    parsed = extract_json(payload)
    assert parsed["skill"] == "check_device_connectivity"
    assert parsed["args"]["host"] == "1.1.1.1"


def test_extract_json_returns_none_for_invalid_payload():
    assert extract_json("not json") is None


def test_normalize_skill_call_rejects_unknown_skill():
    assert normalize_skill_call({"skill": "do_something", "args": {}}) is None


def test_parse_direct_skill_request_detects_scan_prompt():
    parsed = parse_direct_skill_request("scan 192.168.178.0/24 ports 22,80,443")
    assert parsed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.178.0/24", "ports": "22,80,443"},
    }


def test_parse_direct_skill_request_detects_explicit_masscan_scan_prompt():
    parsed = parse_direct_skill_request("scan 192.168.178.0/24 with masscan ports 22,80,443")
    assert parsed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.178.0/24", "ports": "22,80,443", "scanner": "masscan"},
    }


def test_parse_direct_skill_request_detects_service_detection_scan_prompt():
    parsed = parse_direct_skill_request("scan 192.168.178.0/24 service detection ports 22,443")
    assert parsed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.178.0/24", "ports": "22,443", "service_detection": "safe"},
    }


def test_parse_direct_skill_request_detects_direct_host_check():
    parsed = parse_direct_skill_request("check 192.168.178.49")
    assert parsed == {
        "skill": "check_device_connectivity",
        "args": {"host": "192.168.178.49"},
    }


def test_parse_direct_skill_request_treats_connectivity_as_ping_check_not_ssh():
    parsed = parse_direct_skill_request("check ping device connectivity 192.168.178.49")
    assert parsed == {
        "skill": "check_device_connectivity",
        "args": {"host": "192.168.178.49"},
    }


def test_parse_direct_skill_request_ping_and_ssh_uses_connectivity_check():
    parsed = parse_direct_skill_request("check device connectivity 192.168.178.49 ping ssh")
    assert parsed == {
        "skill": "check_device_connectivity",
        "args": {"host": "192.168.178.49"},
    }


def test_parse_direct_skill_request_explicit_ssh_still_routes_to_ssh():
    parsed = parse_direct_skill_request("ssh to 192.168.178.49")
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "192.168.178.49"
    assert parsed["args"]["user"] is None


def test_parse_direct_skill_request_detects_direct_hostname_check():
    parsed = parse_direct_skill_request("check edge-fw01")
    assert parsed == {
        "skill": "check_device_connectivity",
        "args": {"host": "edge-fw01"},
    }


def test_parse_direct_skill_request_ignores_casual_greeting():
    assert parse_direct_skill_request("hi") is None
    assert is_casual_greeting("hi") is True


def test_parse_direct_skill_request_accepts_host_like_bare_token():
    parsed = parse_direct_skill_request("edge-fw01")
    assert parsed == {
        "skill": "check_device_connectivity",
        "args": {"host": "edge-fw01"},
    }


def test_parse_direct_skill_request_detects_ip_question_with_typo():
    parsed = parse_direct_skill_request("is 192.168.178.1 rachable?")
    assert parsed == {
        "skill": "check_device_connectivity",
        "args": {"host": "192.168.178.1"},
    }


def test_parse_direct_skill_request_detects_single_host_port_range():
    parsed = parse_direct_skill_request("check first 200 ports of 192.168.178.1")
    assert parsed == {
        "skill": "scan_host_tcp_ports",
        "args": {"host": "192.168.178.1", "ports": "1-200"},
    }


def test_parse_direct_skill_request_detects_single_hostname_port_scan():
    parsed = parse_direct_skill_request("scan switch-a1.lab ports 22,443")
    assert parsed == {
        "skill": "scan_host_tcp_ports",
        "args": {"host": "switch-a1.lab", "ports": "22,443"},
    }


def test_parse_direct_skill_request_detects_ssh_prompt():
    parsed = parse_direct_skill_request(
        "ssh to 192.168.178.49 user admin run uptime"
    )
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "192.168.178.49"
    assert parsed["args"]["user"] == "admin"
    assert parsed["args"]["port"] is None


def test_parse_direct_skill_request_detects_connect_word_for_ssh():
    parsed = parse_direct_skill_request(
        "connect to 192.168.178.49 with user user1"
    )
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "192.168.178.49"
    assert parsed["args"]["user"] == "user1"


def test_parse_direct_skill_request_detects_hostname_for_ssh():
    parsed = parse_direct_skill_request(
        "connect to core-sw01.lab with user user1"
    )
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "core-sw01.lab"
    assert parsed["args"]["user"] == "user1"



def test_parse_direct_skill_request_supports_user_at_ip_for_ssh():
    parsed = parse_direct_skill_request("ssh admin@192.168.178.49 run uptime")
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "192.168.178.49"
    assert parsed["args"]["user"] == "admin"
    assert parsed["args"]["command"] == "uptime"



def test_parse_direct_skill_request_supports_user_at_hostname_for_ssh():
    parsed = parse_direct_skill_request("ssh admin@core-sw01.lab")
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "core-sw01.lab"
    assert parsed["args"]["user"] == "admin"



def test_parse_direct_skill_request_allows_missing_ssh_user():
    parsed = parse_direct_skill_request("connect to 192.168.178.49")
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "192.168.178.49"
    assert parsed["args"]["user"] is None


def test_format_result_for_fallback_compacts_ssh_result():
    text = format_result_for_fallback(
        {
            "skill": "run_remote_ssh_diagnostic",
            "host": "192.168.1.10",
            "user": "admin",
            "status": "ok",
            "platform_key": "rhel",
            "result": {
                "command": "uptime",
                "success": True,
                "cleaned_stdout": "up 1 day",
                "cleaned_stderr": "",
                "summary": "Collected combined system health snapshot.",
                "error": None,
            },
        }
    )
    assert "SSH ok: admin@192.168.1.10" in text
    assert "Platform: rhel" in text
    assert "Command: uptime" in text
    assert "Summary:\nCollected combined system health snapshot." in text
    assert "Output:\nup 1 day" in text


def test_format_result_for_fallback_summarizes_network_scan():
    text = format_result_for_fallback(
        {
            "skill": "discover_network_hosts",
            "cidr": "194.55.34.0/24",
            "ports": "80",
            "scanner": "masscan",
            "service_detection": None,
            "host_count": 0,
            "status": "scan_failed",
            "hosts": {},
            "checks": {
                "icmp_scan": {"stderr": "[-] FAIL: permission denied\nneed to sudo"},
                "port_scan": {"stderr": "[-] FAIL: permission denied\nneed to sudo"},
                "compare": {
                    "skipped": True,
                    "new_hosts": [],
                    "disappeared_hosts": [],
                    "changed_hosts": [],
                },
            },
        }
    )
    assert "Network scan scan_failed: 194.55.34.0/24" in text
    assert "Scanner: masscan" in text
    assert "Ports: 80" in text
    assert "Hosts found: 0" in text
    assert "Inventory changes:" not in text
    assert "Warnings:" in text
    assert "permission denied" in text
    assert "Recommended next step:" in text
    assert "elevated privileges" in text


def test_format_scan_memory_lists_all_hosts_from_last_scan():
    text = format_scan_memory(
        {
            "skill": "discover_network_hosts",
            "cidr": "192.168.178.0/24",
            "ports": "22,80,443",
            "hosts": {
                "192.168.178.49": {
                    "hostname": "homeassistant.fritz.box",
                    "alive_icmp": True,
                    "ports": [{"port": 22, "service": "ssh"}],
                },
                "192.168.178.67": {
                    "hostname": "fox",
                    "alive_icmp": True,
                    "ports": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
                },
            },
        }
    )

    assert "Last Scan Hosts: 192.168.178.0/24" in text
    assert "- 192.168.178.49 (homeassistant.fritz.box): alive; 22/ssh" in text
    assert "- 192.168.178.67 (fox): alive; 22/ssh, 80/http" in text


def test_format_scan_memory_handles_missing_scan():
    assert "No scan results" in format_scan_memory(None)


def test_format_result_for_fallback_recommends_interface_fix_when_init_fails():
    text = format_result_for_fallback(
        {
            "skill": "discover_network_hosts",
            "cidr": "10.0.0.0/24",
            "ports": "22",
            "scanner": "nmap",
            "service_detection": None,
            "host_count": 0,
            "status": "ok",
            "hosts": {},
            "checks": {
                "icmp_scan": {"stderr": "[-] if:wlan0:init: failed\n"},
                "port_scan": {"stderr": ""},
                "compare": {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": []},
            },
        }
    )
    assert "Warnings:" in text
    assert "if:wlan0:init: failed" in text
    assert "Set the correct network interface/source IP before scanning." in text


def test_format_result_for_fallback_marks_partial_network_scan():
    text = format_result_for_fallback(
        {
            "skill": "discover_network_hosts",
            "cidr": "192.168.1.0/24",
            "ports": "22",
            "scanner": "nmap",
            "service_detection": None,
            "host_count": 1,
            "status": "partial_scan",
            "hosts": {"192.168.1.10": {"hostname": None, "ports": []}},
            "checks": {
                "icmp_scan": {"success": True, "stderr": ""},
                "port_scan": {"success": False, "error": "permission denied", "stderr": "need to sudo"},
                "compare": {"skipped": True, "new_hosts": [], "disappeared_hosts": [], "changed_hosts": []},
                "warnings": [
                    "Port scan failed: permission denied",
                    "Inventory compare/store skipped because the scan did not complete cleanly.",
                ],
            },
        }
    )
    assert "Network scan partial_scan: 192.168.1.0/24" in text
    assert "Hosts:" in text
    assert "permission denied" in text
    assert "Inventory changes:" not in text


def test_format_result_for_fallback_summarizes_connectivity_check():
    text = format_result_for_fallback(
        {
            "skill": "check_device_connectivity",
            "host": "192.168.1.10",
            "status": "reachable_and_ssh_open",
            "checks": {
                "ping": {"reachable": True},
                "ssh": {"open": True},
            },
        }
    )
    assert "Connectivity reachable_and_ssh_open: 192.168.1.10" in text
    assert "- ping reachable: yes" in text
    assert "- ssh port 22 open: yes" in text


def test_format_result_for_fallback_summarizes_tcp_port_scan():
    text = format_result_for_fallback(
        {
            "skill": "scan_host_tcp_ports",
            "host": "192.168.1.10",
            "ports": "1-200",
            "status": "open_ports_found",
            "checks": {
                "ping": {"reachable": True},
                "port_scan": {
                    "scanned_count": 200,
                    "requested_count": 200,
                    "open_count": 2,
                    "findings": [
                        {"port": 80, "proto": "tcp", "open": True},
                        {"port": 443, "proto": "tcp", "open": True},
                    ],
                },
            },
        }
    )
    assert "TCP port scan open_ports_found: 192.168.1.10" in text
    assert "- ports: 1-200" in text
    assert "- scanned: 200" in text
    assert "- requested: 200" in text
    assert "- open: 2" in text
    assert "- open ports: 80, 443" in text


def test_format_result_for_fallback_surfaces_tcp_port_scan_error():
    text = format_result_for_fallback(
        {
            "skill": "scan_host_tcp_ports",
            "host": "192.168.1.10",
            "ports": "22,443",
            "status": "scan_failed",
            "checks": {
                "ping": {"reachable": False, "error": "Ping command timed out"},
                "port_scan": {
                    "scanned_count": 1,
                    "requested_count": 2,
                    "open_count": 0,
                    "timed_out_count": 0,
                    "findings": [],
                    "error": "[Errno 113] No route to host",
                },
            },
        }
    )
    assert "TCP port scan scan_failed: 192.168.1.10" in text
    assert "- scan error: [Errno 113] No route to host" in text
    assert "- ping error: Ping command timed out" in text


def test_extract_explicit_ssh_command_prefers_quoted_command():
    user_match = None
    text = 'connect to 192.168.178.49 with user user1 and run the command "ls -la /home/user1" to check contents'
    assert extract_explicit_ssh_command(text, user_match) == "ls -la /home/user1"


def test_parse_direct_skill_request_extracts_quoted_ssh_command():
    parsed = parse_direct_skill_request(
        'connect to 192.168.178.49 with user user1 and run the command "ls -la /home/user1" to check the contents of the home directory.'
    )
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["command"] == "ls -la /home/user1"


def test_parse_direct_skill_request_extracts_ssh_port_and_password():
    parsed = parse_direct_skill_request(
        "connect to 127.0.0.1 port 2222 with user admin and pass admin with command show version"
    )
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "127.0.0.1"
    assert parsed["args"]["port"] == 2222
    assert parsed["args"]["user"] == "admin"
    assert parsed["args"]["password"] == "admin"
    assert parsed["args"]["command"] == "show version"


def test_parse_direct_skill_request_extracts_hostport_and_admin_user_phrase():
    parsed = parse_direct_skill_request(
        "connect to 127.0.0.1:2222 with admin user and run the command show version"
    )
    assert parsed["skill"] == "run_remote_ssh_diagnostic"
    assert parsed["args"]["host"] == "127.0.0.1"
    assert parsed["args"]["port"] == 2222
    assert parsed["args"]["user"] == "admin"
    assert parsed["args"]["command"] == "show version"


def test_format_playbook_result_contains_summary_and_matches():
    text = format_playbook_result(
        {
            "skill": "cisco_mac_lookup_playbook",
            "host": "10.0.0.10",
            "user": "admin",
            "platform_key": "cisco_ios",
            "mac": "0011.2233.4455",
            "summary": "Found 1 matching MAC table entry.",
            "matches": [{"mac": "0011.2233.4455", "port": "Gi1/0/1", "vlan": "10", "type": "DYNAMIC"}],
        }
    )
    assert "MAC Lookup: 0011.2233.4455" in text
    assert "Platform: cisco_ios" in text
    assert "- Entries: 1" in text
    assert "VLAN 10 0011.2233.4455 DYNAMIC on Gi1/0/1" in text
    assert "Matches:" not in text


def test_format_interface_down_playbook_is_human_friendly_without_json():
    text = format_playbook_result(
        {
            "skill": "cisco_interface_down_playbook",
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_ios_xe",
            "interface": "Gi1/0/16",
            "matches": {
                "interfaces": [{"port": "Gi1/0/16", "status": "notconnect", "vlan": "207"}],
                "ip_interfaces": [{"interface": "GigabitEthernet1/0/16", "status": "down", "protocol": "down"}],
                "neighbors": [],
                "mac_table": [],
            },
            "log_matches": [],
            "possible_reasons": ["cable/SFP/patch path disconnected"],
            "recommendations": ["Check cable/SFP/patch panel and endpoint power/NIC."],
        }
    )
    assert "Troubleshooting: Gi1/0/16" in text
    assert "Matches:" not in text
    assert '"interfaces"' not in text
    assert "Possible Reasons:" in text
    assert "Recommendations:" in text


def test_format_interface_check_playbook_is_human_friendly_without_json():
    text = format_playbook_result(
        {
            "skill": "cisco_interface_check_playbook",
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_ios_xe",
            "interface": "Te1/1/2",
            "matches": {
                "interfaces": [{"port": "Te1/1/2", "status": "connected", "vlan": "trunk"}],
                "ip_interfaces": [{"interface": "Te1/1/2", "status": "up", "protocol": "up"}],
                "neighbors": [{"device_id": "device.example.local", "remote_port": "TwentyFiveGigE2/0/1"}],
                "mac_table": [],
            },
        }
    )

    assert "Troubleshooting: Te1/1/2" in text
    assert "- Assessment: interface is not down" in text
    assert "- Switchport: Te1/1/2: connected VLAN trunk" in text
    assert "- device.example.local via Tw2/0/1" in text
    assert "Matches:" not in text
    assert '"neighbors"' not in text


def test_format_interface_mac_table_playbook_filters_output_without_raw_table():
    text = format_playbook_result(
        {
            "skill": "cisco_interface_mac_table_playbook",
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_ios_xe",
            "interface": "GigabitEthernet1/0/6",
            "matches": [
                {"mac": "0011.2233.4455", "vlan": "10", "type": "DYNAMIC", "port": "GigabitEthernet1/0/6"}
            ],
        }
    )

    assert "MAC Table: Gi1/0/6" in text
    assert "- Entries: 1" in text
    assert "- VLAN 10 0011.2233.4455 DYNAMIC on Gi1/0/6" in text
    assert "Output:" not in text
    assert "Mac Address Table" not in text


def test_format_trunk_uplink_playbook_is_human_friendly():
    text = format_playbook_result(
        {
            "skill": "cisco_trunk_uplink_playbook",
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_ios_xe",
            "interface": "GigabitEthernet1/0/1",
            "assessment": "healthy",
            "matches": {
                "interfaces": [{"port": "Gi1/0/1", "status": "connected", "vlan": "trunk"}],
                "neighbors": [{"device_id": "core-sw", "remote_port": "Ethernet1/1"}],
                "spanning_tree": ["Gi1/0/1    Desg FWD 4         128.1    P2p"],
                "port_channels": [
                    {
                        "port_channel": "Po1",
                        "flags": "SU",
                        "matched_member": {"interface": "GigabitEthernet1/0/1", "flags": "P"},
                    }
                ],
                "interface_trunks": [
                    {
                        "port": "Gi1/0/1",
                        "native_vlan": "1",
                        "allowed_vlans": "1,10",
                        "active_vlans": "1,10",
                        "forwarding_vlans": "1,10",
                    }
                ],
            },
            "recommendations": ["Evidence is healthy; compare VLAN allowance/STP root placement only if symptoms persist."],
        }
    )

    assert "Trunk/Uplink: Gi1/0/1" in text
    assert "- Assessment: healthy" in text
    assert "- Switchport: Gi1/0/1: connected VLAN trunk" in text
    assert "- core-sw via Eth1/1" in text
    assert "- Po1 flags SU member Gi1/0/1(P)" in text
    assert "- Allowed VLANs: 1,10; active: 1,10; forwarding: 1,10" in text
    assert "Trunk VLANs:" in text
    assert "Matches:" not in text


def test_format_trunk_uplink_playbook_includes_vpc_analysis():
    text = format_playbook_result(
        {
            "skill": "cisco_trunk_uplink_playbook",
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_nxos",
            "interface": "Ethernet1/1",
            "assessment": "attention",
            "matches": {
                "interfaces": [{"port": "Eth1/1", "status": "connected", "vlan": "trunk"}],
                "neighbors": [],
                "spanning_tree": [],
                "port_channels": [],
                "interface_trunks": [],
            },
            "vpc_analysis": {
                "matches": [{"id": "10", "port_channel": "Po10", "status": "down", "consistency": "failed"}],
                "observations": ["vPC 10 Po10 status down consistency failed"],
                "risks": ["vPC 10 is not up"],
            },
            "risks": ["vPC 10 is not up"],
        }
    )

    assert "vPC:" in text
    assert "- vPC 10 Po10 status down consistency failed" in text
    assert "- vPC matches: 1" in text


def test_display_interface_name_shortens_common_cisco_names():
    assert display_interface_name("GigabitEthernet1/0/1") == "Gi1/0/1"
    assert display_interface_name("TenGigabitEthernet1/1/1") == "Te1/1/1"
    assert display_interface_name("TwentyFiveGigE1/1/1") == "Tw1/1/1"
    assert display_interface_name("FortyGigabitEthernet1/1/1") == "Fo1/1/1"
    assert display_interface_name("HundredGigE1/1/1") == "Hu1/1/1"


def test_format_interface_down_playbook_reports_not_down_when_link_is_healthy():
    text = format_playbook_result(
        {
            "skill": "cisco_interface_down_playbook",
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_ios_xe",
            "interface": "Gi1/0/1",
            "interface_is_down": False,
            "matches": {
                "interfaces": [{"port": "Gi1/0/1", "status": "connected", "vlan": "68"}],
                "ip_interfaces": [{"interface": "GigabitEthernet1/0/1", "status": "up", "protocol": "up"}],
                "neighbors": [],
                "mac_table": [{"port": "Gi1/0/1", "mac": "0011.2233.4455"}],
            },
            "log_matches": [],
            "possible_reasons": ["current evidence does not show the interface is down"],
            "recommendations": ["Treat this as not currently down."],
        }
    )

    assert "- Assessment: interface is not down" in text
    assert "current evidence does not show the interface is down" in text


def test_format_interface_down_playbook_reports_missing_interface():
    text = format_playbook_result(
        {
            "skill": "cisco_interface_down_playbook",
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_ios_xe",
            "interface": "Te1/0/1",
            "interface_found": False,
            "interface_is_down": False,
            "matches": {
                "interfaces": [],
                "ip_interfaces": [],
                "neighbors": [],
                "mac_table": [],
            },
            "log_matches": [],
            "possible_reasons": ["interface was not found in the current device output"],
            "recommendations": ["Verify the interface name and platform syntax, then list interfaces with show interface status."],
        }
    )

    assert "- Assessment: interface is not found" in text
    assert "interface was not found in the current device output" in text


def test_is_session_info_request_matches_helpful_phrases():
    assert is_session_info_request("session info") is True
    assert is_identity_request("what can you do here?") is True
    assert is_identity_request("who are you?") is True
    assert is_identity_request("how can you help me?") is True
    assert is_session_info_request("What I can on this paltform?") is True
    assert is_session_info_request("examples") is True
    assert is_session_info_request("check 192.168.178.49") is False


def test_is_help_request_matches_short_help_commands():
    assert is_help_request("help") is True
    assert is_help_request("?") is True
    assert is_help_request("/") is True
    assert is_help_request("show help") is False


def test_is_scan_memory_request_matches_scanned_host_phrases():
    assert is_scan_memory_request("list all hosts") is True
    assert is_scan_memory_request("list all scaned hosts") is True
    assert is_scan_memory_request("show last scan") is True
    assert is_scan_memory_request("check 192.168.178.49") is False


def test_format_identity_response_lists_capabilities_and_examples():
    text = format_identity_response()

    assert "NetAdmin Agent Identity" in text
    assert "read-only diagnostics" in text
    assert "Capabilities:" in text
    assert "- Check one host for ICMP reachability" in text
    assert "- Connect over SSH and run safe read-only diagnostics." in text
    assert "- Start a local Cisco SSH simulator backend" in text
    assert "Examples:" in text
    assert "`check 192.168.178.49`" in text
    assert "`python main.py --simulator nxos --ssh-request \"show vpc\"`" in text


def test_format_help_response_lists_modes_and_session_examples():
    text = format_help_response(
        {
            "host": "127.0.0.1",
            "port": 2222,
            "user": "admin",
            "platform_key": "cisco_ios_xe",
        },
        mode="ssh",
    )

    assert "NetAdmin Agent Help" in text
    assert "ssh mode: send read-only commands directly" in text
    assert "Target: admin@127.0.0.1:2222" in text
    assert "Current mode: ssh" in text
    assert "show interfaces status" in text


def test_run_agent_answers_identity_question_without_diagnostics(monkeypatch):
    outputs = []
    cli_app.PENDING_FOLLOW_UP = None
    cli_app.ACTIVE_SSH_SESSION = None

    monkeypatch.setattr(cli_app, "print", lambda *args, **kwargs: outputs.append(" ".join(str(a) for a in args)))
    monkeypatch.setattr(cli_app, "print_paged", lambda text, **_kwargs: outputs.append(text))
    monkeypatch.setattr(
        cli_app,
        "execute_skill",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("identity should not run a skill")),
    )

    cli_app.run_agent("who are you?")

    assert outputs
    assert "NetAdmin Agent Identity" in outputs[-1]
    assert "Capabilities:" in outputs[-1]


def test_run_agent_answers_help_without_diagnostics(monkeypatch):
    outputs = []
    cli_app.PENDING_FOLLOW_UP = None
    cli_app.ACTIVE_SSH_SESSION = None
    cli_app.ACTIVE_INTERACTIVE_MODE = "agent"

    monkeypatch.setattr(cli_app, "print_paged", lambda text, **_kwargs: outputs.append(text))
    monkeypatch.setattr(
        cli_app,
        "execute_skill",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("help should not run a skill")),
    )

    cli_app.run_agent("?")

    assert outputs
    assert "NetAdmin Agent Help" in outputs[-1]
    assert "Modes:" in outputs[-1]


def test_format_active_session_status_includes_platform_intents_and_examples():
    text = format_active_session_status(
        {
            "host": "10.0.0.10",
            "user": "admin",
            "platform_key": "cisco_ios",
            "session_mode": "cisco_cli",
            "prepared": True,
            "fingerprint": "Cisco IOS Software, Catalyst",
        }
    )
    assert "Active SSH session: admin@10.0.0.10" in text
    assert "Platform: cisco_ios" in text
    assert "Supported intents:" in text
    assert "interfaces" in text
    assert "Examples:" in text
    assert "- troubleshoot interface Gi1/0/1" in text
    assert "- mac table for int Gi1/0/1" in text
    assert "Fingerprint:" in text


def test_format_active_session_status_filters_invalid_probe_noise():
    text = format_active_session_status(
        {
            "host": "127.0.0.1",
            "user": "admin",
            "platform_key": "cisco_ios_xe",
            "fingerprint": (
                "% Invalid input detected for command: cat /etc/os-release\n"
                "% Invalid input detected for command: uname -a\n"
                "Cisco IOS XE Software, Version 17.06.06"
            ),
        }
    )

    assert "Invalid input detected" not in text
    assert "cat /etc/os-release" not in text
    assert "uname -a" not in text
    assert "Cisco IOS XE Software, Version 17.06.06" in text


def test_build_interactive_prompt_without_session():
    assert build_interactive_prompt(None) == "\nnetadmin-agent> "


def test_build_interactive_prompt_with_session():
    prompt = build_interactive_prompt(
        {
            "host": "127.0.0.1",
            "port": 2222,
            "platform_key": "cisco_ios",
        }
    )
    assert prompt == "\nnetadmin-agent[cisco_ios:127.0.0.1:2222]> "


def test_ssh_mode_completion_candidates_include_platform_commands():
    candidates = get_interactive_completion_candidates(
        {"platform_key": "cisco_ios_xe"},
        "ssh",
    )

    assert "show interfaces status" in candidates
    assert "show interface status" in candidates
    assert "show mac table" in candidates
    assert "agent mode" in candidates


def test_agent_mode_completion_candidates_include_agent_actions():
    candidates = get_interactive_completion_candidates(None, "agent")

    assert "connect to " in candidates
    assert "scan " in candidates
    assert "ssh mode" in candidates


def test_complete_interactive_input_returns_stateful_matches(monkeypatch):
    monkeypatch.setattr(cli_app, "ACTIVE_INTERACTIVE_MODE", "ssh")
    monkeypatch.setattr(cli_app, "ACTIVE_SSH_SESSION", {"platform_key": "cisco_ios_xe"})

    first = complete_interactive_input("show int", 0)
    second = complete_interactive_input("show int", 1)

    assert first.startswith("show int")
    assert second.startswith("show int")
    assert first != second


def test_run_agent_routes_unparsed_input_to_active_ssh_session(monkeypatch):
    outputs = []
    calls = []
    cli_app.PENDING_FOLLOW_UP = None
    cli_app.ACTIVE_SSH_SESSION = {
        "client": object(),
        "host": "127.0.0.1",
        "port": 2222,
        "user": "admin",
        "platform_key": "cisco_ios",
    }

    def fake_run_with_status(_message, func, *args, **kwargs):
        return func(*args, **kwargs)

    def fake_run_on_session(client, **kwargs):
        calls.append({"client": client, **kwargs})
        return {
            "skill": "run_remote_ssh_diagnostic",
            "host": kwargs["host"],
            "port": kwargs["port"],
            "user": kwargs["user"],
            "status": "ok",
            "platform_key": kwargs["platform_key"],
            "result": {
                "command": kwargs["request"],
                "success": True,
                "cleaned_stdout": "running config",
                "cleaned_stderr": "",
            },
        }

    monkeypatch.setattr(cli_app, "print", lambda *args, **kwargs: outputs.append(" ".join(str(a) for a in args)))
    monkeypatch.setattr(cli_app, "run_with_status", fake_run_with_status)
    monkeypatch.setattr(cli_app, "run_remote_ssh_diagnostic_on_session", fake_run_on_session)

    cli_app.run_agent("show run")

    assert calls
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 2222
    assert calls[0]["user"] == "admin"
    assert calls[0]["request"] == "show run"
    assert outputs[-1] != "Which host should I connect to over SSH? Give me an IP or hostname."


def test_run_agent_remembers_last_scan_and_lists_hosts(monkeypatch):
    outputs = []
    cli_app.PENDING_FOLLOW_UP = None
    cli_app.ACTIVE_SSH_SESSION = None
    cli_app.LAST_SCAN_RESULT = None

    scan_result = {
        "skill": "discover_network_hosts",
        "cidr": "192.168.178.0/24",
        "ports": "22,80,443",
        "hosts": {
            "192.168.178.49": {
                "hostname": "homeassistant.fritz.box",
                "alive_icmp": True,
                "ports": [{"port": 22, "service": "ssh"}],
            }
        },
        "host_count": 1,
        "status": "ok",
        "checks": {"compare": {"new_hosts": [], "disappeared_hosts": [], "changed_hosts": []}},
    }

    def fake_run_with_status(_message, func, *args, **kwargs):
        return func(*args, **kwargs)

    def fake_execute_skill(skill_name, args):
        assert skill_name == "discover_network_hosts"
        return scan_result

    monkeypatch.setattr(cli_app, "print", lambda *args, **kwargs: outputs.append(" ".join(str(a) for a in args)))
    monkeypatch.setattr(cli_app, "run_with_status", fake_run_with_status)
    monkeypatch.setattr(cli_app, "execute_skill", fake_execute_skill)
    monkeypatch.setattr(cli_app, "explain_skill_result", lambda *_args, **_kwargs: "scan summary")

    cli_app.run_agent("scan 192.168.178.0/24")
    cli_app.run_agent("list all scaned hosts")

    assert cli_app.LAST_SCAN_RESULT == scan_result
    assert "scan summary" in outputs[0]
    assert "Last Scan Hosts: 192.168.178.0/24" in outputs[-1]
    assert "192.168.178.49 (homeassistant.fritz.box)" in outputs[-1]


def test_run_agent_list_hosts_without_scan_uses_memory_message(monkeypatch):
    outputs = []
    cli_app.PENDING_FOLLOW_UP = None
    cli_app.ACTIVE_SSH_SESSION = None
    cli_app.LAST_SCAN_RESULT = None

    monkeypatch.setattr(cli_app, "print", lambda *args, **kwargs: outputs.append(" ".join(str(a) for a in args)))

    cli_app.run_agent("list all hosts")

    assert "No scan results in this session yet" in outputs[-1]


def test_print_paged_prompts_for_long_output(monkeypatch):
    outputs = []
    writes = []
    monkeypatch.setattr(cli_app, "print", lambda *args, **kwargs: outputs.append(" ".join(str(a) for a in args)))
    monkeypatch.setattr(cli_app.shutil, "get_terminal_size", lambda fallback: type("Size", (), {"lines": 8})())
    monkeypatch.setattr(cli_app, "_read_pager_key", lambda: " ")
    monkeypatch.setattr(cli_app.sys.stdout, "write", lambda text: writes.append(text))
    monkeypatch.setattr(cli_app.sys.stdout, "flush", lambda: None)

    cli_app.print_paged("\n".join(f"line {idx}" for idx in range(12)))

    assert len(outputs) == 3
    assert any("--More-- Enter/Space next page, q quit" in text for text in writes)


def test_run_agent_does_not_summarize_direct_ssh_result(monkeypatch):
    outputs = []
    cli_app.PENDING_FOLLOW_UP = None
    cli_app.ACTIVE_SSH_SESSION = None

    def fake_run_with_status(_message, func, *args, **kwargs):
        return func(*args, **kwargs)

    def fake_execute_skill(skill_name, args):
        assert skill_name == "run_remote_ssh_diagnostic"
        return {
            "skill": "run_remote_ssh_diagnostic",
            "host": args["host"],
            "port": args["port"],
            "user": args["user"],
            "status": "ok",
            "result": {
                "command": "hostname",
                "cleaned_stdout": "iosxe-sim-1",
                "cleaned_stderr": "",
            },
        }

    monkeypatch.setattr(cli_app, "print", lambda *args, **kwargs: outputs.append(" ".join(str(a) for a in args)))
    monkeypatch.setattr(cli_app, "run_with_status", fake_run_with_status)
    monkeypatch.setattr(cli_app, "execute_skill", fake_execute_skill)
    monkeypatch.setattr(cli_app, "connect_ssh_session", lambda *args, **kwargs: {"success": True, "client": object()})
    monkeypatch.setattr(
        cli_app,
        "explain_skill_result",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("summarizer should not run")),
    )

    cli_app.run_agent("connect to 127.0.0.1:2222 with user admin and pass admin")

    assert outputs
    assert "SSH ok: admin@127.0.0.1:2222" in outputs[-1]
    assert "Command: hostname" in outputs[-1]


def test_get_skill_status_message_returns_clear_phase_labels():
    assert get_skill_status_message("check_device_connectivity") == "Checking host reachability..."
    assert get_skill_status_message("discover_network_hosts") == "Collecting network inventory..."
    assert get_skill_status_message("run_remote_ssh_diagnostic") == "Collecting remote diagnostics..."
    assert get_skill_status_message("unknown") == "Working..."


def test_get_history_file_points_into_repo():
    assert get_history_file().name == ".netadmin_history"


def test_setup_and_save_interactive_history(monkeypatch, tmp_path):
    calls = []

    class FakeReadline:
        def read_history_file(self, path):
            calls.append(("read", path))

        def set_history_length(self, length):
            calls.append(("length", length))

        def set_completer(self, completer):
            calls.append(("completer", completer))

        def parse_and_bind(self, binding):
            calls.append(("bind", binding))

        def write_history_file(self, path):
            calls.append(("write", path))

    history_file = tmp_path / ".netadmin_history"
    history_file.write_text("connect to 127.0.0.1\n")
    monkeypatch.setattr(cli_history, "readline", FakeReadline())
    monkeypatch.setattr(cli_history, "HISTORY_FILE", history_file)

    assert setup_interactive_history(completer=lambda *_args: None) is True
    save_interactive_history()

    assert ("read", str(history_file)) in calls
    assert ("length", 500) in calls
    assert any(item[0] == "completer" for item in calls)
    assert ("bind", "tab: complete") in calls
    assert ("write", str(history_file)) in calls


def test_exit_closes_active_ssh_session_without_quitting(monkeypatch):
    class FakeClient:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    client = FakeClient()
    printed = []
    monkeypatch.setattr(cli_app, "ACTIVE_SSH_SESSION", {"client": client})
    monkeypatch.setattr(cli_app, "ACTIVE_INTERACTIVE_MODE", "ssh")
    monkeypatch.setattr(cli_app, "print_paged", lambda message, force=False: printed.append(message))

    action = cli_app.handle_interactive_control_command("exit")

    assert action == "handled"
    assert client.closed is True
    assert cli_app.ACTIVE_SSH_SESSION is None
    assert cli_app.ACTIVE_INTERACTIVE_MODE == "agent"
    assert printed == ["SSH session closed.\n------------------------------------------------------------------------"]


def test_exit_quits_agent_when_no_active_ssh_session(monkeypatch):
    monkeypatch.setattr(cli_app, "ACTIVE_SSH_SESSION", None)

    assert cli_app.handle_interactive_control_command("exit") == "quit"


def test_ssh_mode_switch_requires_active_session(monkeypatch):
    printed = []
    monkeypatch.setattr(cli_app, "ACTIVE_SSH_SESSION", None)
    monkeypatch.setattr(cli_app, "ACTIVE_INTERACTIVE_MODE", "agent")
    monkeypatch.setattr(cli_app, "print_paged", lambda message, force=False: printed.append(message))

    action = cli_app.handle_interactive_control_command("ssh mode")

    assert action == "handled"
    assert cli_app.ACTIVE_INTERACTIVE_MODE == "agent"
    assert "No active SSH session" in printed[-1]


def test_ssh_mode_switch_and_agent_mode_switch(monkeypatch):
    printed = []
    monkeypatch.setattr(cli_app, "ACTIVE_SSH_SESSION", {"client": object()})
    monkeypatch.setattr(cli_app, "ACTIVE_INTERACTIVE_MODE", "agent")
    monkeypatch.setattr(cli_app, "print_paged", lambda message, force=False: printed.append(message))

    assert cli_app.handle_interactive_control_command("ssh mode") == "handled"
    assert cli_app.ACTIVE_INTERACTIVE_MODE == "ssh"
    assert cli_app.handle_interactive_control_command("agent mode") == "handled"
    assert cli_app.ACTIVE_INTERACTIVE_MODE == "agent"
    assert "SSH mode enabled" in printed[0]
    assert "Agent mode enabled" in printed[1]


def test_run_agent_ssh_mode_prints_raw_stdout_without_separator(monkeypatch):
    writes = []
    calls = []
    monkeypatch.setattr(
        cli_app,
        "ACTIVE_SSH_SESSION",
        {"client": object(), "host": "127.0.0.1", "port": 2222, "user": "admin", "platform_key": "cisco_ios_xe"},
    )
    monkeypatch.setattr(cli_app, "ACTIVE_INTERACTIVE_MODE", "ssh")
    monkeypatch.setattr(cli_app.sys.stdout, "write", lambda text: writes.append(text))
    monkeypatch.setattr(cli_app.sys.stdout, "flush", lambda: None)

    def fake_raw(client, **kwargs):
        calls.append({"client": client, **kwargs})
        return {"stdout": "Cisco IOS XE Software\n", "stderr": ""}

    monkeypatch.setattr(cli_app, "run_raw_command_on_ssh_session", fake_raw)

    cli_app.run_agent("show version")

    assert calls[0]["command"] == "show version"
    assert writes == ["Cisco IOS XE Software\n"]


def test_run_with_status_uses_console_status(monkeypatch):
    calls = []

    class FakeStatus:
        def __enter__(self):
            calls.append("enter")

        def __exit__(self, exc_type, exc, tb):
            calls.append("exit")

    class FakeConsole:
        def status(self, message, spinner=None):
            calls.append((message, spinner))
            return FakeStatus()

        def print(self, message):
            calls.append(("print", message))

    monkeypatch.setattr(cli_status, "CONSOLE", FakeConsole())
    monkeypatch.setattr(cli_status.time, "monotonic", lambda: 10.0 if not calls else 11.2)

    result = run_with_status("Working...", lambda value: value + 1, 4)

    assert result == 5
    assert calls[0] == ("[bold dark_orange]Working...[/]", "dots")
    assert "enter" in calls
    assert "exit" in calls
    assert ("print", "[bold green]✓ Working... done (1.2s)[/]") in calls


def test_run_with_status_prints_failure_and_reraises(monkeypatch):
    calls = []

    class FakeStatus:
        def __enter__(self):
            calls.append("enter")

        def __exit__(self, exc_type, exc, tb):
            calls.append("exit")

    class FakeConsole:
        def status(self, message, spinner=None):
            calls.append((message, spinner))
            return FakeStatus()

        def print(self, message):
            calls.append(("print", message))

    ticks = iter([20.0, 20.8])
    monkeypatch.setattr(cli_status, "CONSOLE", FakeConsole())
    monkeypatch.setattr(cli_status.time, "monotonic", lambda: next(ticks))

    def boom():
        raise RuntimeError("bad")

    try:
        run_with_status("Scanning network...", boom)
    except RuntimeError as exc:
        assert str(exc) == "bad"
    else:
        raise AssertionError("Expected RuntimeError")

    assert ("print", "[bold red]✗ Scanning network... failed (0.8s)[/]") in calls


def test_maybe_run_cisco_playbook_matches_interface_down(monkeypatch):
    cli_app.ACTIVE_SSH_SESSION = {
        "client": object(),
        "host": "10.0.0.10",
        "user": "admin",
        "platform_key": "cisco_ios",
    }

    monkeypatch.setattr(
        cli_app,
        "run_cisco_interface_down_playbook",
        lambda client, host, user, interface_name, platform_key=None: {
            "skill": "cisco_interface_down_playbook",
            "interface": interface_name,
            "host": host,
            "user": user,
            "platform_key": platform_key,
        },
    )

    result = maybe_run_cisco_playbook("why is Gi1/0/24 down?")
    assert result["skill"] == "cisco_interface_down_playbook"
    assert result["interface"] == "Gi1/0/24"


def test_maybe_run_cisco_playbook_matches_interface_check(monkeypatch):
    cli_app.ACTIVE_SSH_SESSION = {
        "client": object(),
        "host": "10.0.0.10",
        "user": "admin",
        "platform_key": "cisco_ios",
    }

    monkeypatch.setattr(
        cli_app,
        "run_cisco_interface_check_playbook",
        lambda client, host, user, interface_name, platform_key=None: {
            "skill": "cisco_interface_check_playbook",
            "interface": interface_name,
        },
    )

    result = maybe_run_cisco_playbook("check interface Te1/1 status")
    assert result["skill"] == "cisco_interface_check_playbook"
    assert result["interface"] == "Te1/1"


def test_maybe_run_cisco_playbook_matches_interface_mac_table(monkeypatch):
    cli_app.ACTIVE_SSH_SESSION = {
        "client": object(),
        "host": "10.0.0.10",
        "user": "admin",
        "platform_key": "cisco_ios",
    }

    monkeypatch.setattr(
        cli_app,
        "run_cisco_interface_mac_table_playbook",
        lambda client, host, user, interface_name, platform_key=None: {
            "skill": "cisco_interface_mac_table_playbook",
            "interface": interface_name,
        },
    )

    result = maybe_run_cisco_playbook("mac table for int Gi1/0/6")
    assert result["skill"] == "cisco_interface_mac_table_playbook"
    assert result["interface"] == "Gi1/0/6"


def test_maybe_run_cisco_playbook_matches_trunk_uplink(monkeypatch):
    cli_app.ACTIVE_SSH_SESSION = {
        "client": object(),
        "host": "10.0.0.10",
        "user": "admin",
        "platform_key": "cisco_ios_xe",
    }

    monkeypatch.setattr(
        cli_app,
        "run_cisco_trunk_uplink_playbook",
        lambda client, host, user, interface_name, platform_key=None: {
            "skill": "cisco_trunk_uplink_playbook",
            "interface": interface_name,
            "platform_key": platform_key,
        },
    )

    result = maybe_run_cisco_playbook("check trunk uplink Gi1/0/1")
    assert result["skill"] == "cisco_trunk_uplink_playbook"
    assert result["interface"] == "Gi1/0/1"


def test_maybe_run_cisco_playbook_matches_vpc_uplink(monkeypatch):
    cli_app.ACTIVE_SSH_SESSION = {
        "client": object(),
        "host": "10.0.0.10",
        "user": "admin",
        "platform_key": "cisco_nxos",
    }

    monkeypatch.setattr(
        cli_app,
        "run_cisco_trunk_uplink_playbook",
        lambda client, host, user, interface_name, platform_key=None: {
            "skill": "cisco_trunk_uplink_playbook",
            "interface": interface_name,
            "platform_key": platform_key,
        },
    )

    result = maybe_run_cisco_playbook("check vPC uplink Eth1/1")
    assert result["skill"] == "cisco_trunk_uplink_playbook"
    assert result["platform_key"] == "cisco_nxos"
