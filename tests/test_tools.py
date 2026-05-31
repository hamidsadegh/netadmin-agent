import errno
import json
from pathlib import Path

import pytest

from agent import tools
from agent.tools.ssh import _append_fingerprint_output
from agent.tools import scanning
from agent.skills import scan_host_tcp_ports


def test_validate_scan_target_allows_private_subnets():
    assert tools.validate_scan_target("192.168.178.0/24") == "192.168.178.0/24"


def test_append_fingerprint_output_ignores_cisco_invalid_command_stderr():
    combined = []

    _append_fingerprint_output(
        combined,
        {
            "stdout": "",
            "stderr": "% Invalid input detected for command: cat /etc/os-release",
        },
    )
    _append_fingerprint_output(
        combined,
        {
            "stdout": "Cisco IOS XE Software, Version 17.06.06",
            "stderr": "",
        },
    )

    assert combined == ["Cisco IOS XE Software, Version 17.06.06"]


def test_validate_scan_target_rejects_public_subnets():
    with pytest.raises(ValueError):
        tools.validate_scan_target("8.8.8.0/24")


def test_validate_ports_normalizes_and_deduplicates():
    assert tools.validate_ports("22, 80,443,22,1000-1002") == "22,80,443,1000-1002"


def test_validate_ports_rejects_invalid_values():
    with pytest.raises(ValueError):
        tools.validate_ports("0,70000")


def test_load_known_hosts_returns_empty_for_non_mapping_json(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)
    db_path.write_text("[]")

    assert tools.load_known_hosts() == {}


def test_save_known_hosts_creates_parent_directory(monkeypatch, tmp_path):
    db_path = tmp_path / "nested" / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)

    tools.save_known_hosts({"192.168.1.10": {"hostname": "switch.local"}})

    assert db_path.exists()
    assert json.loads(Path(db_path).read_text()) == {"192.168.1.10": {"hostname": "switch.local"}}


def test_store_known_hosts_adds_and_updates(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)

    first = tools.store_known_hosts(
        {
            "192.168.1.10": {
                "hostname": "switch.local",
                "alive_icmp": True,
                "ports": [{"port": 22, "proto": "tcp"}],
            }
        }
    )
    second = tools.store_known_hosts(
        {
            "192.168.1.10": {
                "hostname": "switch.local",
                "alive_icmp": False,
                "ports": [{"port": 443, "proto": "tcp"}],
            }
        }
    )

    assert first["added"] == 1
    assert second["updated"] == 1

    saved = json.loads(Path(db_path).read_text())
    assert saved["192.168.1.10"]["ports"] == [{"port": 443, "proto": "tcp"}]
    assert saved["192.168.1.10"]["source"] == "netadmin-agent"


def test_store_known_hosts_normalizes_and_deduplicates_ports(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)

    tools.store_known_hosts(
        {
            "192.168.1.10": {
                "hostname": "switch.local",
                "alive_icmp": True,
                "ports": [
                    {"port": 443, "proto": "TCP"},
                    {"port": 22, "proto": "tcp"},
                    {"port": 443, "proto": "tcp"},
                ],
            }
        }
    )

    saved = json.loads(Path(db_path).read_text())
    assert saved["192.168.1.10"]["ports"] == [
        {"port": 22, "proto": "tcp"},
        {"port": 443, "proto": "tcp"},
    ]


def test_store_known_hosts_preserves_existing_data_when_requested(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)
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

    result = tools.store_known_hosts(
        {
            "192.168.1.10": {
                "hostname": None,
                "alive_icmp": True,
                "ports": [],
            }
        },
        preserve_hostname_when_missing=True,
        preserve_ports_when_missing=True,
    )

    assert result["updated"] == 0
    assert result["unchanged"] == 1

    saved = json.loads(Path(db_path).read_text())
    assert saved["192.168.1.10"]["hostname"] == "switch.local"
    assert saved["192.168.1.10"]["ports"] == [{"port": 22, "proto": "tcp"}]


def test_compare_known_hosts_reports_new_missing_and_changed(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)
    db_path.write_text(
        json.dumps(
            {
                "192.168.1.10": {
                    "hostname": "switch.local",
                    "alive_icmp": True,
                    "ports": [{"port": 22, "proto": "tcp"}],
                },
                "192.168.1.20": {
                    "hostname": "printer.local",
                    "alive_icmp": True,
                    "ports": [],
                },
            }
        )
    )

    result = tools.compare_known_hosts(
        {
            "192.168.1.10": {
                "hostname": "switch.local",
                "alive_icmp": False,
                "ports": [{"port": 443, "proto": "tcp"}],
            },
            "192.168.1.30": {
                "hostname": "nas.local",
                "alive_icmp": True,
                "ports": [{"port": 22, "proto": "tcp"}],
            },
        }
    )

    assert result["new_hosts"] == ["192.168.1.30"]
    assert result["disappeared_hosts"] == ["192.168.1.20"]
    assert result["changed_hosts"][0]["ip"] == "192.168.1.10"
    assert "alive_icmp" in result["changed_hosts"][0]["changes"]
    assert "ports" in result["changed_hosts"][0]["changes"]


def test_compare_known_hosts_ignores_port_order_only_changes(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)
    db_path.write_text(
        json.dumps(
            {
                "192.168.1.10": {
                    "hostname": "switch.local",
                    "alive_icmp": True,
                    "ports": [
                        {"port": 22, "proto": "tcp"},
                        {"port": 443, "proto": "tcp"},
                    ],
                }
            }
        )
    )

    result = tools.compare_known_hosts(
        {
            "192.168.1.10": {
                "hostname": "switch.local",
                "alive_icmp": True,
                "ports": [
                    {"port": 443, "proto": "TCP"},
                    {"port": 22, "proto": "tcp"},
                    {"port": 443, "proto": "tcp"},
                ],
            }
        }
    )

    assert result["changed_hosts"] == []


def test_compare_known_hosts_can_preserve_missing_hostname_and_ports(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)
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

    result = tools.compare_known_hosts(
        {
            "192.168.1.10": {
                "hostname": None,
                "alive_icmp": True,
                "ports": [],
            }
        },
        preserve_hostname_when_missing=True,
        preserve_ports_when_missing=True,
    )

    assert result["changed_hosts"] == []


def test_compare_known_hosts_scope_ignores_other_subnets_when_marking_disappeared(monkeypatch, tmp_path):
    db_path = tmp_path / "known_hosts.json"
    monkeypatch.setattr(tools.inventory, "KNOWN_HOSTS_FILE", db_path)
    db_path.write_text(
        json.dumps(
            {
                "192.168.1.10": {
                    "hostname": "switch.local",
                    "alive_icmp": True,
                    "ports": [{"port": 22, "proto": "tcp"}],
                },
                "192.168.2.20": {
                    "hostname": "printer.local",
                    "alive_icmp": True,
                    "ports": [],
                },
            }
        )
    )

    result = tools.compare_known_hosts(
        {
            "192.168.1.10": {
                "hostname": "switch.local",
                "alive_icmp": True,
                "ports": [{"port": 22, "proto": "tcp"}],
            }
        },
        scope_cidr="192.168.1.0/24",
    )

    assert result["scope_cidr"] == "192.168.1.0/24"
    assert result["disappeared_hosts"] == []
    assert result["previous_count"] == 1


def test_infer_safe_remote_command_maps_common_requests():
    assert tools.infer_safe_remote_command("show disk usage") == "df -h"
    assert tools.infer_safe_remote_command("show the cpu usage") == "top -bn1"
    assert tools.infer_safe_remote_command("show ip addresses") == "ip addr show"
    assert tools.infer_safe_remote_command("show the services") == "service --status-all"
    assert tools.infer_safe_remote_command("show the services", platform_key="rhel") == (
        "systemctl --type=service --state=running --no-pager"
    )
    assert tools.infer_safe_remote_command("show interface brief", platform_key="cisco_ios") == (
        "show ip interface brief"
    )
    assert tools.infer_safe_remote_command("show interface trunk", platform_key="cisco_ios") == (
        "show interfaces trunk"
    )
    assert tools.infer_safe_remote_command("show allowed vlans", platform_key="cisco_nxos") == (
        "show interface trunk"
    )
    assert tools.infer_safe_remote_command("show routes", platform_key="cisco_ios") == "show ip route"
    assert tools.infer_safe_remote_command("show port-channel summary", platform_key="cisco_ios") == (
        "show etherchannel summary"
    )
    assert tools.infer_safe_remote_command("show routes", platform_key="cisco_nxos") == "show ip route vrf all"
    assert tools.infer_safe_remote_command("show port-channel summary", platform_key="cisco_nxos") == (
        "show port-channel summary"
    )
    assert tools.infer_safe_remote_command("connect to the server") == "hostname"
    assert tools.infer_safe_remote_command("what containers are running") == (
        "docker ps --format '{{.Names}}\t{{.Status}}'"
    )


def test_validate_read_only_command_blocks_dangerous_shell_ops():
    with pytest.raises(ValueError):
        tools.validate_read_only_command("rm -rf /")

    with pytest.raises(ValueError):
        tools.validate_read_only_command("uptime && reboot")


def test_resolve_remote_command_strips_prefix_and_falls_back_to_inference():
    assert tools.resolve_remote_command(command="run uptime") == "uptime"
    assert tools.resolve_remote_command(command="and show disk usage") == "df -h"
    assert (
        tools.resolve_remote_command(command="rm -rf /", request="show disk usage")
        == "df -h"
    )


def test_resolve_remote_command_allows_exact_platform_allowlisted_command():
    assert tools.resolve_remote_command(command="show version", platform_key="cisco_ios") == "show version"
    assert tools.resolve_remote_command(command="show run", platform_key="cisco_ios") == "show run"
    assert tools.resolve_remote_command(command="sh run", platform_key="cisco_ios") == "show run"
    assert (
        tools.resolve_remote_command(
            command="hostnamectl && uptime && free -h && df -h",
            platform_key="rhel",
        )
        == "hostnamectl && uptime && free -h && df -h"
    )


def test_resolve_remote_command_rejects_explicit_command_outside_platform_allowlist():
    with pytest.raises(tools.UnsupportedIntentError):
        tools.resolve_remote_command(command="free -h", platform_key="cisco_ios")


def test_clean_remote_output_compacts_and_limits_text():
    output = tools.clean_remote_output("  line one  \n\nline   two\n\n\nline three\n")
    assert output == "line one\n\nline two\n\nline three"


def test_run_nmap_service_detection_parses_service_metadata(monkeypatch):
    xml_output = """
<nmaprun>
  <host>
    <status state=\"up\"/>
    <address addr=\"192.168.1.10\" addrtype=\"ipv4\"/>
    <ports>
      <port protocol=\"tcp\" portid=\"22\">
        <state state=\"open\"/>
        <service name=\"ssh\" product=\"OpenSSH\" version=\"9.6\" extrainfo=\"protocol 2.0\"/>
      </port>
    </ports>
  </host>
</nmaprun>
""".strip()

    monkeypatch.setattr(scanning, "_build_nmap_base_cmd", lambda: ["nmap"])
    monkeypatch.setattr(
        scanning,
        "_run_nmap",
        lambda args, timeout=180: (type("Result", (), {"returncode": 0, "stdout": xml_output, "stderr": ""})(), None),
    )

    result = tools.run_nmap_service_detection(["192.168.1.10"], "22", profile="safe")

    assert result["success"] is True
    assert result["profile"] == "safe"
    assert result["findings"][0]["ports"][0]["service"] == "ssh"
    assert result["findings"][0]["ports"][0]["product"] == "OpenSSH"
    assert result["findings"][0]["ports"][0]["version"] == "9.6"
    assert result["findings"][0]["ports"][0]["extra_info"] == "protocol 2.0"


def test_run_tcp_connect_scan_reports_open_ports(monkeypatch):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_create_connection(target, timeout=None):
        host, port = target
        assert host == "192.168.1.10"
        if port == 80:
            return FakeSocket()
        raise ConnectionRefusedError("closed")

    monkeypatch.setattr(tools.scanning.socket, "create_connection", fake_create_connection)

    result = tools.run_tcp_connect_scan("192.168.1.10", "79-81")
    assert result["success"] is True
    assert result["scanned_count"] == 3
    assert result["requested_count"] == 3
    assert result["open_count"] == 1
    assert result["closed_count"] == 2
    assert result["timed_out_count"] == 0
    assert result["findings"] == [{"port": 80, "proto": "tcp", "open": True}]


def test_run_tcp_connect_scan_reports_fatal_host_error(monkeypatch):
    def fake_create_connection(target, timeout=None):
        raise OSError(errno.EHOSTUNREACH, "No route to host")

    monkeypatch.setattr(tools.scanning.socket, "create_connection", fake_create_connection)

    result = tools.run_tcp_connect_scan("192.168.1.10", "22,443")
    assert result["success"] is False
    assert result["error"] == "[Errno 113] No route to host"
    assert result["scanned_count"] == 1
    assert result["requested_count"] == 2
    assert result["open_count"] == 0
    assert result["closed_count"] == 0
    assert result["timed_out_count"] == 0


def test_run_tcp_connect_scan_tracks_timeouts_separately(monkeypatch):
    def fake_create_connection(target, timeout=None):
        raise tools.scanning.socket.timeout()

    monkeypatch.setattr(tools.scanning.socket, "create_connection", fake_create_connection)

    result = tools.run_tcp_connect_scan("192.168.1.10", "22-23")
    assert result["success"] is True
    assert result["scanned_count"] == 2
    assert result["requested_count"] == 2
    assert result["open_count"] == 0
    assert result["closed_count"] == 0
    assert result["timed_out_count"] == 2


def test_scan_host_tcp_ports_marks_fatal_connect_error_as_scan_failed(monkeypatch):
    monkeypatch.setattr("agent.skills.port_scan.ping_host", lambda host, count=1: {"reachable": False})
    monkeypatch.setattr(
        "agent.skills.port_scan.run_tcp_connect_scan",
        lambda host, ports: {
            "ports": ports,
            "success": False,
            "error": "[Errno 113] No route to host",
            "scanned_count": 1,
            "requested_count": 2,
            "open_count": 0,
            "closed_count": 0,
            "timed_out_count": 0,
            "findings": [],
        },
    )
    monkeypatch.setattr("agent.skills.port_scan.reverse_dns_lookup", lambda host: {})

    result = scan_host_tcp_ports("192.168.1.10", "22,443")
    assert result["status"] == "scan_failed"
    assert result["checks"]["port_scan"]["error"] == "[Errno 113] No route to host"


def test_execute_remote_ssh_command_preserves_ssh_failure_when_command_is_invalid(monkeypatch):
    monkeypatch.setattr(
        tools.ssh,
        "connect_ssh_session",
        lambda host, user, password=None, port=None: {
            "success": False,
            "host": host,
            "port": port,
            "user": user,
            "target": f"{user}@{host}",
            "error": "SSH authentication failed",
            "auth_failed": True,
        },
    )

    result = tools.execute_remote_ssh_command(
        host="192.168.1.10",
        user="admin",
        command="uptime && reboot",
    )

    assert result["success"] is False
    assert result["auth_failed"] is True
    assert result["error"] == "SSH authentication failed"
    assert result["command"] == "uptime"


def test_detect_platform_on_ssh_session_matches_rhel_without_probing_cisco():
    calls = []

    class FakeChannel:
        def recv_exit_status(self):
            return 0

    class FakeStream:
        def __init__(self, text):
            self._text = text.encode()
            self.channel = FakeChannel()

        def read(self):
            return self._text

    class FakeClient:
        def exec_command(self, command, timeout=None):
            calls.append(command)
            if command == "cat /etc/os-release":
                return None, FakeStream('PRETTY_NAME="Red Hat Enterprise Linux 9.4"'), FakeStream("")
            return None, FakeStream(""), FakeStream("")

    metadata = tools.detect_platform_on_ssh_session(FakeClient())
    assert metadata["platform_key"] == "rhel"
    assert calls == ["cat /etc/os-release"]


def test_detect_platform_on_ssh_session_prepares_cisco_terminal_length_before_show_version():
    calls = []

    class FakeChannel:
        def recv_exit_status(self):
            return 0

    class FakeStream:
        def __init__(self, text):
            self._text = text.encode()
            self.channel = FakeChannel()

        def read(self):
            return self._text

    class FakeClient:
        def exec_command(self, command, timeout=None):
            calls.append(command)
            if command == "show version":
                return None, FakeStream("Cisco IOS Software, Catalyst"), FakeStream("")
            return None, FakeStream(""), FakeStream("")

    metadata = tools.detect_platform_on_ssh_session(FakeClient())
    assert metadata["platform_key"] == "cisco_ios"
    assert calls == ["cat /etc/os-release", "uname -a", "terminal length 0", "show version"]
    assert metadata["prepared"] is True
    assert metadata["preparation_results"][0]["command"] == "terminal length 0"


def test_validate_raw_ssh_command_allows_cisco_show_and_blocks_config():
    assert tools.validate_raw_ssh_command("show version", platform_key="cisco_ios_xe") == "show version"
    with pytest.raises(ValueError):
        tools.validate_raw_ssh_command("configure terminal", platform_key="cisco_ios_xe")


def test_run_raw_command_on_ssh_session_returns_exact_stdout():
    class FakeChannel:
        def recv_exit_status(self):
            return 0

    class FakeStream:
        def __init__(self, text):
            self._text = text.encode()
            self.channel = FakeChannel()

        def read(self):
            return self._text

    class FakeClient:
        def exec_command(self, command, timeout=None):
            assert command == "show version"
            return None, FakeStream("line 1\r\nline 2\n"), FakeStream("")

    result = tools.run_raw_command_on_ssh_session(
        FakeClient(),
        host="192.168.1.10",
        user="admin",
        command="show version",
        platform_key="cisco_ios_xe",
    )

    assert result["success"] is True
    assert result["stdout"] == "line 1\r\nline 2\n"


def test_summarize_remote_result_for_rhel_memory():
    summary = tools.summarize_remote_result(
        "rhel",
        "show memory",
        "free -h",
        "               total        used        free      shared  buff/cache   available\nMem:           15Gi       4.2Gi       8.0Gi       200Mi       3.5Gi        10Gi\n",
        "",
    )
    assert summary == "Memory used 4.2Gi of 15Gi, available 10Gi."


def test_summarize_remote_result_for_cisco_interfaces():
    summary = tools.summarize_remote_result(
        "cisco_ios",
        "show interfaces",
        "show interfaces status",
        "Port Name Status Vlan Duplex Speed Type\nGi1/0/1 up 10 a-full a-1000 10/100/1000-TX\nGi1/0/2 down 1 auto auto 10/100/1000-TX\n",
        "",
    )
    assert summary == "Found 2 interface entries; 1 appear connected."


def test_summarize_remote_result_for_cisco_routes():
    summary = tools.summarize_remote_result(
        "cisco_nxos",
        "show routes",
        "show ip route vrf all",
        "IP Route Table for VRF \"default\"\n'*' denotes best ucast next-hop\n10.0.0.0/24, ubest/1, attached\n",
        "",
    )
    assert summary == "Collected routing table output with 3 lines."


def test_summarize_remote_result_for_cisco_port_channels():
    summary = tools.summarize_remote_result(
        "cisco_ios",
        "show port-channel",
        "show etherchannel summary",
        "Group  Port-channel  Protocol    Ports\n"
        "1      Po1(SU)         LACP      Gi1/0/1(P) Gi1/0/2(P)\n",
        "",
    )
    assert summary == "Found 1 port-channel summary entries."


def test_summarize_remote_result_for_cisco_interface_trunks():
    summary = tools.summarize_remote_result(
        "cisco_ios",
        "show interface trunk",
        "show interfaces trunk",
        "Port        Mode             Encapsulation  Status        Native vlan\n"
        "Gi1/0/1     on               802.1q         trunking      1\n",
        "",
    )
    assert summary == "Found 1 trunk entries; 1 report trunking."


def test_summarize_remote_result_for_cisco_vpc_entries():
    summary = tools.summarize_remote_result(
        "cisco_nxos",
        "show vpc",
        "show vpc",
        "Id    Port          Status Consistency Reason                Active vlans\n"
        "10    Po10          up     success     success               10-12\n",
        "",
    )
    assert summary == "Collected vPC state with 1 vPC entries."


def test_infer_safe_remote_command_maps_rhel_logs_intent():
    assert tools.infer_safe_remote_command("show logs", platform_key="rhel") == (
        "journalctl -p err -n 50 --no-pager"
    )


def test_unsupported_intent_error_for_platform_specific_request():
    with pytest.raises(tools.UnsupportedIntentError):
        tools.infer_safe_remote_command("show memory", platform_key="cisco_ios")
