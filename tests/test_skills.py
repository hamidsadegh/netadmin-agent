from agent import skills
from agent.skills.cisco import playbooks


class DummyClient:
    pass


def test_run_cisco_interface_check_playbook_filters_matches(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "interfaces": [
                        {"port": "Gi1/0/24", "status": "down", "vlan": "20"},
                        {"port": "Gi1/0/1", "status": "up", "vlan": "10"},
                    ]
                }
            },
        },
        "show ip interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "ip_interfaces": [
                        {"interface": "Vlan10", "status": "up", "protocol": "up"}
                    ]
                }
            },
        },
        "show neighbors": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "neighbors": [
                        {"device_id": "edge-sw", "local_interface": "Gi1/0/24", "remote_port": "Eth1/1"}
                    ]
                }
            },
        },
        "show mac table": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "mac_table": [
                        {"mac": "0011.2233.4455", "port": "Gi1/0/24", "vlan": "20"}
                    ]
                }
            },
        },
    }

    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: responses[request],
    )

    result = skills.run_cisco_interface_check_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/24",
        platform_key="cisco_ios",
    )
    assert result["matches"]["interfaces"][0]["port"] == "Gi1/0/24"
    assert result["matches"]["neighbors"][0]["device_id"] == "edge-sw"
    assert "neighbor(s) seen" in result["summary"]


def test_run_cisco_uplink_health_playbook_propagates_neighbor_failure(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"interfaces": []}},
        },
        "show neighbors": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ssh_failed",
            "result": {"parsed": {"neighbors": []}},
        },
    }

    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: responses[request],
    )

    result = skills.run_cisco_uplink_health_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        platform_key="cisco_ios",
    )
    assert result["status"] == "ssh_failed"


def test_run_cisco_interface_mac_table_playbook_filters_by_interface(monkeypatch):
    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "mac_table": [
                        {"mac": "0011.2233.4455", "port": "GigabitEthernet1/0/6", "vlan": "10"},
                        {"mac": "00aa.bbcc.ddee", "port": "Gi1/0/7", "vlan": "20"},
                    ]
                }
            },
        },
    )

    result = skills.run_cisco_interface_mac_table_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/6",
        platform_key="cisco_ios",
    )

    assert result["skill"] == "cisco_interface_mac_table_playbook"
    assert result["matches"] == [{"mac": "0011.2233.4455", "port": "GigabitEthernet1/0/6", "vlan": "10"}]
    assert "Found 1 MAC table entry on Gi1/0/6" in result["summary"]


def test_run_cisco_interface_check_playbook_propagates_step_failure(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"interfaces": [{"port": "Gi1/0/24", "status": "down", "vlan": "20"}]}},
        },
        "show ip interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ssh_failed",
            "result": {"parsed": {"ip_interfaces": []}},
        },
        "show neighbors": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"neighbors": []}},
        },
        "show mac table": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"mac_table": []}},
        },
    }

    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: responses[request],
    )

    result = skills.run_cisco_interface_check_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/24",
        platform_key="cisco_ios",
    )
    assert result["status"] == "ssh_failed"


def test_run_cisco_interface_down_playbook_builds_observations(monkeypatch):
    monkeypatch.setattr(
        playbooks,
        "run_cisco_interface_check_playbook",
        lambda client, host, user, interface_name, platform_key=None: {
            "skill": "cisco_interface_check_playbook",
            "host": host,
            "user": user,
            "platform_key": platform_key,
            "interface": interface_name,
            "matches": {
                "interfaces": [{"port": interface_name, "status": "down", "vlan": "20"}],
                "ip_interfaces": [],
                "neighbors": [],
                "mac_table": [],
            },
            "steps": {},
            "summary": "placeholder",
        },
    )
    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "stdout": "May 17 12:00:00: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/24, changed state to down\n"
            },
        },
    )

    result = skills.run_cisco_interface_down_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/24",
        platform_key="cisco_ios",
    )
    assert result["skill"] == "cisco_interface_down_playbook"
    assert "link appears down" in result["summary"]
    assert "no CDP neighbor" in result["summary"]
    assert result["log_matches"]
    assert "cable/SFP/patch path disconnected" in result["possible_reasons"]
