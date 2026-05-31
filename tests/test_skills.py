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


def test_run_cisco_interface_deep_dive_collects_logs_and_config(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "stdout": "Gi1/0/24 down line\n",
                "parsed": {"interfaces": [{"port": "Gi1/0/24", "status": "down", "vlan": "20"}]},
            },
        },
        "show ip interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"ip_interfaces": [{"interface": "Gi1/0/24", "status": "down", "protocol": "down"}]}},
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
        "show logs": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"stdout": "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/24, changed state to down\n"},
        },
        "show running config": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "stdout": "interface GigabitEthernet1/0/24\n description test port\n switchport access vlan 20\n!\n"
            },
        },
    }

    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: responses[request],
    )

    result = skills.run_cisco_interface_deep_dive_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/24",
        platform_key="cisco_ios",
    )

    assert result["skill"] == "cisco_interface_deep_dive_playbook"
    assert result["log_matches"]
    assert "switchport access vlan 20" in result["config_block"]
    assert "Interface deep dive Gi1/0/24" in result["summary"]


def test_run_cisco_interface_config_diff_reports_missing_lines(monkeypatch):
    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "stdout": "interface GigabitEthernet1/0/24\n description test port\n switchport access vlan 20\n!\n"
            },
        },
    )

    result = skills.run_cisco_interface_config_diff_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/24",
        expected_config="description test port; switchport access vlan 30",
        platform_key="cisco_ios",
    )

    assert result["skill"] == "cisco_interface_config_diff_playbook"
    assert result["comparison"]["present"] == ["description test port"]
    assert result["comparison"]["missing"] == ["switchport access vlan 30"]
    assert result["assessment"] == "attention"


def test_run_cisco_mac_lookup_playbook_matches_dotted_static_cpu_mac(monkeypatch):
    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "mac_table": [
                        {"mac": "0100.0ccc.cccd", "port": "CPU", "vlan": "All", "type": "STATIC"},
                    ]
                }
            },
        },
    )

    result = skills.run_cisco_mac_lookup_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        mac="0100.0ccc.cccd",
        platform_key="cisco_ios",
    )

    assert result["matches"] == [
        {"mac": "0100.0ccc.cccd", "port": "CPU", "vlan": "All", "type": "STATIC"}
    ]
    assert "Found 1 matching MAC table entries" in result["summary"]


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


def test_run_cisco_trunk_uplink_playbook_assesses_bundle_and_trunk(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "interfaces": [{"port": "Gi1/0/1", "status": "connected", "vlan": "trunk"}]
                }
            },
        },
        "show neighbors": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "neighbors": [
                        {"device_id": "core-sw", "local_interface": "Gi1/0/1", "remote_port": "Eth1/1"}
                    ]
                }
            },
        },
        "show spanning tree": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"stdout": "Gi1/0/1    Desg FWD 4         128.1    P2p\n"},
        },
        "show port-channel": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "port_channels": [
                        {
                            "group": "1",
                            "port_channel": "Po1",
                            "flags": "SU",
                            "protocol": "LACP",
                            "members": [{"interface": "GigabitEthernet1/0/1", "flags": "P"}],
                        }
                    ]
                }
            },
        },
        "show interface trunk": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "interface_trunks": [
                        {
                            "port": "Gi1/0/1",
                            "status": "trunking",
                            "native_vlan": "1",
                            "allowed_vlans": "1,10,20",
                            "active_vlans": "1,10,20",
                            "forwarding_vlans": "1,10,20",
                        }
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

    result = skills.run_cisco_trunk_uplink_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/1",
        platform_key="cisco_ios",
    )
    assert result["skill"] == "cisco_trunk_uplink_playbook"
    assert result["assessment"] == "healthy"
    assert result["matches"]["port_channels"][0]["matched_member"]["flags"] == "P"
    assert "interface is shown as a trunk" in result["observations"]
    assert result["risks"] == []


def test_run_cisco_trunk_uplink_playbook_flags_unbundled_access_port(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "interfaces": [{"port": "Eth1/1", "status": "connected", "vlan": "10"}]
                }
            },
        },
        "show neighbors": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"neighbors": []}},
        },
        "show spanning tree": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"stdout": ""},
        },
        "show port-channel": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "port_channels": [
                        {
                            "group": "10",
                            "port_channel": "Po10",
                            "flags": "SD",
                            "protocol": "LACP",
                            "members": [{"interface": "Ethernet1/1", "flags": "D"}],
                        }
                    ]
                }
            },
        },
        "show interface trunk": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"interface_trunks": []}},
        },
        "show vpc": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"stdout": "", "parsed": {"vpc": {"vpcs": []}}},
        },
    }

    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: responses[request],
    )

    result = skills.run_cisco_trunk_uplink_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Eth1/1",
        platform_key="cisco_nxos",
    )
    assert result["assessment"] == "attention"
    assert "uplink is not currently listed as trunk" in result["risks"]
    assert "interface appears in a port-channel but is not bundled" in result["risks"]


def test_run_cisco_trunk_uplink_playbook_flags_vlan_mismatch(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"interfaces": [{"port": "Gi1/0/1", "status": "connected", "vlan": "trunk"}]}},
        },
        "show neighbors": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"neighbors": [{"device_id": "core-sw", "local_interface": "Gi1/0/1"}]}},
        },
        "show spanning tree": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"stdout": "Gi1/0/1    Desg FWD 4         128.1    P2p\n"},
        },
        "show port-channel": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"port_channels": []}},
        },
        "show interface trunk": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "interface_trunks": [
                        {
                            "port": "Gi1/0/1",
                            "status": "trunking",
                            "native_vlan": "1",
                            "allowed_vlans": "10,20",
                            "active_vlans": "10,20",
                            "forwarding_vlans": "10",
                        }
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

    result = skills.run_cisco_trunk_uplink_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Gi1/0/1",
        platform_key="cisco_ios",
    )
    assert result["assessment"] == "attention"
    assert result["trunk_vlan_analysis"]["entry"]["allowed_vlans"] == "10,20"
    assert "allowed active VLANs not forwarding or pruned by STP: 20" in result["risks"]


def test_run_cisco_trunk_uplink_playbook_adds_nxos_vpc_analysis(monkeypatch):
    responses = {
        "show interfaces": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"interfaces": [{"port": "Eth1/1", "status": "connected", "vlan": "trunk"}]}},
        },
        "show neighbors": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"parsed": {"neighbors": [{"device_id": "core-sw", "local_interface": "Eth1/1"}]}},
        },
        "show spanning tree": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {"stdout": "Eth1/1 Desg FWD\n"},
        },
        "show port-channel": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "port_channels": [
                        {
                            "group": "10",
                            "port_channel": "Po10",
                            "flags": "SU",
                            "protocol": "LACP",
                            "members": [{"interface": "Ethernet1/1", "flags": "P"}],
                        }
                    ]
                }
            },
        },
        "show interface trunk": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "parsed": {
                    "interface_trunks": [
                        {
                            "port": "Eth1/1",
                            "status": "trunking",
                            "native_vlan": "1",
                            "allowed_vlans": "10-12",
                            "active_vlans": "10-12",
                            "forwarding_vlans": "10-12",
                        }
                    ]
                }
            },
        },
        "show vpc": {
            "skill": "run_remote_ssh_diagnostic",
            "status": "ok",
            "result": {
                "stdout": "10    Po10          down   failed      VLAN mismatch\n",
                "parsed": {
                    "vpc": {
                        "peer_status": "peer adjacency formed ok",
                        "keepalive_status": "peer is alive",
                        "peer_link_status": "up",
                        "vpcs": [
                            {
                                "id": "10",
                                "port_channel": "Po10",
                                "status": "down",
                                "consistency": "failed",
                                "reason": "VLAN mismatch",
                            }
                        ],
                    }
                },
            },
        },
    }

    monkeypatch.setattr(
        playbooks,
        "run_remote_ssh_diagnostic_on_session",
        lambda client, host, user, command=None, request=None, platform_key=None: responses[request],
    )

    result = skills.run_cisco_trunk_uplink_playbook(
        DummyClient(),
        host="10.0.0.10",
        user="admin",
        interface_name="Eth1/1",
        platform_key="cisco_nxos",
    )
    assert result["vpc_analysis"]["matches"][0]["port_channel"] == "Po10"
    assert "vPC 10 is not up" in result["risks"]
    assert "vPC 10 consistency is failed" in result["risks"]


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
