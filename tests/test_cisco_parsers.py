from agent.parsers.cisco import (
    parse_show_cdp_neighbors_detail,
    parse_show_interfaces_status,
    parse_show_ip_interface_brief,
    parse_show_mac_address_table,
    parse_show_vlan_brief,
)


def test_parse_show_interfaces_status():
    parsed = parse_show_interfaces_status(
        "Port  Name  Status  Vlan\nGi1/0/1  uplink  connected  trunk\nGi1/0/2  phone  notconnect  20\n"
    )
    assert parsed[0]["port"] == "Gi1/0/1"
    assert parsed[0]["status"] == "connected"


def test_parse_show_ip_interface_brief():
    parsed = parse_show_ip_interface_brief(
        "Interface IP-Address OK? Method Status Protocol\nVlan10 10.0.10.1 YES manual up up\n"
    )
    assert parsed[0]["interface"] == "Vlan10"
    assert parsed[0]["status"] == "up"


def test_parse_show_ip_interface_brief_preserves_ios_admin_down_status():
    parsed = parse_show_ip_interface_brief(
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet1/0/24  unassigned      YES unset  administratively down down\n"
    )
    assert parsed[0]["interface"] == "GigabitEthernet1/0/24"
    assert parsed[0]["ip_address"] == "unassigned"
    assert parsed[0]["status"] == "administratively down"
    assert parsed[0]["protocol"] == "down"


def test_parse_show_ip_interface_brief_parses_nxos_interface_status_column():
    parsed = parse_show_ip_interface_brief(
        "Interface              IP Address      Interface Status     Protocol Status\n"
        "Ethernet1/2            unassigned      admin-down/down     down\n"
    )
    assert parsed[0]["interface"] == "Ethernet1/2"
    assert parsed[0]["ip_address"] == "unassigned"
    assert parsed[0]["status"] == "admin-down/down"
    assert parsed[0]["protocol"] == "down"


def test_parse_show_vlan_brief():
    parsed = parse_show_vlan_brief(
        "VLAN Name Status Ports\n10 users active Gi1/0/1\n20 voice active Gi1/0/2\n"
    )
    assert parsed[1]["vlan_id"] == "20"


def test_parse_show_mac_address_table():
    parsed = parse_show_mac_address_table(
        " 10  0011.2233.4455 DYNAMIC Gi1/0/1\n"
    )
    assert parsed[0]["mac"] == "0011.2233.4455"
    assert parsed[0]["port"] == "Gi1/0/1"


def test_parse_show_cdp_neighbors_detail():
    parsed = parse_show_cdp_neighbors_detail(
        "Device ID: core-sw\nInterface: Gig 1/0/1,  Port ID (outgoing port): Eth1/1\n-------------------------\n"
    )
    assert parsed[0]["device_id"] == "core-sw"
