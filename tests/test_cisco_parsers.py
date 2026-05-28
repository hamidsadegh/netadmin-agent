from agent.parsers.cisco import (
    parse_show_cdp_neighbors_detail,
    parse_show_interfaces_status,
    parse_show_interfaces_trunk,
    parse_show_ip_interface_brief,
    parse_show_mac_address_table,
    parse_show_port_channel_summary,
    parse_show_vpc,
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


def test_parse_show_port_channel_summary_ios_members():
    parsed = parse_show_port_channel_summary(
        "Group  Port-channel  Protocol    Ports\n"
        "------+-------------+-----------+-----------------------------------------------\n"
        "1      Po1(SU)         LACP      Gi1/0/1(P) Gi1/0/2(P)\n"
    )
    assert parsed[0]["group"] == "1"
    assert parsed[0]["port_channel"] == "Po1"
    assert parsed[0]["flags"] == "SU"
    assert parsed[0]["protocol"] == "LACP"
    assert parsed[0]["members"] == [
        {"interface": "Gi1/0/1", "flags": "P"},
        {"interface": "Gi1/0/2", "flags": "P"},
    ]


def test_parse_show_port_channel_summary_nxos_members():
    parsed = parse_show_port_channel_summary(
        "Group Port-Channel Type Protocol Member Ports\n"
        "1     Po10(SD)     Eth  LACP     Eth1/1(D) Eth1/2(P)\n"
    )
    assert parsed[0]["port_channel"] == "Po10"
    assert parsed[0]["flags"] == "SD"
    assert parsed[0]["members"][0] == {"interface": "Eth1/1", "flags": "D"}


def test_parse_show_interfaces_trunk_ios_sections():
    parsed = parse_show_interfaces_trunk(
        "Port        Mode             Encapsulation  Status        Native vlan\n"
        "Gi1/0/1     on               802.1q         trunking      1\n\n"
        "Port        Vlans allowed on trunk\n"
        "Gi1/0/1     1,10,20\n\n"
        "Port        Vlans allowed and active in management domain\n"
        "Gi1/0/1     1,10\n\n"
        "Port        Vlans in spanning tree forwarding state and not pruned\n"
        "Gi1/0/1     1\n"
    )
    assert parsed[0]["port"] == "Gi1/0/1"
    assert parsed[0]["status"] == "trunking"
    assert parsed[0]["native_vlan"] == "1"
    assert parsed[0]["allowed_vlans"] == "1,10,20"
    assert parsed[0]["active_vlans"] == "1,10"
    assert parsed[0]["forwarding_vlans"] == "1"


def test_parse_show_interfaces_trunk_nxos_sections():
    parsed = parse_show_interfaces_trunk(
        "Port          Native  Status        Port\n"
        "              Vlan                  Channel\n"
        "Eth1/1        1       trunking      Po10\n\n"
        "Port          Vlans Allowed on Trunk\n"
        "Eth1/1        10-12,20\n\n"
        "Port          STP Forwarding\n"
        "Eth1/1        10-12\n"
    )
    assert parsed[0]["port"] == "Eth1/1"
    assert parsed[0]["status"] == "trunking"
    assert parsed[0]["port_channel"] == "Po10"
    assert parsed[0]["allowed_vlans"] == "10-12,20"
    assert parsed[0]["forwarding_vlans"] == "10-12"


def test_parse_show_vpc_extracts_status_and_rows():
    parsed = parse_show_vpc(
        "Peer status                : peer adjacency formed ok\n"
        "Peer keep-alive status     : peer is alive\n"
        "vPC peer-link status       : up\n\n"
        "Id    Port          Status Consistency Reason                Active vlans\n"
        "10    Po10          up     success     success               10-12\n"
    )
    assert parsed["peer_status"] == "peer adjacency formed ok"
    assert parsed["peer_link_status"] == "up"
    assert parsed["vpcs"][0]["port_channel"] == "Po10"


def test_parse_show_cdp_neighbors_detail():
    parsed = parse_show_cdp_neighbors_detail(
        "Device ID: core-sw\nInterface: Gig 1/0/1,  Port ID (outgoing port): Eth1/1\n-------------------------\n"
    )
    assert parsed[0]["device_id"] == "core-sw"
