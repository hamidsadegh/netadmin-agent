from agent.platforms.base import CommandSpec, PlatformProfile


CISCO_NXOS_PROFILE = PlatformProfile(
    key="cisco_nxos",
    label="Cisco NX-OS",
    family="cisco",
    detection_hints=(
        "Cisco Nexus Operating System",
        "NX-OS",
        "Nexus",
    ),
    safe_commands={
        "system_health": CommandSpec("system_health", "show version", "NX-OS version, uptime, image, and hardware overview."),
        "interfaces": CommandSpec("interfaces", "show interface brief", "Interface admin/oper summary."),
        "interface_trunk": CommandSpec("interface_trunk", "show interface trunk", "Trunk state and allowed VLAN summary."),
        "ip_interfaces": CommandSpec("ip_interfaces", "show ip interface vrf all", "Layer-3 interface status across VRFs."),
        "routes": CommandSpec("routes", "show ip route vrf all", "Routing table summary across VRFs."),
        "vlans": CommandSpec("vlans", "show vlan brief", "VLAN summary."),
        "neighbors": CommandSpec("neighbors", "show cdp neighbors detail", "CDP neighbor details."),
        "mac_table": CommandSpec("mac_table", "show mac address-table", "MAC table."),
        "port_channel": CommandSpec("port_channel", "show port-channel summary", "LAG health and membership."),
        "spanning_tree": CommandSpec("spanning_tree", "show spanning-tree", "STP state and root details."),
        "vpc": CommandSpec("vpc", "show vpc", "vPC state and consistency."),
        "logs": CommandSpec("logs", "show logging last 50", "Recent device logs."),
        "running_config": CommandSpec("running_config", "show run", "Current running configuration."),
    },
)
