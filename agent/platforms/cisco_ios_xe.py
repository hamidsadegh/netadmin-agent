from agent.platforms.base import CommandSpec, PlatformProfile


CISCO_IOS_XE_PROFILE = PlatformProfile(
    key="cisco_ios_xe",
    label="Cisco IOS-XE",
    family="cisco",
    detection_hints=(
        "IOS-XE",
        "IOS XE",
        "CAT9K_IOSXE",
        "CSR1000V",
        "Cisco IOS XE Software",
    ),
    safe_commands={
        "system_health": CommandSpec("system_health", "show version", "Version, uptime, platform, and image details."),
        "interfaces": CommandSpec("interfaces", "show interfaces status", "Port admin/oper/duplex/speed summary."),
        "ip_interfaces": CommandSpec("ip_interfaces", "show ip interface brief", "Layer-3 interface summary."),
        "routes": CommandSpec("routes", "show ip route", "Routing table summary."),
        "vlans": CommandSpec("vlans", "show vlan brief", "VLAN inventory."),
        "neighbors": CommandSpec("neighbors", "show cdp neighbors detail", "Neighbor discovery details."),
        "mac_table": CommandSpec("mac_table", "show mac address-table", "MAC learning table."),
        "spanning_tree": CommandSpec("spanning_tree", "show spanning-tree", "STP state and root details."),
        "logs": CommandSpec("logs", "show logging", "Device log buffer."),
        "running_config": CommandSpec("running_config", "show run", "Current running configuration."),
    },
)
