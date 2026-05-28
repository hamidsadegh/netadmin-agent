from agent.platforms.base import CommandSpec, PlatformProfile


CISCO_IOS_PROFILE = PlatformProfile(
    key="cisco_ios",
    label="Cisco IOS / Catalyst",
    family="cisco",
    detection_hints=(
        "Cisco IOS Software",
        "Cisco Internetwork Operating System Software",
        "Catalyst",
    ),
    safe_commands={
        "system_health": CommandSpec("system_health", "show version", "Version, uptime, platform, and image details."),
        "interfaces": CommandSpec("interfaces", "show interfaces status", "Port admin/oper/duplex/speed summary."),
        "interface_trunk": CommandSpec("interface_trunk", "show interfaces trunk", "Trunk state and allowed VLAN summary."),
        "ip_interfaces": CommandSpec("ip_interfaces", "show ip interface brief", "Layer-3 interface summary."),
        "routes": CommandSpec("routes", "show ip route", "Routing table summary."),
        "vlans": CommandSpec("vlans", "show vlan brief", "VLAN inventory."),
        "neighbors": CommandSpec("neighbors", "show cdp neighbors detail", "Neighbor discovery details."),
        "mac_table": CommandSpec("mac_table", "show mac address-table", "MAC learning table."),
        "spanning_tree": CommandSpec("spanning_tree", "show spanning-tree", "STP state and root details."),
        "port_channel": CommandSpec("port_channel", "show etherchannel summary", "EtherChannel health and membership."),
        "logs": CommandSpec("logs", "show logging", "Device log buffer."),
        "running_config": CommandSpec("running_config", "show run", "Current running configuration."),
    },
)
