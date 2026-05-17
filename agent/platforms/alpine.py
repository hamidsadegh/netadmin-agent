from agent.platforms.base import CommandSpec, PlatformProfile


ALPINE_PROFILE = PlatformProfile(
    key="alpine",
    label="Alpine Linux",
    family="linux",
    detection_hints=("Alpine Linux", "PRETTY_NAME=\"Alpine Linux", "ID=alpine", "ID=\"alpine\""),
    safe_commands={
        "system_health": CommandSpec("system_health", "hostname && uptime && free -h && df -h", "Portable Alpine health snapshot."),
        "cpu": CommandSpec("cpu", "top -bn1", "BusyBox top snapshot when available."),
        "memory": CommandSpec("memory", "free -h", "Human-readable memory usage."),
        "disk": CommandSpec("disk", "df -h", "Filesystem capacity and use."),
        "interfaces": CommandSpec("interfaces", "ip addr show", "Interface and address state."),
        "routes": CommandSpec("routes", "ip route", "Kernel routing table."),
        "services": CommandSpec("services", "rc-status", "OpenRC service state where available."),
    },
)
