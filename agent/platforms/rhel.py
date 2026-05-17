from agent.platforms.base import CommandSpec, PlatformProfile


RHEL_PROFILE = PlatformProfile(
    key="rhel",
    label="Red Hat Enterprise Linux / compatible",
    family="linux",
    detection_hints=(
        "Red Hat Enterprise Linux",
        "CentOS Linux",
        "CentOS Stream",
        "Rocky Linux",
        "AlmaLinux",
        "PRETTY_NAME=\"Red Hat",
        "ID=\"rhel\"",
        "ID_LIKE=\"rhel",
    ),
    safe_commands={
        "system_health": CommandSpec("system_health", "hostnamectl && uptime && free -h && df -h", "High-value first-pass health snapshot for RHEL-like hosts."),
        "cpu": CommandSpec("cpu", "top -bn1", "Batch-mode CPU/process snapshot."),
        "memory": CommandSpec("memory", "free -h", "Human-readable memory usage."),
        "disk": CommandSpec("disk", "df -h", "Filesystem capacity and use."),
        "interfaces": CommandSpec("interfaces", "ip -br addr", "Interface and IP summary."),
        "routes": CommandSpec("routes", "ip route", "Kernel routing table."),
        "services": CommandSpec("services", "systemctl --type=service --state=running --no-pager", "Running services on systemd-based RHEL hosts."),
        "logs": CommandSpec("logs", "journalctl -p err -n 50 --no-pager", "Recent error-priority journal entries."),
        "errors": CommandSpec("errors", "journalctl -p err -n 50 --no-pager", "Recent error-priority journal entries."),
    },
)
