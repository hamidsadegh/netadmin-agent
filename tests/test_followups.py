from agent.cli import app as cli_app
from agent.cli.parsing import complete_follow_up, detect_ambiguous_follow_up


def test_detect_ambiguous_follow_up_for_scan_without_cidr():
    follow_up = detect_ambiguous_follow_up("scan the subnet")
    assert follow_up["skill"] == "discover_network_hosts"
    assert follow_up["missing"] == ["cidr"]
    assert "CIDR" in follow_up["question"]


def test_detect_ambiguous_follow_up_preserves_ping_only_intent():
    follow_up = detect_ambiguous_follow_up("scan the subnet for ping")
    assert follow_up["skill"] == "discover_network_hosts"
    assert follow_up["args"]["ports"] is None


def test_detect_ambiguous_follow_up_for_ssh_without_host():
    follow_up = detect_ambiguous_follow_up("ssh into the switch")
    assert follow_up["skill"] == "run_remote_ssh_diagnostic"
    assert follow_up["missing"] == ["host"]
    assert "SSH" in follow_up["question"]


def test_detect_ambiguous_follow_up_for_ssh_without_user():
    follow_up = detect_ambiguous_follow_up("connect to 192.168.1.10")
    assert follow_up["skill"] == "run_remote_ssh_diagnostic"
    assert follow_up["missing"] == ["user"]
    assert "192.168.1.10" in follow_up["question"]


def test_detect_ambiguous_follow_up_for_hostname_ssh_without_user():
    follow_up = detect_ambiguous_follow_up("ssh to core-switch-01")
    assert follow_up["skill"] == "run_remote_ssh_diagnostic"
    assert follow_up["missing"] == ["user"]
    assert "core-switch-01" in follow_up["question"]


def test_complete_follow_up_fills_cidr_and_default_ports():
    completed = complete_follow_up(
        {"skill": "discover_network_hosts", "args": {}, "missing": ["cidr"]},
        "192.168.1.0/24",
    )
    assert completed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.1.0/24", "ports": "22,80,443"},
    }


def test_complete_follow_up_preserves_ping_only_when_cidr_arrives_later():
    completed = complete_follow_up(
        {"skill": "discover_network_hosts", "args": {"ports": None}, "missing": ["cidr"]},
        "192.168.1.0/24",
    )
    assert completed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.1.0/24", "ports": None},
    }


def test_complete_follow_up_accepts_first_ports_for_subnet_scan():
    completed = complete_follow_up(
        {"skill": "discover_network_hosts", "args": {}, "missing": ["cidr"]},
        "192.168.1.0/24 first 50 ports",
    )
    assert completed == {
        "skill": "discover_network_hosts",
        "args": {"cidr": "192.168.1.0/24", "ports": "1-50"},
    }


def test_complete_follow_up_fills_host_and_port_from_hostport():
    completed = complete_follow_up(
        {"skill": "run_remote_ssh_diagnostic", "args": {}, "missing": ["host"]},
        "127.0.0.1:2222",
    )
    assert completed == {
        "skill": "run_remote_ssh_diagnostic",
        "args": {"host": "127.0.0.1", "port": 2222},
    }


def test_complete_follow_up_fills_hostname_and_port_from_hostport():
    completed = complete_follow_up(
        {"skill": "run_remote_ssh_diagnostic", "args": {}, "missing": ["host"]},
        "core-switch-01:2222",
    )
    assert completed == {
        "skill": "run_remote_ssh_diagnostic",
        "args": {"host": "core-switch-01", "port": 2222},
    }


def test_complete_follow_up_accepts_user_at_host_reply():
    completed = complete_follow_up(
        {"skill": "run_remote_ssh_diagnostic", "args": {}, "missing": ["host", "user"]},
        "ssh admin@core-switch-01",
    )
    assert completed == {
        "skill": "run_remote_ssh_diagnostic",
        "args": {"host": "core-switch-01", "user": "admin"},
    }


def test_complete_follow_up_skips_filler_words_when_host_arrives_later():
    completed = complete_follow_up(
        {"skill": "run_remote_ssh_diagnostic", "args": {}, "missing": ["host"]},
        "the host is core-switch-01 please",
    )
    assert completed == {
        "skill": "run_remote_ssh_diagnostic",
        "args": {"host": "core-switch-01"},
    }


def test_complete_follow_up_skips_filler_words_when_user_arrives_later():
    completed = complete_follow_up(
        {
            "skill": "run_remote_ssh_diagnostic",
            "args": {"host": "192.168.1.10"},
            "missing": ["user"],
        },
        "use admin please",
    )
    assert completed == {
        "skill": "run_remote_ssh_diagnostic",
        "args": {"host": "192.168.1.10", "user": "admin"},
    }


def test_run_agent_keeps_pending_follow_up_until_answered(monkeypatch):
    outputs = []
    cli_app.PENDING_FOLLOW_UP = None
    cli_app.ACTIVE_SSH_SESSION = None
    monkeypatch.setattr(cli_app, "print", lambda *args, **kwargs: outputs.append(" ".join(str(a) for a in args)))

    cli_app.run_agent("scan the subnet")
    assert outputs[-1] == "Which subnet should I scan? Give me a CIDR like 192.168.1.0/24."
    assert cli_app.PENDING_FOLLOW_UP is not None

    monkeypatch.setattr(cli_app, "execute_skill", lambda skill, args: {"skill": skill, "cidr": args["cidr"], "ports": args["ports"], "status": "ok", "host_count": 0, "hosts": {}, "checks": {}})
    monkeypatch.setattr(cli_app, "run_with_status", lambda _message, func, *args, **kwargs: func(*args, **kwargs))
    monkeypatch.setattr(cli_app, "explain_skill_result", lambda user_input, result: f"done {result['cidr']} {result['ports']}")

    cli_app.run_agent("192.168.1.0/24")
    assert outputs[-1] == "done 192.168.1.0/24 22,80,443"
    assert cli_app.PENDING_FOLLOW_UP is None
