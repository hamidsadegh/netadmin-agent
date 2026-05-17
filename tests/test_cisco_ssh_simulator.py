from agent import tools
from agent.skills import run_remote_ssh_diagnostic
from demos.simulator_integration_demo import run_demo
from simulators.cisco_ssh_simulator import CiscoCommandSimulator, SimulatorServer, PROFILES


def test_cisco_simulator_returns_ios_show_version():
    simulator = CiscoCommandSimulator(PROFILES["ios"])
    result = simulator.execute("show version")
    assert result.exit_status == 0
    assert "Cisco IOS Software" in result.stdout
    assert "IOS XE" not in result.stdout


def test_cisco_simulator_returns_ios_xe_show_version():
    simulator = CiscoCommandSimulator(PROFILES["iosxe"])
    result = simulator.execute("show version")
    assert result.exit_status == 0
    assert "Cisco IOS XE Software" in result.stdout
    assert "C9300-48P" in result.stdout


def test_cisco_simulator_loads_ios_xe_catalog_commands():
    simulator = CiscoCommandSimulator(PROFILES["iosxe"])
    result = simulator.execute("show power inline")

    assert result.exit_status == 0
    assert "Interface" in result.stdout
    assert len(PROFILES["iosxe"].command_table) >= 100


def test_cisco_simulator_loads_nxos_catalog_commands_and_aliases():
    simulator = CiscoCommandSimulator(PROFILES["nxos"])
    result = simulator.execute("show logging last 50")

    assert result.exit_status == 0
    assert "%DAEMON" in result.stdout
    assert len(PROFILES["nxos"].command_table) >= 100


def test_cisco_simulator_rejects_unknown_command():
    simulator = CiscoCommandSimulator(PROFILES["nxos"])
    result = simulator.execute("write erase")
    assert result.exit_status == 1
    assert "% Invalid input detected" in result.stderr


def test_cisco_simulator_accepts_running_config_aliases():
    simulator = CiscoCommandSimulator(PROFILES["ios"])

    for command in ("show run", "show running-config", "sh run"):
        result = simulator.execute(command)
        assert result.exit_status == 0
        assert "hostname access-sw1" in result.stdout


def test_ios_simulator_supports_platform_detection_and_command_execution():
    server = SimulatorServer(platform="ios", port=0).start()
    session = None

    try:
        session = tools.connect_ssh_session(
            host="127.0.0.1",
            port=server.port,
            user="admin",
            password="admin",
        )
        assert session["success"] is True
        assert session["platform_key"] == "cisco_ios"
        assert session["prepared"] is True

        result = tools.run_command_on_ssh_session(
            session["client"],
            host="127.0.0.1",
            port=server.port,
            user="admin",
            command="show interfaces status",
            platform_key="cisco_ios",
        )
        assert result["success"] is True
        assert result["summary"] == "Found 4 interface entries; 3 appear connected."
        assert len(result["parsed"]["interfaces"]) == 4
    finally:
        if session and session.get("client"):
            session["client"].close()
        server.stop()


def test_nxos_simulator_supports_platform_detection():
    server = SimulatorServer(platform="nxos", port=0).start()
    session = None

    try:
        session = tools.connect_ssh_session(
            host="127.0.0.1",
            port=server.port,
            user="admin",
            password="admin",
        )
        assert session["platform_key"] == "cisco_nxos"
        assert "NX-OS" in session["fingerprint"]
    finally:
        if session and session.get("client"):
            session["client"].close()
        server.stop()


def test_ios_xe_simulator_supports_platform_detection():
    server = SimulatorServer(platform="iosxe", port=0).start()
    session = None

    try:
        session = tools.connect_ssh_session(
            host="127.0.0.1",
            port=server.port,
            user="admin",
            password="admin",
        )
        assert session["platform_key"] == "cisco_ios_xe"
        assert session["session_mode"] == "cisco_cli"
        assert "IOS XE" in session["fingerprint"]
    finally:
        if session and session.get("client"):
            session["client"].close()
        server.stop()


def test_run_remote_ssh_diagnostic_accepts_custom_port():
    server = SimulatorServer(platform="ios", port=0).start()
    try:
        result = run_remote_ssh_diagnostic(
            host="127.0.0.1",
            port=server.port,
            user="admin",
            password="admin",
            request="show neighbors",
        )
        assert result["status"] == "ok"
        assert result["port"] == server.port
        assert result["platform_key"] == "cisco_ios"
    finally:
        server.stop()


def test_simulator_integration_demo_runs_for_ios():
    result = run_demo("ios")
    assert result["ok"] is True
    assert result["detected_platform"] == "cisco_ios"
    assert result["one_shot"]["status"] == "ok"
