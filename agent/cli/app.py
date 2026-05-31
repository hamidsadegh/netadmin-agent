import argparse
import getpass
import importlib
import json
from pathlib import Path
import shutil
import sys
import termios
import tty

try:
    from rich import print
except ImportError:  # pragma: no cover
    from builtins import print

from agent.prompts import build_result_explainer_prompt, build_skill_router_prompt
from agent.providers import get_provider
from agent.providers.gemini import get_genai_modules
from agent.skills import (
    check_device_connectivity,
    discover_network_hosts,
    run_cisco_interface_check_playbook,
    run_cisco_interface_config_diff_playbook,
    run_cisco_interface_deep_dive_playbook,
    run_cisco_interface_down_playbook,
    run_cisco_interface_mac_table_playbook,
    run_cisco_mac_lookup_playbook,
    run_cisco_trunk_uplink_playbook,
    run_cisco_uplink_health_playbook,
    run_cisco_vlan_check_playbook,
    run_remote_ssh_diagnostic,
    run_remote_ssh_diagnostic_on_session,
    scan_host_tcp_ports,
)
from agent.tools import UnsupportedIntentError, connect_ssh_session, run_raw_command_on_ssh_session

from .formatting import (
    PLATFORM_EXAMPLES,
    build_interactive_prompt,
    format_active_session_status,
    format_help_response,
    format_identity_response,
    format_playbook_result,
    format_result_for_fallback,
    format_scan_memory,
)
from .history import setup_interactive_history
from .memory import (
    SessionMemory,
    apply_remember_command,
    format_last_result,
    format_long_term_memory,
    format_session_memory,
    is_last_result_request,
    is_long_term_memory_request,
    is_memory_request,
    load_long_term_memory,
    parse_remember_command,
    recall_long_term_context,
    refers_to_last_interface,
    save_long_term_memory,
)
from .parsing import (
    INTERFACE_PATTERN,
    MAC_ADDRESS_PATTERN,
    VLAN_ID_PATTERN,
    complete_follow_up,
    detect_ambiguous_follow_up,
    extract_json,
    is_casual_greeting,
    is_help_request,
    is_identity_request,
    is_scan_memory_request,
    is_session_info_request,
    normalize_skill_call,
    parse_direct_skill_request,
)
from .status import get_skill_status_message, run_with_status


ACTIVE_SSH_SESSION = None
ACTIVE_INTERACTIVE_MODE = "agent"
PENDING_FOLLOW_UP = None
LAST_SCAN_RESULT = None
SESSION_MEMORY = SessionMemory()
LONG_TERM_MEMORY = load_long_term_memory()
PAGER_MIN_LINES = 12
SIMULATOR_PLATFORMS = ("ios", "iosxe", "nxos")
ANSWER_SEPARATOR = "-" * 72
CONTROL_COMPLETIONS = (
    "help",
    "?",
    "/",
    "agent mode",
    "ssh mode",
    "exit",
    "disconnect",
)
AGENT_COMPLETIONS = (
    "check ",
    "scan ",
    "connect to ",
    "list all scanned hosts",
    "show memory",
    "show remembered devices",
    "show last result",
    "remember this device as ",
    "remember subnet ",
    "remember preference ",
    "session info",
    "what can I do on this platform?",
    "troubleshoot interface ",
    "deep dive ",
    "compare config ",
    "why is interface down ",
    "mac table for int ",
    "find mac ",
    "check vlan ",
)
CISCO_SSH_COMPLETION_EXTRAS = {
    "cisco_ios": (
        "show interface status",
        "show int status",
        "show mac table",
        "show logging",
        "show run",
        "sh run",
    ),
    "cisco_ios_xe": (
        "show interface status",
        "show int status",
        "show mac table",
        "show logging",
        "show run",
        "sh run",
    ),
    "cisco_nxos": (
        "show interfaces status",
        "show int status",
        "show mac table",
        "show logging last 50",
        "show run",
        "sh run",
    ),
}


def _read_pager_key() -> str:
    if not sys.stdin.isatty():
        try:
            return input()
        except EOFError:
            return "q"

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def print_paged(text: str, *, force: bool = False) -> None:
    lines = str(text).splitlines()
    terminal_height = shutil.get_terminal_size((80, 24)).lines
    page_size = max(5, terminal_height - 3)
    should_page = (force and len(lines) > PAGER_MIN_LINES) or len(lines) > page_size
    if not should_page:
        print(text)
        return

    for start in range(0, len(lines), page_size):
        chunk = lines[start : start + page_size]
        print("\n".join(chunk))
        if start + page_size >= len(lines):
            break
        sys.stdout.write("--More-- Enter/Space next page, q quit ")
        sys.stdout.flush()
        key = _read_pager_key().lower()
        sys.stdout.write("\r" + " " * 42 + "\r")
        sys.stdout.flush()
        if key == "q":
            break


def _with_answer_separator(text: str) -> str:
    return f"{str(text).rstrip()}\n{ANSWER_SEPARATOR}"


def print_answer(text: str, *, force: bool = False) -> None:
    print_paged(_with_answer_separator(text), force=force)


def get_client():
    return get_provider().get_client()


def get_interactive_completion_candidates(session: dict | None, mode: str) -> list[str]:
    candidates = set(CONTROL_COMPLETIONS)
    if mode == "ssh" and session:
        platform_key = session.get("platform_key")
        candidates.update(CISCO_SSH_COMPLETION_EXTRAS.get(platform_key, ()))
        for example in PLATFORM_EXAMPLES.get(platform_key, ()):
            if example.lower().startswith(("show ", "sh ")):
                candidates.add(example)
        from agent.tools import get_platform_profile

        profile = get_platform_profile(platform_key)
        if profile:
            candidates.update(spec.command for spec in profile.safe_commands.values())
    else:
        candidates.update(AGENT_COMPLETIONS)
        if session:
            candidates.update(PLATFORM_EXAMPLES.get(session.get("platform_key"), ()))
    return sorted(candidates)


def complete_interactive_input(text: str, state: int):
    matches = [
        candidate
        for candidate in get_interactive_completion_candidates(ACTIVE_SSH_SESSION, ACTIVE_INTERACTIVE_MODE)
        if candidate.lower().startswith(str(text).lower())
    ]
    try:
        return matches[state]
    except IndexError:
        return None


def ask_model_for_skill(user_input: str) -> str:
    prompt = build_skill_router_prompt(user_input)
    return get_provider().generate(prompt, temperature=0.1, max_output_tokens=1024)


def explain_skill_result(user_input: str, skill_result: dict) -> str:
    prompt = build_result_explainer_prompt(user_input, skill_result)
    return get_provider().generate(prompt, temperature=0.2, max_output_tokens=2048)


def remember_interaction(user_input: str, result: dict | None = None, rendered: str | None = None) -> None:
    SESSION_MEMORY.remember_from_text(
        user_input,
        interface_pattern=INTERFACE_PATTERN,
        mac_pattern=MAC_ADDRESS_PATTERN,
        vlan_pattern=VLAN_ID_PATTERN,
    )
    SESSION_MEMORY.remember_from_result(result)
    if ACTIVE_SSH_SESSION:
        SESSION_MEMORY.remember_device(ACTIVE_SSH_SESSION)
    if rendered:
        SESSION_MEMORY.remember_result_summary(rendered)
    summary = None
    if isinstance(result, dict):
        summary = result.get("summary")
        if not summary and isinstance(result.get("result"), dict):
            summary = result["result"].get("summary")
    SESSION_MEMORY.remember_turn(user_input, summary or rendered)


def format_session_status_with_memory(session: dict | None) -> str:
    base = format_active_session_status(session)
    remembered = recall_long_term_context(LONG_TERM_MEMORY, session)
    if remembered:
        return f"{base}\n\nMemory:\n- {remembered}"
    return base


def resolve_memory_reference(user_input: str) -> str:
    if refers_to_last_interface(user_input) and SESSION_MEMORY.last_interface:
        return f"{user_input} {SESSION_MEMORY.last_interface}"
    return user_input


def execute_skill(skill_name: str, args: dict) -> dict:
    if skill_name == "check_device_connectivity":
        return check_device_connectivity(**args)
    if skill_name == "discover_network_hosts":
        return discover_network_hosts(**args)
    if skill_name == "scan_host_tcp_ports":
        return scan_host_tcp_ports(**args)
    if skill_name == "run_remote_ssh_diagnostic":
        return run_remote_ssh_diagnostic(**args)
    raise ValueError(f"Unknown skill requested: {skill_name}")


def _load_simulator_server():
    try:
        return importlib.import_module("simulators.cisco_ssh_simulator").SimulatorServer
    except ImportError:
        workspace_root = Path(__file__).resolve().parents[3]
        if str(workspace_root) not in sys.path:
            sys.path.insert(0, str(workspace_root))
        try:
            return importlib.import_module("simulators.cisco_ssh_simulator").SimulatorServer
        except ImportError as exc:
            raise RuntimeError(
                "Cisco simulator package not found. Keep the sibling simulators repo at ../simulators "
                "or install it on PYTHONPATH."
            ) from exc


def run_simulator_ssh_diagnostic(
    platform: str,
    command: str | None = None,
    request: str | None = None,
) -> dict:
    if platform not in SIMULATOR_PLATFORMS:
        raise ValueError(f"Unsupported simulator platform: {platform}")

    SimulatorServer = _load_simulator_server()
    server = SimulatorServer(platform=platform, port=0).start()
    try:
        result = run_remote_ssh_diagnostic(
            host="127.0.0.1",
            port=server.port,
            user=server.username,
            password=server.password,
            command=command,
            request=request,
        )
        result["simulator"] = {
            "platform": platform,
            "host": "127.0.0.1",
            "port": server.port,
            "user": server.username,
        }
        return result
    finally:
        server.stop()


def close_active_ssh_session() -> None:
    global ACTIVE_SSH_SESSION, ACTIVE_INTERACTIVE_MODE
    if ACTIVE_SSH_SESSION and ACTIVE_SSH_SESSION.get("client"):
        try:
            ACTIVE_SSH_SESSION["client"].close()
        except Exception:
            pass
    ACTIVE_SSH_SESSION = None
    ACTIVE_INTERACTIVE_MODE = "agent"


def handle_interactive_control_command(question: str) -> str | None:
    global ACTIVE_INTERACTIVE_MODE
    lowered = question.lower()
    if is_help_request(question):
        print_answer(format_help_response(ACTIVE_SSH_SESSION, ACTIVE_INTERACTIVE_MODE), force=True)
        return "handled"
    if lowered in ["agent mode", "agent", "/agent"]:
        ACTIVE_INTERACTIVE_MODE = "agent"
        print_answer("Agent mode enabled.")
        return "handled"
    if lowered in ["ssh mode", "raw mode", "normal mode", "no agent mode", "/ssh", "/raw"]:
        if not ACTIVE_SSH_SESSION:
            print_answer("No active SSH session. Connect to a host first.")
            return "handled"
        ACTIVE_INTERACTIVE_MODE = "ssh"
        print_answer("SSH mode enabled. Commands are sent directly as read-only SSH commands.")
        return "handled"
    if lowered in ["exit", "quit"]:
        if ACTIVE_SSH_SESSION:
            close_active_ssh_session()
            print_answer("SSH session closed.")
            return "handled"
        return "quit"
    if lowered in ["disconnect", "close ssh", "logout"]:
        close_active_ssh_session()
        print_answer("SSH session closed.")
        return "handled"
    if question.startswith("\x1b") or not question:
        return "handled"
    return None


def print_raw_ssh_result(result: dict) -> None:
    stdout_text = result.get("stdout") or ""
    stderr_text = result.get("stderr") or ""
    error_text = result.get("error")
    if stdout_text:
        sys.stdout.write(stdout_text)
        sys.stdout.flush()
    if stderr_text:
        sys.stderr.write(stderr_text)
        sys.stderr.flush()
    if not stdout_text and not stderr_text and error_text:
        print_answer(f"SSH command failed: {error_text}")


def maybe_complete_ssh_args(skill_name: str, args: dict) -> dict:
    if skill_name != "run_remote_ssh_diagnostic":
        return args

    completed = dict(args)
    if not completed.get("user"):
        completed["user"] = input(f"SSH username for {completed.get('host')}: ").strip()
    return completed


def maybe_retry_ssh_with_password(skill_name: str, args: dict, result: dict) -> dict:
    global ACTIVE_SSH_SESSION

    if skill_name != "run_remote_ssh_diagnostic":
        return result
    ssh_result = result.get("result", {}) if isinstance(result, dict) else {}
    needs_password = result.get("status") == "ssh_auth_failed" or ssh_result.get("auth_failed")
    if not needs_password or args.get("password"):
        return result

    password = getpass.getpass(f"Password for {args.get('user')}@{args.get('host')}: ")
    if not password:
        return result

    session = connect_ssh_session(args.get("host"), args.get("user"), password=password, port=args.get("port"))
    if not session.get("success"):
        return {
            "skill": "run_remote_ssh_diagnostic",
            "host": args.get("host"),
            "port": args.get("port"),
            "user": args.get("user"),
            "status": "ssh_auth_failed" if session.get("auth_failed") else "ssh_failed",
            "result": {
                "tool": "execute_remote_ssh_command",
                "host": args.get("host"),
                "port": args.get("port"),
                "user": args.get("user"),
                "command": ssh_result.get("command"),
                "success": False,
                "cleaned_stdout": "",
                "cleaned_stderr": "",
                "error": session.get("error"),
                "auth_failed": session.get("auth_failed", False),
            },
        }

    close_active_ssh_session()
    ACTIVE_SSH_SESSION = session
    return run_remote_ssh_diagnostic_on_session(
        session["client"],
        host=args.get("host"),
        port=args.get("port"),
        user=args.get("user"),
        command=args.get("command"),
        request=args.get("request"),
        platform_key=session.get("platform_key"),
    )


def _extract_expected_config_request(user_input: str, interface_name: str) -> str | None:
    lowered = user_input.lower()
    markers = (" expected ", " should have ", " should be ")
    for marker in markers:
        idx = lowered.find(marker)
        if idx >= 0:
            expected = user_input[idx + len(marker) :].strip(" .")
            return expected or None
    return None


def maybe_run_cisco_playbook(user_input: str):
    global ACTIVE_SSH_SESSION

    if not ACTIVE_SSH_SESSION:
        return None
    platform_key = ACTIVE_SSH_SESSION.get("platform_key")
    if platform_key not in {"cisco_ios", "cisco_ios_xe", "cisco_nxos"}:
        return None

    lowered = user_input.lower()
    interface_match = INTERFACE_PATTERN.search(user_input)

    if not interface_match and refers_to_last_interface(user_input) and SESSION_MEMORY.last_interface:
        user_input = f"{user_input} {SESSION_MEMORY.last_interface}"
        lowered = user_input.lower()
        interface_match = INTERFACE_PATTERN.search(user_input)

    if interface_match and any(term in lowered for term in ("deep dive", "deep-dive", "full check", "full troubleshoot")):
        return run_cisco_interface_deep_dive_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            interface_name=interface_match.group(0),
            platform_key=platform_key,
        )

    if interface_match and any(term in lowered for term in ("compare config", "config diff", "expected config", "should have", "should be")):
        expected_config = _extract_expected_config_request(user_input, interface_match.group(0))
        if expected_config:
            return run_cisco_interface_config_diff_playbook(
                ACTIVE_SSH_SESSION["client"],
                host=ACTIVE_SSH_SESSION["host"],
                user=ACTIVE_SSH_SESSION["user"],
                interface_name=interface_match.group(0),
                expected_config=expected_config,
                platform_key=platform_key,
            )

    if interface_match and any(word in lowered for word in ("mac", "mac table", "mac address")):
        return run_cisco_interface_mac_table_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            interface_name=interface_match.group(0),
            platform_key=platform_key,
        )

    trunk_uplink_terms = (
        "trunk",
        "uplink",
        "allowed vlan",
        "allowed vlans",
        "vlan mismatch",
        "port-channel",
        "port channel",
        "etherchannel",
        "lacp",
        "pagp",
        "vpc",
    )
    if interface_match and any(term in lowered for term in trunk_uplink_terms):
        return run_cisco_trunk_uplink_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            interface_name=interface_match.group(0),
            platform_key=platform_key,
        )

    if interface_match and any(word in lowered for word in ("why", "down", "problem", "issue", "troubleshoot", "log", "logs")):
        return run_cisco_interface_down_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            interface_name=interface_match.group(0),
            platform_key=platform_key,
        )

    if interface_match and any(word in lowered for word in ("interface", "port", "check", "status", "show")):
        return run_cisco_interface_check_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            interface_name=interface_match.group(0),
            platform_key=platform_key,
        )

    if "uplink" in lowered and any(word in lowered for word in ("health", "check", "status")):
        return run_cisco_uplink_health_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            platform_key=platform_key,
        )

    mac_match = MAC_ADDRESS_PATTERN.search(user_input)
    if mac_match and any(word in lowered for word in ("find", "lookup", "where", "mac")):
        return run_cisco_mac_lookup_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            mac=mac_match.group(0),
            platform_key=platform_key,
        )

    vlan_match = VLAN_ID_PATTERN.search(user_input)
    if vlan_match and any(word in lowered for word in ("check", "show", "why", "status", "vlan")):
        return run_cisco_vlan_check_playbook(
            ACTIVE_SSH_SESSION["client"],
            host=ACTIVE_SSH_SESSION["host"],
            user=ACTIVE_SSH_SESSION["user"],
            vlan_id=vlan_match.group(1),
            platform_key=platform_key,
        )

    return None


def run_agent(user_input: str):
    global ACTIVE_SSH_SESSION, PENDING_FOLLOW_UP, LAST_SCAN_RESULT

    skill_call = None
    model_response = None
    original_user_input = user_input

    if ACTIVE_INTERACTIVE_MODE == "ssh" and ACTIVE_SSH_SESSION:
        try:
            result = run_raw_command_on_ssh_session(
                ACTIVE_SSH_SESSION["client"],
                host=ACTIVE_SSH_SESSION["host"],
                port=ACTIVE_SSH_SESSION.get("port"),
                user=ACTIVE_SSH_SESSION["user"],
                command=user_input,
                platform_key=ACTIVE_SSH_SESSION.get("platform_key"),
            )
            print_raw_ssh_result(result)
            SESSION_MEMORY.remember_command(result.get("command"))
            SESSION_MEMORY.remember_device(ACTIVE_SSH_SESSION)
            SESSION_MEMORY.remember_turn(original_user_input, f"raw SSH command: {result.get('command')}")
        except Exception as exc:
            print_answer(str(exc))
        return

    user_input = resolve_memory_reference(user_input)

    if is_casual_greeting(user_input):
        print_answer("Hi. What should we check?")
        return

    if is_help_request(user_input):
        print_answer(format_help_response(ACTIVE_SSH_SESSION, ACTIVE_INTERACTIVE_MODE), force=True)
        return

    if is_identity_request(user_input):
        print_answer(format_identity_response(ACTIVE_SSH_SESSION), force=True)
        return

    if is_memory_request(user_input):
        print_answer(format_session_memory(SESSION_MEMORY), force=True)
        return

    remember_command = parse_remember_command(user_input)
    if remember_command:
        print_answer(apply_remember_command(remember_command, ACTIVE_SSH_SESSION, LONG_TERM_MEMORY))
        return

    if is_long_term_memory_request(user_input):
        print_answer(format_long_term_memory(LONG_TERM_MEMORY), force=True)
        return

    if is_last_result_request(user_input):
        print_answer(format_last_result(SESSION_MEMORY), force=True)
        return

    if is_scan_memory_request(user_input):
        print_answer(format_scan_memory(SESSION_MEMORY.last_scan or LAST_SCAN_RESULT), force=True)
        return

    if PENDING_FOLLOW_UP:
        skill_call = complete_follow_up(PENDING_FOLLOW_UP, user_input)
        if not skill_call:
            print_answer(PENDING_FOLLOW_UP.get("question") or "I still need a bit more detail.")
            return
        PENDING_FOLLOW_UP = None
    else:
        skill_call = None if (ACTIVE_SSH_SESSION and refers_to_last_interface(user_input)) else parse_direct_skill_request(user_input)

    if is_session_info_request(user_input):
        print_answer(format_session_status_with_memory(ACTIVE_SSH_SESSION), force=True)
        return

    if not skill_call and ACTIVE_SSH_SESSION:
        playbook_result = maybe_run_cisco_playbook(user_input)
        if playbook_result:
            rendered = format_playbook_result(playbook_result)
            remember_interaction(original_user_input, playbook_result, rendered)
            print_answer(rendered)
            return
        try:
            result = run_with_status(
                "Collecting data from active session...",
                run_remote_ssh_diagnostic_on_session,
                ACTIVE_SSH_SESSION["client"],
                host=ACTIVE_SSH_SESSION["host"],
                port=ACTIVE_SSH_SESSION.get("port"),
                user=ACTIVE_SSH_SESSION["user"],
                request=user_input,
                platform_key=ACTIVE_SSH_SESSION.get("platform_key"),
            )
            rendered = format_result_for_fallback(result)
            remember_interaction(original_user_input, result, rendered)
            print_answer(rendered)
            return
        except UnsupportedIntentError as exc:
            print_answer(str(exc))
            return
        except ValueError as exc:
            print_answer(f"I couldn't map that to a safe SSH diagnostic command yet: {exc}")
            return
        except Exception:
            close_active_ssh_session()

    if not skill_call:
        follow_up = detect_ambiguous_follow_up(user_input)
        if follow_up:
            PENDING_FOLLOW_UP = follow_up
            print_answer(follow_up["question"])
            return

    if not skill_call:
        try:
            model_response = run_with_status("Planning action...", ask_model_for_skill, user_input)
        except Exception as exc:
            print_answer(f"[red]Model routing failed:[/red] {exc}")
            return
        skill_call = normalize_skill_call(extract_json(model_response))

    if not skill_call:
        print_answer(model_response or "I couldn't determine a safe action for that request.")
        return

    try:
        skill_name = skill_call.get("skill")
        args = maybe_complete_ssh_args(skill_name, skill_call.get("args", {}))
        result = run_with_status(get_skill_status_message(skill_name), execute_skill, skill_name, args)
        result = maybe_retry_ssh_with_password(skill_name, args, result)
        if skill_name == "discover_network_hosts":
            LAST_SCAN_RESULT = result
            SESSION_MEMORY.remember_scan(result)
    except Exception as exc:
        print_answer(f"[red]Skill execution failed:[/red] {exc}\n{skill_call}")
        return

    if skill_name == "run_remote_ssh_diagnostic" and result.get("status") == "ok" and not ACTIVE_SSH_SESSION:
        session = run_with_status(
            "Opening persistent SSH session...",
            connect_ssh_session,
            args.get("host"),
            args.get("user"),
            password=args.get("password"),
            port=args.get("port"),
        )
        if session.get("success"):
            ACTIVE_SSH_SESSION = session
            SESSION_MEMORY.remember_device(session)

    if skill_name == "run_remote_ssh_diagnostic":
        rendered = format_result_for_fallback(result)
        remember_interaction(original_user_input, result, rendered)
        print_answer(rendered)
        return

    try:
        explanation = run_with_status("Summarizing result...", explain_skill_result, user_input, result)
        remember_interaction(original_user_input, result, explanation)
        print_answer(explanation)
    except Exception:
        rendered = format_result_for_fallback(result)
        remember_interaction(original_user_input, result, rendered)
        print_answer(rendered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetAdmin Agent")
    parser.add_argument("--prompt", help="Ask the agent a single natural-language question")
    parser.add_argument("--host", help="Run a direct connectivity check for one host")
    parser.add_argument("--scan", help="Run a direct subnet discovery scan")
    parser.add_argument("--ports", default="profile", help="Comma-separated port list or ranges for --scan")
    parser.add_argument("--scanner", choices=["nmap", "masscan"], help="Scanner to use for --scan (default: nmap)")
    parser.add_argument("--scan-profile", choices=["quick", "default", "deep"], default="default", help="Safe scan profile for --scan")
    parser.add_argument("--service-detection", choices=["safe", "deep"], help="Run nmap service/version detection after discovery")
    parser.add_argument("--ssh-host", help="Run a remote SSH diagnostic against one host")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port for --ssh-host")
    parser.add_argument("--ssh-user", help="SSH username for --ssh-host")
    parser.add_argument("--ssh-cmd", help="Explicit safe read-only SSH command to run")
    parser.add_argument("--ssh-request", help="Natural-language SSH diagnostic request to infer a safe command")
    parser.add_argument(
        "--simulator",
        choices=SIMULATOR_PLATFORMS,
        help="Start a local Cisco SSH simulator and run --ssh-cmd or --ssh-request against it",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.host:
        print(json.dumps(run_with_status("Checking host reachability...", check_device_connectivity, args.host), indent=2))
        return

    if args.scan:
        print(
            json.dumps(
                run_with_status(
                    "Collecting network inventory...",
                    discover_network_hosts,
                    cidr=args.scan,
                    ports=args.ports,
                    scanner=args.scanner,
                    scan_profile=args.scan_profile,
                    service_detection=args.service_detection,
                ),
                indent=2,
            )
        )
        return

    if args.simulator:
        print(
            json.dumps(
                run_with_status(
                    "Running local Cisco simulator diagnostic...",
                    run_simulator_ssh_diagnostic,
                    args.simulator,
                    command=args.ssh_cmd,
                    request=args.ssh_request,
                ),
                indent=2,
            )
        )
        return

    if args.ssh_host:
        ssh_user = args.ssh_user or input(f"SSH username for {args.ssh_host}: ").strip()
        session = run_with_status("Connecting over SSH...", connect_ssh_session, args.ssh_host, ssh_user, port=args.ssh_port)
        platform_key = session.get("platform_key") if session.get("success") else None
        if session.get("success"):
            session["client"].close()
        result = run_with_status(
            "Collecting remote diagnostics...",
            run_remote_ssh_diagnostic,
            host=args.ssh_host,
            port=args.ssh_port,
            user=ssh_user,
            command=args.ssh_cmd,
            request=args.ssh_request,
            platform_key=platform_key,
        )
        if result.get("status") == "ssh_auth_failed":
            password = getpass.getpass(f"Password for {ssh_user}@{args.ssh_host}: ")
            if password:
                result = run_with_status(
                    "Retrying remote diagnostics...",
                    run_remote_ssh_diagnostic,
                    host=args.ssh_host,
                    port=args.ssh_port,
                    user=ssh_user,
                    command=args.ssh_cmd,
                    request=args.ssh_request,
                    password=password,
                    platform_key=platform_key,
                )
        print(json.dumps(result, indent=2))
        return

    if args.prompt:
        run_agent(args.prompt)
        return

    setup_interactive_history(completer=complete_interactive_input)
    print("[bold green]NetAdmin Agent started. Type 'exit' to quit.[/bold green]")

    while True:
        try:
            question = input(build_interactive_prompt(ACTIVE_SSH_SESSION, ACTIVE_INTERACTIVE_MODE)).strip()
        except KeyboardInterrupt:
            print("\nExiting NetAdmin Agent.")
            break
        except EOFError:
            print("\nExiting NetAdmin Agent.")
            break
        control_action = handle_interactive_control_command(question)
        if control_action == "quit":
            break
        if control_action == "handled":
            continue
        run_agent(question)

    close_active_ssh_session()
