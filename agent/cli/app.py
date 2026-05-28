import argparse
import getpass
import json
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
from agent.tools import UnsupportedIntentError, connect_ssh_session

from .formatting import (
    build_interactive_prompt,
    format_active_session_status,
    format_playbook_result,
    format_result_for_fallback,
)
from .history import setup_interactive_history
from .parsing import (
    INTERFACE_PATTERN,
    MAC_ADDRESS_PATTERN,
    VLAN_ID_PATTERN,
    complete_follow_up,
    detect_ambiguous_follow_up,
    extract_json,
    is_session_info_request,
    normalize_skill_call,
    parse_direct_skill_request,
)
from .status import get_skill_status_message, run_with_status


ACTIVE_SSH_SESSION = None
PENDING_FOLLOW_UP = None
PAGER_MIN_LINES = 12


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


def get_client():
    return get_provider().get_client()


def ask_model_for_skill(user_input: str) -> str:
    prompt = build_skill_router_prompt(user_input)
    return get_provider().generate(prompt, temperature=0.1, max_output_tokens=1024)


def explain_skill_result(user_input: str, skill_result: dict) -> str:
    prompt = build_result_explainer_prompt(user_input, skill_result)
    return get_provider().generate(prompt, temperature=0.2, max_output_tokens=2048)


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


def close_active_ssh_session() -> None:
    global ACTIVE_SSH_SESSION
    if ACTIVE_SSH_SESSION and ACTIVE_SSH_SESSION.get("client"):
        try:
            ACTIVE_SSH_SESSION["client"].close()
        except Exception:
            pass
    ACTIVE_SSH_SESSION = None


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


def maybe_run_cisco_playbook(user_input: str):
    global ACTIVE_SSH_SESSION

    if not ACTIVE_SSH_SESSION:
        return None
    platform_key = ACTIVE_SSH_SESSION.get("platform_key")
    if platform_key not in {"cisco_ios", "cisco_ios_xe", "cisco_nxos"}:
        return None

    lowered = user_input.lower()
    interface_match = INTERFACE_PATTERN.search(user_input)

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

    if interface_match and any(word in lowered for word in ("why", "down", "problem", "issue", "troubleshoot")):
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
    global ACTIVE_SSH_SESSION, PENDING_FOLLOW_UP

    skill_call = None
    model_response = None

    if PENDING_FOLLOW_UP:
        skill_call = complete_follow_up(PENDING_FOLLOW_UP, user_input)
        if not skill_call:
            print(PENDING_FOLLOW_UP.get("question") or "I still need a bit more detail.")
            return
        PENDING_FOLLOW_UP = None
    else:
        skill_call = parse_direct_skill_request(user_input)

    if is_session_info_request(user_input):
        print_paged(format_active_session_status(ACTIVE_SSH_SESSION), force=True)
        return

    if not skill_call and ACTIVE_SSH_SESSION:
        playbook_result = maybe_run_cisco_playbook(user_input)
        if playbook_result:
            print_paged(format_playbook_result(playbook_result))
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
            print_paged(format_result_for_fallback(result))
            return
        except UnsupportedIntentError as exc:
            print(str(exc))
            return
        except ValueError as exc:
            print(f"I couldn't map that to a safe SSH diagnostic command yet: {exc}")
            return
        except Exception:
            close_active_ssh_session()

    if not skill_call:
        follow_up = detect_ambiguous_follow_up(user_input)
        if follow_up:
            PENDING_FOLLOW_UP = follow_up
            print(follow_up["question"])
            return

    if not skill_call:
        try:
            model_response = run_with_status("Planning action...", ask_model_for_skill, user_input)
        except Exception as exc:
            print(f"[red]Model routing failed:[/red] {exc}")
            return
        skill_call = normalize_skill_call(extract_json(model_response))

    if not skill_call:
        print(model_response or "I couldn't determine a safe action for that request.")
        return

    try:
        skill_name = skill_call.get("skill")
        args = maybe_complete_ssh_args(skill_name, skill_call.get("args", {}))
        result = run_with_status(get_skill_status_message(skill_name), execute_skill, skill_name, args)
        result = maybe_retry_ssh_with_password(skill_name, args, result)
    except Exception as exc:
        print(f"[red]Skill execution failed:[/red] {exc}")
        print(skill_call)
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

    if skill_name == "run_remote_ssh_diagnostic":
        print_paged(format_result_for_fallback(result))
        return

    try:
        explanation = run_with_status("Summarizing result...", explain_skill_result, user_input, result)
        print_paged(explanation)
    except Exception:
        print_paged(format_result_for_fallback(result))


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

    setup_interactive_history()
    print("[bold green]NetAdmin Agent started. Type 'exit' to quit.[/bold green]")

    while True:
        try:
            question = input(build_interactive_prompt(ACTIVE_SSH_SESSION)).strip()
        except KeyboardInterrupt:
            print("\nExiting NetAdmin Agent.")
            break
        except EOFError:
            print("\nExiting NetAdmin Agent.")
            break
        if question.lower() in ["exit", "quit"]:
            break
        if question.lower() in ["disconnect", "close ssh", "logout"]:
            close_active_ssh_session()
            print("SSH session closed.")
            continue
        if question.startswith("\x1b") or not question:
            continue
        run_agent(question)

    close_active_ssh_session()
