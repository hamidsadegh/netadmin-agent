from contextlib import nullcontext
import time

try:
    from rich.console import Console
except ImportError:  # pragma: no cover
    Console = None


STATUS_SPINNER = "dots"
STATUS_STYLE = "bold dark_orange"
STATUS_DONE_STYLE = "bold green"
STATUS_FAIL_STYLE = "bold red"

CONSOLE = Console() if Console is not None else None


def status_context(message: str):
    if CONSOLE is None:
        return nullcontext()
    return CONSOLE.status(f"[{STATUS_STYLE}]{message}[/]", spinner=STATUS_SPINNER)


def print_status_outcome(message: str, success: bool, elapsed_seconds: float) -> None:
    if CONSOLE is None:
        return

    state = "done" if success else "failed"
    icon = "✓" if success else "✗"
    style = STATUS_DONE_STYLE if success else STATUS_FAIL_STYLE
    CONSOLE.print(f"[{style}]{icon} {message} {state} ({elapsed_seconds:.1f}s)[/]")


def run_with_status(message: str, func, *args, **kwargs):
    started = time.monotonic()
    try:
        with status_context(message):
            result = func(*args, **kwargs)
    except Exception:
        print_status_outcome(message, False, time.monotonic() - started)
        raise

    print_status_outcome(message, True, time.monotonic() - started)
    return result


def get_skill_status_message(skill_name: str) -> str:
    return {
        "check_device_connectivity": "Checking host reachability...",
        "discover_network_hosts": "Collecting network inventory...",
        "scan_host_tcp_ports": "Scanning TCP ports...",
        "run_remote_ssh_diagnostic": "Collecting remote diagnostics...",
    }.get(skill_name, "Working...")
