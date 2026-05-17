from agent.cli.app import (
    ACTIVE_SSH_SESSION,
    ask_model_for_skill,
    build_parser,
    close_active_ssh_session,
    execute_skill,
    explain_skill_result,
    get_client,
    get_genai_modules,
    main,
    maybe_complete_ssh_args,
    maybe_retry_ssh_with_password,
    maybe_run_cisco_playbook,
    run_agent,
    scan_host_tcp_ports,
)
from agent.cli.formatting import (
    build_interactive_prompt,
    format_active_session_status,
    format_playbook_result,
    format_result_for_fallback,
)
from agent.cli.history import get_history_file, save_interactive_history, setup_interactive_history
from agent.cli.parsing import (
    extract_explicit_ssh_command,
    extract_json,
    is_session_info_request,
    normalize_skill_call,
    parse_direct_skill_request,
)
from agent.cli.status import get_skill_status_message, run_with_status

__all__ = [
    "ACTIVE_SSH_SESSION",
    "ask_model_for_skill",
    "build_interactive_prompt",
    "build_parser",
    "close_active_ssh_session",
    "execute_skill",
    "explain_skill_result",
    "extract_explicit_ssh_command",
    "extract_json",
    "format_active_session_status",
    "format_playbook_result",
    "format_result_for_fallback",
    "get_client",
    "get_genai_modules",
    "get_history_file",
    "get_skill_status_message",
    "is_session_info_request",
    "main",
    "maybe_complete_ssh_args",
    "maybe_retry_ssh_with_password",
    "maybe_run_cisco_playbook",
    "normalize_skill_call",
    "parse_direct_skill_request",
    "run_agent",
    "scan_host_tcp_ports",
    "run_with_status",
    "save_interactive_history",
    "setup_interactive_history",
]

if __name__ == "__main__":
    main()
