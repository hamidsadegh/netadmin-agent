from agent.tools import execute_remote_ssh_command, run_command_on_ssh_session


def run_remote_ssh_diagnostic(
    host: str,
    user: str,
    port: int | None = None,
    command: str | None = None,
    request: str | None = None,
    password: str | None = None,
    platform_key: str | None = None,
) -> dict:
    ssh_result = execute_remote_ssh_command(
        host=host,
        user=user,
        port=port,
        command=command,
        request=request,
        password=password,
        platform_key=platform_key,
    )

    status = "ok" if ssh_result.get("success") else "ssh_failed"
    if ssh_result.get("auth_failed"):
        status = "ssh_auth_failed"
    return {
        "skill": "run_remote_ssh_diagnostic",
        "host": host,
        "port": ssh_result.get("port") or port,
        "user": user,
        "status": status,
        "platform_key": ssh_result.get("platform_key") or platform_key,
        "result": ssh_result,
    }


def run_remote_ssh_diagnostic_on_session(
    client,
    host: str,
    user: str,
    port: int | None = None,
    command: str | None = None,
    request: str | None = None,
    platform_key: str | None = None,
) -> dict:
    ssh_result = run_command_on_ssh_session(
        client,
        host=host,
        user=user,
        port=port,
        command=command,
        request=request,
        platform_key=platform_key,
    )
    status = "ok" if ssh_result.get("success") else "ssh_failed"
    return {
        "skill": "run_remote_ssh_diagnostic",
        "host": host,
        "port": ssh_result.get("port") or port,
        "user": user,
        "status": status,
        "platform_key": ssh_result.get("platform_key") or platform_key,
        "result": ssh_result,
    }
