from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
WORKSPACE_ROOT = ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from agent.skills import run_remote_ssh_diagnostic
from agent.tools import connect_ssh_session, run_command_on_ssh_session
from simulators.cisco_ssh_simulator import SimulatorServer


DEFAULT_REQUESTS = {
    "ios": [
        {"command": "show interfaces status"},
        {"request": "show neighbors"},
        {"request": "show vlans"},
    ],
    "iosxe": [
        {"command": "show interfaces status"},
        {"request": "show neighbors"},
        {"request": "show logs"},
    ],
    "nxos": [
        {"command": "show interface brief"},
        {"request": "show port-channel summary"},
        {"request": "show vpc"},
    ],
}


def run_demo(platform: str) -> dict:
    server = SimulatorServer(platform=platform, port=0).start()
    session = None
    try:
        session = connect_ssh_session(
            host="127.0.0.1",
            port=server.port,
            user=server.username,
            password=server.password,
        )
        if not session.get("success"):
            return {
                "ok": False,
                "platform": platform,
                "error": session.get("error"),
            }

        checks = []
        for item in DEFAULT_REQUESTS[platform]:
            result = run_command_on_ssh_session(
                session["client"],
                host="127.0.0.1",
                port=server.port,
                user=server.username,
                command=item.get("command"),
                request=item.get("request"),
                platform_key=session.get("platform_key"),
            )
            checks.append(
                {
                    "command": result.get("command"),
                    "success": result.get("success"),
                    "summary": result.get("summary"),
                }
            )

        one_shot = run_remote_ssh_diagnostic(
            host="127.0.0.1",
            port=server.port,
            user=server.username,
            password=server.password,
            request="what interfaces do you have",
            platform_key=session.get("platform_key"),
        )

        return {
            "ok": True,
            "platform": platform,
            "simulator_port": server.port,
            "detected_platform": session.get("platform_key"),
            "session_mode": session.get("session_mode"),
            "prepared": session.get("prepared"),
            "checks": checks,
            "one_shot": {
                "status": one_shot.get("status"),
                "command": (one_shot.get("result") or {}).get("command"),
                "summary": (one_shot.get("result") or {}).get("summary"),
            },
        }
    finally:
        if session and session.get("client"):
            session["client"].close()
        server.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the NetAdmin agent against the fake Cisco simulator")
    parser.add_argument("--platform", choices=["ios", "iosxe", "nxos"], default="ios")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = run_demo(args.platform)
    if args.pretty:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
