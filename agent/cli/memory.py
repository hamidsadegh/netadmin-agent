from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any


MAX_RECENT_TURNS = 10
LONG_TERM_MEMORY_FILE = Path(__file__).resolve().parents[2] / ".netadmin_memory.json"
REMEMBER_DEVICE_RE = re.compile(r"^remember\s+(?:this\s+device|device)\s+as\s+(.+)$", re.IGNORECASE)
REMEMBER_SUBNET_RE = re.compile(
    r"^remember\s+(?:subnet\s+)?((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})\s+as\s+(.+)$",
    re.IGNORECASE,
)
REMEMBER_PREFERENCE_RE = re.compile(r"^remember\s+preference\s+([a-zA-Z0-9_.-]+)\s+as\s+(.+)$", re.IGNORECASE)


@dataclass
class SessionMemory:
    last_device: dict[str, Any] | None = None
    last_scan: dict[str, Any] | None = None
    last_interface: str | None = None
    last_mac: str | None = None
    last_vlan: str | None = None
    last_command: str | None = None
    last_result_summary: str | None = None
    recent_turns: deque[dict[str, str]] = field(default_factory=lambda: deque(maxlen=MAX_RECENT_TURNS))

    def remember_turn(self, user_input: str, result_summary: str | None = None) -> None:
        self.recent_turns.append(
            {
                "user": str(user_input).strip(),
                "summary": str(result_summary or "").strip(),
            }
        )
        if result_summary:
            self.last_result_summary = str(result_summary).strip()

    def remember_device(self, session: dict | None) -> None:
        if not session:
            return
        self.last_device = {
            "host": session.get("host"),
            "port": session.get("port") or 22,
            "user": session.get("user"),
            "platform_key": session.get("platform_key"),
            "session_mode": session.get("session_mode"),
        }

    def remember_scan(self, scan_result: dict | None) -> None:
        if scan_result:
            self.last_scan = scan_result

    def remember_command(self, command: str | None) -> None:
        if command:
            self.last_command = str(command).strip()

    def remember_result_summary(self, summary: str | None) -> None:
        if summary:
            self.last_result_summary = str(summary).strip()

    def remember_from_text(self, text: str, *, interface_pattern=None, mac_pattern=None, vlan_pattern=None) -> None:
        if interface_pattern:
            match = interface_pattern.search(text)
            if match:
                self.last_interface = match.group(0)
        if mac_pattern:
            match = mac_pattern.search(text)
            if match:
                self.last_mac = match.group(0)
        if vlan_pattern:
            match = vlan_pattern.search(text)
            if match:
                self.last_vlan = match.group(1)

    def remember_from_result(self, result: dict | None) -> None:
        if not isinstance(result, dict):
            return
        if result.get("interface"):
            self.last_interface = str(result.get("interface"))
        if result.get("mac"):
            self.last_mac = str(result.get("mac"))
        if result.get("vlan_id"):
            self.last_vlan = str(result.get("vlan_id"))
        if result.get("skill") == "discover_network_hosts":
            self.remember_scan(result)

        ssh_result = result.get("result") or {}
        if isinstance(ssh_result, dict):
            self.remember_command(ssh_result.get("command"))
            self.remember_result_summary(ssh_result.get("summary"))
        self.remember_result_summary(result.get("summary"))


def format_session_memory(memory: SessionMemory) -> str:
    lines = ["Session Memory"]
    device = memory.last_device or {}
    if device:
        lines.extend(
            [
                "",
                "Device:",
                f"- {device.get('user')}@{device.get('host')}:{device.get('port')}",
                f"- Platform: {device.get('platform_key') or 'unknown'}",
            ]
        )
    lines.extend(
        [
            "",
            "Remembered:",
            f"- Interface: {memory.last_interface or 'none'}",
            f"- MAC: {memory.last_mac or 'none'}",
            f"- VLAN: {memory.last_vlan or 'none'}",
            f"- Last command: {memory.last_command or 'none'}",
            f"- Last scan: {(memory.last_scan or {}).get('cidr') or 'none'}",
        ]
    )
    if memory.last_result_summary:
        lines.extend(["", "Last Result:", memory.last_result_summary])
    if memory.recent_turns:
        lines.append("")
        lines.append("Recent:")
        for turn in list(memory.recent_turns)[-5:]:
            summary = f" -> {turn['summary']}" if turn.get("summary") else ""
            lines.append(f"- {turn.get('user')}{summary}")
    return "\n".join(lines)


def format_last_result(memory: SessionMemory) -> str:
    if not memory.last_result_summary:
        return "No last result in memory yet."
    return f"Last Result:\n{memory.last_result_summary}"


def is_memory_request(user_input: str) -> bool:
    lowered = user_input.strip().lower()
    return lowered in {"memory", "show memory", "session memory", "what do you remember"}


def is_last_result_request(user_input: str) -> bool:
    lowered = user_input.strip().lower()
    return lowered in {"last result", "show last result", "show last answer", "repeat last result"}


def refers_to_last_interface(user_input: str) -> bool:
    lowered = user_input.lower()
    return any(phrase in lowered for phrase in ("same interface", "same int", "that interface", "this interface", "it"))


def _empty_long_term_memory() -> dict[str, Any]:
    return {"version": 1, "devices": {}, "subnets": {}, "preferences": {}}


def load_long_term_memory(path: Path = LONG_TERM_MEMORY_FILE) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_long_term_memory()
    if not isinstance(data, dict):
        return _empty_long_term_memory()
    memory = _empty_long_term_memory()
    for key in ("devices", "subnets", "preferences"):
        if isinstance(data.get(key), dict):
            memory[key] = data[key]
    return memory


def save_long_term_memory(memory: dict[str, Any], path: Path = LONG_TERM_MEMORY_FILE) -> None:
    safe_memory = _empty_long_term_memory()
    for key in ("devices", "subnets", "preferences"):
        if isinstance(memory.get(key), dict):
            safe_memory[key] = memory[key]
    path.write_text(json.dumps(safe_memory, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _clean_label(label: str) -> str:
    return " ".join(str(label).strip().split())[:80]


def is_long_term_memory_request(user_input: str) -> bool:
    lowered = user_input.strip().lower()
    return lowered in {
        "show remembered",
        "show remembered devices",
        "show long term memory",
        "long term memory",
        "remembered devices",
    }


def parse_remember_command(user_input: str) -> dict[str, str] | None:
    text = user_input.strip()
    device_match = REMEMBER_DEVICE_RE.match(text)
    if device_match:
        return {"kind": "device", "label": _clean_label(device_match.group(1))}
    subnet_match = REMEMBER_SUBNET_RE.match(text)
    if subnet_match:
        return {"kind": "subnet", "cidr": subnet_match.group(1), "label": _clean_label(subnet_match.group(2))}
    preference_match = REMEMBER_PREFERENCE_RE.match(text)
    if preference_match:
        return {
            "kind": "preference",
            "key": _clean_label(preference_match.group(1)),
            "value": _clean_label(preference_match.group(2)),
        }
    return None


def apply_remember_command(command: dict[str, str], session: dict | None, memory: dict[str, Any]) -> str:
    kind = command.get("kind")
    if kind == "device":
        if not session:
            return "No active SSH session. Connect to a device first, then use: remember this device as <name>."
        host = str(session.get("host") or "")
        if not host:
            return "No active device host is available to remember."
        memory.setdefault("devices", {})[host] = {
            "label": command.get("label"),
            "host": host,
            "port": session.get("port") or 22,
            "user": session.get("user"),
            "platform_key": session.get("platform_key"),
        }
        save_long_term_memory(memory)
        return f"Remembered device {host} as {command.get('label')}."

    if kind == "subnet":
        cidr = command.get("cidr")
        memory.setdefault("subnets", {})[cidr] = {"label": command.get("label"), "cidr": cidr}
        save_long_term_memory(memory)
        return f"Remembered subnet {cidr} as {command.get('label')}."

    if kind == "preference":
        key = command.get("key")
        memory.setdefault("preferences", {})[key] = command.get("value")
        save_long_term_memory(memory)
        return f"Remembered preference {key}."

    return "I could not understand what to remember."


def format_long_term_memory(memory: dict[str, Any]) -> str:
    lines = ["Long-Term Memory"]
    devices = memory.get("devices") or {}
    subnets = memory.get("subnets") or {}
    preferences = memory.get("preferences") or {}

    lines.extend(["", "Devices:"])
    if devices:
        for host, info in sorted(devices.items()):
            lines.append(
                f"- {info.get('label') or 'unnamed'}: {host}:{info.get('port') or 22} "
                f"{info.get('platform_key') or 'unknown'} user={info.get('user') or 'unknown'}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "Subnets:"])
    if subnets:
        for cidr, info in sorted(subnets.items()):
            lines.append(f"- {info.get('label') or 'unnamed'}: {cidr}")
    else:
        lines.append("- none")

    lines.extend(["", "Preferences:"])
    if preferences:
        for key, value in sorted(preferences.items()):
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- none")
    return "\n".join(lines)


def recall_long_term_context(memory: dict[str, Any], session: dict | None = None) -> str | None:
    if not session:
        return None
    host = session.get("host")
    device = (memory.get("devices") or {}).get(host)
    if not device:
        return None
    label = device.get("label")
    if not label:
        return None
    return f"Remembered device: {label}"
