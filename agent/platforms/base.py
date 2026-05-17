from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CommandSpec:
    intent: str
    command: str
    notes: str = ""


@dataclass(frozen=True)
class PlatformProfile:
    key: str
    label: str
    family: str
    detection_hints: tuple[str, ...] = ()
    safe_commands: dict[str, CommandSpec] = field(default_factory=dict)

    def supports_intent(self, intent: str) -> bool:
        return intent in self.safe_commands

    def get_command(self, intent: str) -> CommandSpec | None:
        return self.safe_commands.get(intent)
