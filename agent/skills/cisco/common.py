def normalize_interface_name(name: str | None) -> str:
    if not name:
        return ""
    normalized = str(name).strip().lower().replace(" ", "")
    replacements = {
        "gigabitethernet": "gi",
        "tengigabitethernet": "te",
        "fastethernet": "fa",
        "ethernet": "eth",
        "port-channel": "po",
    }
    for source, target in replacements.items():
        if normalized.startswith(source):
            normalized = target + normalized[len(source) :]
            break
    return normalized


def filter_by_interface(entries: list[dict], *keys: str, interface_name: str) -> list[dict]:
    wanted = normalize_interface_name(interface_name)
    matches = []
    for entry in entries:
        for key in keys:
            if normalize_interface_name(entry.get(key)) == wanted:
                matches.append(entry)
                break
    return matches
