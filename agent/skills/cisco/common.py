INTERFACE_PREFIXES = (
    ("fourhundredgigabitethernet", "fh", "Fh"),
    ("fourhundredgige", "fh", "Fh"),
    ("twohundredgigabitethernet", "th", "Th"),
    ("twohundredgige", "th", "Th"),
    ("hundredgigabitethernet", "hu", "Hu"),
    ("hundredgige", "hu", "Hu"),
    ("twentyfivegigabitethernet", "tw", "Tw"),
    ("twentyfivegige", "tw", "Tw"),
    ("fortygigabitethernet", "fo", "Fo"),
    ("fortygige", "fo", "Fo"),
    ("tengigabitethernet", "te", "Te"),
    ("tengige", "te", "Te"),
    ("gigabitethernet", "gi", "Gi"),
    ("fastethernet", "fa", "Fa"),
    ("ethernet", "eth", "Eth"),
    ("port-channel", "po", "Po"),
    ("portchannel", "po", "Po"),
    ("loopback", "lo", "Lo"),
    ("vlan", "vl", "Vl"),
)


def normalize_interface_name(name: str | None) -> str:
    if not name:
        return ""
    normalized = str(name).strip().lower().replace(" ", "")
    for source, target, _display in INTERFACE_PREFIXES:
        if normalized.startswith(source):
            normalized = target + normalized[len(source) :]
            break
    return normalized


def display_interface_name(name: str | None) -> str:
    if not name:
        return ""
    compact = str(name).strip().replace(" ", "")
    lowered = compact.lower()
    for source, _target, display in INTERFACE_PREFIXES:
        if lowered.startswith(source):
            return display + compact[len(source) :]

    normalized = normalize_interface_name(compact)
    short_prefixes = {target: display for _source, target, display in INTERFACE_PREFIXES}
    for target, display in sorted(short_prefixes.items(), key=lambda item: len(item[0]), reverse=True):
        if normalized.startswith(target):
            return display + normalized[len(target) :]
    return compact


def filter_by_interface(entries: list[dict], *keys: str, interface_name: str) -> list[dict]:
    wanted = normalize_interface_name(interface_name)
    matches = []
    for entry in entries:
        for key in keys:
            if normalize_interface_name(entry.get(key)) == wanted:
                matches.append(entry)
                break
    return matches
