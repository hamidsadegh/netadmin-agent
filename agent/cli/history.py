import atexit
from pathlib import Path

try:
    import readline
except ImportError:  # pragma: no cover
    readline = None


HISTORY_FILE = Path(__file__).resolve().parents[2] / ".netadmin_history"
HISTORY_LENGTH = 500


def get_history_file() -> Path:
    return HISTORY_FILE


def save_interactive_history() -> None:
    if readline is None:
        return

    history_file = get_history_file()
    try:
        history_file.parent.mkdir(parents=True, exist_ok=True)
        readline.write_history_file(str(history_file))
    except Exception:
        return


def setup_interactive_history(completer=None) -> bool:
    if readline is None:
        return False

    history_file = get_history_file()
    try:
        history_file.parent.mkdir(parents=True, exist_ok=True)
        if history_file.exists():
            readline.read_history_file(str(history_file))
        readline.set_history_length(HISTORY_LENGTH)
        if completer is not None:
            readline.set_completer(completer)
            readline.parse_and_bind("tab: complete")
        atexit.register(save_interactive_history)
        return True
    except Exception:
        return False
