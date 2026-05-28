import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
PACKAGE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")
load_dotenv(PACKAGE_DIR / ".env")

KNOWN_HOSTS_FILE = Path(
    os.getenv("NETADMIN_KNOWN_HOSTS_FILE", BASE_DIR / "known_hosts.json")
).expanduser()

PROVIDER = os.getenv("NETADMIN_PROVIDER", "openai").strip().lower()
DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash",
    "openai": "gpt-4.1-mini",
}
MODEL = os.getenv("NETADMIN_MODEL", DEFAULT_MODELS.get(PROVIDER, DEFAULT_MODELS["gemini"]))
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MASSCAN_BINARY = os.getenv("NETADMIN_MASSCAN_BIN", "masscan")
NMAP_BINARY = os.getenv("NETADMIN_NMAP_BIN", "nmap")
DEFAULT_NETWORK_SCANNER = os.getenv("NETADMIN_DEFAULT_SCANNER", "nmap").strip().lower()
SSH_BINARY = os.getenv("NETADMIN_SSH_BIN", "ssh")
SSH_PORT = int(os.getenv("NETADMIN_SSH_PORT", "22"))
SSH_CONNECT_TIMEOUT = int(os.getenv("NETADMIN_SSH_CONNECT_TIMEOUT", "8"))
SSH_COMMAND_TIMEOUT = int(os.getenv("NETADMIN_SSH_COMMAND_TIMEOUT", "20"))
ALLOW_SUDO = os.getenv("NETADMIN_ALLOW_SUDO", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DEFAULT_SCAN_RATE = int(os.getenv("NETADMIN_SCAN_RATE", "1000"))


def require_gemini_api_key() -> str:
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is missing")
    return GEMINI_API_KEY


def require_openai_api_key() -> str:
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY is missing")
    return OPENAI_API_KEY
