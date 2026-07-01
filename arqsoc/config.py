"""Configuration and API key management for ArqSOC."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

CONFIG_DIR = Path.home() / ".arqsoc"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS: dict[str, str] = {}


def _ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _restrict_config_file(path: Path) -> None:
    try:
        os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def load_config() -> dict[str, str]:
    _ensure_config_dir()
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except Exception:
            pass
    return dict(DEFAULTS)


def save_config(config: dict[str, str]) -> None:
    _ensure_config_dir()
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    _restrict_config_file(CONFIG_FILE)


def get_api_key(service: str) -> str | None:
    env_map = {
        "vt": "ARQSOC_VT_API_KEY",
        "abuseipdb": "ARQSOC_ABUSEIPDB_KEY",
        "shodan": "ARQSOC_SHODAN_KEY",
    }
    env_var = env_map.get(service, f"ARQSOC_{service.upper()}_KEY")
    env_val = os.environ.get(env_var)
    if env_val:
        return env_val

    config = load_config()
    key_name = f"{service}_api_key"
    return config.get(key_name)


def set_api_key(service: str, key: str) -> None:
    config = load_config()
    config[f"{service}_api_key"] = key
    save_config(config)


def delete_api_key(service: str) -> None:
    config = load_config()
    config.pop(f"{service}_api_key", None)
    save_config(config)


def list_api_keys() -> dict[str, bool]:
    config = load_config()
    return {k.replace("_api_key", ""): bool(v) for k, v in config.items() if k.endswith("_api_key")}
