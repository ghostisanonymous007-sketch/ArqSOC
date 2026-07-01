"""Tests for config module."""

from __future__ import annotations

import pytest
from pathlib import Path

from arqsoc.config import load_config, save_config, get_api_key, set_api_key, delete_api_key, list_api_keys


def test_load_config_default(temp_config: Path) -> None:
    config = load_config()
    assert isinstance(config, dict)


def test_save_and_load_config(temp_config: Path) -> None:
    save_config({"vt_api_key": "test_key_123"})
    config = load_config()
    assert config.get("vt_api_key") == "test_key_123"


def test_set_and_get_api_key(temp_config: Path) -> None:
    set_api_key("vt", "test_vt_key")
    result = get_api_key("vt")
    assert result == "test_vt_key"


def test_delete_api_key(temp_config: Path) -> None:
    set_api_key("vt", "to_delete")
    delete_api_key("vt")
    result = get_api_key("vt")
    assert result is None


def test_list_api_keys(temp_config: Path) -> None:
    set_api_key("vt", "key1")
    set_api_key("abuseipdb", "key2")
    keys = list_api_keys()
    assert "vt" in keys
    assert "abuseipdb" in keys
    assert keys["vt"] is True


def test_get_api_key_env_override(temp_config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARQSOC_VT_API_KEY", "env_key")
    result = get_api_key("vt")
    assert result == "env_key"


def test_get_api_key_nonexistent(temp_config: Path) -> None:
    result = get_api_key("nonexistent_service")
    assert result is None
