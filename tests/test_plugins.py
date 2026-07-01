"""Tests for plugin loader module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.plugins.loader import (
    PluginBase,
    register_plugin,
    load_plugin,
    list_plugins,
    run_plugin,
    PLUGIN_REGISTRY,
)


class MockPlugin(PluginBase):
    name = "mock"
    description = "Mock plugin for testing"
    version = "0.1.0"

    def run(self, target: Path, **kwargs: object) -> dict[str, object]:
        return {"target": str(target), "status": "ok"}


def test_register_and_load_plugin() -> None:
    old_count = len(PLUGIN_REGISTRY)
    register_plugin("mock_test", MockPlugin)

    assert "mock_test" in PLUGIN_REGISTRY
    plugin = load_plugin("mock_test")
    assert plugin is not None
    assert isinstance(plugin, MockPlugin)

    if "mock_test" in PLUGIN_REGISTRY:
        del PLUGIN_REGISTRY["mock_test"]


def test_list_plugins() -> None:
    register_plugin("list_test", MockPlugin)
    plugins = list_plugins()
    assert any(p["name"] == "list_test" for p in plugins)

    if "list_test" in PLUGIN_REGISTRY:
        del PLUGIN_REGISTRY["list_test"]


def test_run_plugin() -> None:
    register_plugin("run_test", MockPlugin)
    result = run_plugin("run_test", Path("/tmp/test"))
    assert result is not None
    assert result["status"] == "ok"

    if "run_test" in PLUGIN_REGISTRY:
        del PLUGIN_REGISTRY["run_test"]


def test_load_nonexistent_plugin() -> None:
    plugin = load_plugin("nonexistent_plugin_xyz")
    assert plugin is None


def test_run_nonexistent_plugin() -> None:
    result = run_plugin("nonexistent_plugin_xyz", Path("/tmp/test"))
    assert result is None
