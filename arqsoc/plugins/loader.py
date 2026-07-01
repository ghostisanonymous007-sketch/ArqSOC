"""Plugin loader for ArqSOC - dynamically load and manage analysis plugins."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class PluginBase:
    name: str = "unknown"
    description: str = ""
    version: str = "0.1.0"

    def run(self, target: Path, **kwargs: object) -> dict[str, object]:
        raise NotImplementedError


PLUGIN_REGISTRY: dict[str, type[PluginBase]] = {}


def register_plugin(name: str, cls: type[PluginBase] | None = None) -> None:
    def decorator(cls_inner: type[PluginBase]) -> type[PluginBase]:
        PLUGIN_REGISTRY[name] = cls_inner
        cls_inner.name = name
        return cls_inner

    if cls is not None:
        return decorator(cls)
    return decorator


def discover_plugins(plugin_dir: Path | None = None) -> list[str]:
    if plugin_dir is None:
        plugin_dir = Path.home() / ".arqsoc" / "plugins"

    if not plugin_dir.exists():
        return []

    discovered: list[str] = []
    for py_file in plugin_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        module_name = f"arqsoc_plugins.{py_file.stem}"
        if module_name not in sys.modules:
            try:
                spec = importlib.util.spec_from_file_location(module_name, str(py_file))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = mod
                    spec.loader.exec_module(mod)
                discovered.append(py_file.stem)
            except Exception:
                pass

    return discovered


def load_plugin(name: str) -> PluginBase | None:
    if name in PLUGIN_REGISTRY:
        cls = PLUGIN_REGISTRY[name]
        return cls()
    return None


def list_plugins() -> list[dict[str, str]]:
    return [
        {"name": name, "description": getattr(cls, "description", ""), "version": getattr(cls, "version", "0.1.0")}
        for name, cls in sorted(PLUGIN_REGISTRY.items())
    ]


def run_plugin(name: str, target: Path, **kwargs: object) -> dict[str, object] | None:
    plugin = load_plugin(name)
    if plugin is None:
        return None
    return plugin.run(target, **kwargs)
