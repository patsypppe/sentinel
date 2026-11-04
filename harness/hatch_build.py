"""Bundle the practice servers (`fixtures/server`) into both the sdist and the wheel.

They live at the repository root, outside this package's directory, so a static
force-include works from a checkout but not when the wheel is built from the sdist,
which is how PyPI releases are built. This hook finds them in either layout.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):  # type: ignore[type-arg]
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root)
        for source in (root.parent / "fixtures" / "server", root / "fixtures" / "server"):
            if source.is_dir():
                target = (
                    "toolgauge/_fixtures/server"
                    if self.target_name == "wheel"
                    else "fixtures/server"
                )
                build_data["force_include"][str(source)] = target
                return
        raise FileNotFoundError("the practice servers (fixtures/server) were not found")
