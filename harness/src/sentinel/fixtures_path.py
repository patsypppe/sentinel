"""Where the practice servers live: bundled in the wheel, or the repo checkout."""

from __future__ import annotations

import pathlib

_PACKAGE = pathlib.Path(__file__).resolve().parent / "_fixtures"
_CHECKOUT = pathlib.Path(__file__).resolve().parents[3] / "fixtures"


def fixtures_dir() -> pathlib.Path:
    return _PACKAGE if (_PACKAGE / "server").is_dir() else _CHECKOUT
