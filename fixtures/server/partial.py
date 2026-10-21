"""A correct server that implements almost nothing.

The third oracle. The conformant fixture exercises every rule's PASS branch and the
non-conformant one exercises every FAIL branch, but neither visits `NOT_APPLICABLE`,
and a rule whose not-applicable branch has never run has never had it checked. This
server declares no capabilities and serves no tools, resources, prompts or
multi round-trip flows, so every rule that constrains one of those has to say
"nothing to check" rather than pass or fail.

It reuses the conformant fixture for everything it does serve -- the header
contract, `_meta` validation, negotiation -- and only empties what it advertises.
"""

from __future__ import annotations

import sys
from typing import Any

from . import conformant
from .common import serve_forever

PORT = 9002

BEHAVIOUR: dict[str, Any] = dict(conformant.BEHAVIOUR)


def dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    status, payload = conformant.dispatch(handler, body)
    if payload is not None and isinstance(payload.get("result"), dict):
        body_result = payload["result"]
        if "capabilities" in body_result:
            body_result["capabilities"] = {}
        if "tools" in body_result:
            body_result["tools"] = []
    return status, payload


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    serve_forever(dispatch, port, banner="partial fixture", **BEHAVIOUR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
