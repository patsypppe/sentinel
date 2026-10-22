"""A conformant server whose gray-box behaviours can each be broken independently.

The conformant fixture proves the PASS branches of the rules a scanner can settle
alone. The five UNVERIFIABLE rules can only be settled with evidence, so settling
them needs a server that can be made to misbehave in exactly the way each evidence
kind is meant to catch, and a way for the evidence commands to read what happened.

Each knob is one defect:

    validates_audience   False -> accepts a token issued for another audience
    distinct_refusals    False -> refuses a wrong audience exactly like garbage
    binds_handles        False -> serves a handle to a principal that did not mint it
    forwards_token       True  -> sends the caller's token to its "downstream"
    idempotent           False -> a duplicate retry performs the effect again
    audits               False -> records no audit row for an invocation

State is per instance, so two servers in one process never share a counter.
"""

from __future__ import annotations

import itertools
from typing import Any

from . import conformant
from .common import error, parse, result

TOKENS = {"principal-a": "a", "principal-b": "b"}
WRONG_AUDIENCE = "wrong-aud"

EXTRA_TOOLS: list[dict[str, Any]] = [
    {
        "name": "data.make-handle",
        "description": "Mint a handle for the caller.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "data.read-handle",
        "description": "Read through a handle.",
        "inputSchema": {"type": "object", "properties": {"handle": {"type": "string"}}},
    },
    {
        "name": "data.proxy-call",
        "description": "Call a downstream service on the caller's behalf.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ops.apply",
        "description": "Apply a change after approval.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "audit.touch",
        "description": "A read-only tool that is audited.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class GrayboxServer:
    def __init__(
        self,
        *,
        validates_audience: bool = True,
        distinct_refusals: bool = True,
        binds_handles: bool = True,
        forwards_token: bool = False,
        idempotent: bool = True,
        audits: bool = True,
    ) -> None:
        self.validates_audience = validates_audience
        self.distinct_refusals = distinct_refusals
        self.binds_handles = binds_handles
        self.forwards_token = forwards_token
        self.idempotent = idempotent
        self.audits = audits
        self.effects = 0
        self.audit_rows = 0
        self.egress: list[str] = []
        self._handles: dict[str, str] = {}
        self._handle_ids = itertools.count(1)
        self._state_ids = itertools.count(1)
        self._consumed: dict[str, dict[str, Any]] = {}

    # ----------------------------------------------------------- introspection

    def introspect(self, path: str) -> str | None:
        if path == "/_effects":
            return f"{self.effects}\n"
        if path == "/_audit":
            return f"{self.audit_rows}\n"
        if path == "/_egress":
            return "\n".join(self.egress) + ("\n" if self.egress else "")
        return None

    # -------------------------------------------------------------------- auth

    def _principal(self, handler: Any) -> tuple[str | None, tuple[int, dict[str, Any]] | None]:
        header = handler.headers.get("Authorization")
        if header is None:
            return "anonymous", None
        token = header.removeprefix("Bearer ").strip()
        if token in TOKENS:
            return TOKENS[token], None
        if token == WRONG_AUDIENCE:
            if not self.validates_audience:
                return "wrong-audience", None
            why = "audience mismatch" if self.distinct_refusals else "signature invalid"
            return None, self._refuse(why)
        return None, self._refuse("signature invalid")

    @staticmethod
    def _refuse(why: str) -> tuple[int, dict[str, Any]]:
        return 401, error(None, -32001, f"invalid_token: {why}")

    # ------------------------------------------------------------------- state

    def _seal(self) -> str:
        """A requestState unique to one flow, so two flows never share a record."""
        nonce = f"{next(self._state_ids):06d}"
        return f"{nonce}.{conformant.seal_state('ops.apply:' + nonce)}"

    @staticmethod
    def _state_is_valid(state: object) -> bool:
        if not isinstance(state, str) or "." not in state:
            return False
        nonce = state.split(".", 1)[0]
        return state == f"{nonce}.{conformant.seal_state('ops.apply:' + nonce)}"

    # ---------------------------------------------------------------- dispatch

    def dispatch(self, handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
        principal, refusal = self._principal(handler)
        if refusal is not None:
            return refusal
        assert principal is not None
        payload = parse(body) or {}
        method = payload.get("method")
        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
        name = params.get("name")

        if method == "tools/call" and name in {t["name"] for t in EXTRA_TOOLS}:
            return 200, self._call(payload.get("id"), name, params, handler, principal)

        status, reply = conformant.dispatch(handler, body)
        if method == "tools/list" and reply is not None and isinstance(reply.get("result"), dict):
            reply["result"]["tools"] = [*reply["result"]["tools"], *EXTRA_TOOLS]
        return status, reply

    def _envelope(self, request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
        return result(request_id, conformant.enveloped(payload, conformant.PROTOCOL))

    def _call(
        self, request_id: Any, name: str, params: dict[str, Any], handler: Any, principal: str
    ) -> dict[str, Any]:
        arguments = params.get("arguments")
        arguments = arguments if isinstance(arguments, dict) else {}

        if name == "audit.touch":
            if self.audits:
                self.audit_rows += 1
            return self._envelope(request_id, {"content": [{"type": "text", "text": "touched"}]})

        if name == "data.make-handle":
            handle = f"h-{next(self._handle_ids)}"
            self._handles[handle] = principal
            if self.audits:
                self.audit_rows += 1
            return self._envelope(
                request_id,
                {"content": [], "structuredContent": {"handle": handle}},
            )

        if name == "data.read-handle":
            handle = arguments.get("handle")
            owner = self._handles.get(str(handle))
            if owner is None or (self.binds_handles and owner != principal):
                # One answer for "does not exist" and "not yours", so the handle
                # space is not an enumeration oracle.
                return error(request_id, -32602, "unknown handle")
            return self._envelope(request_id, {"content": [{"type": "text", "text": "contents"}]})

        if name == "data.proxy-call":
            header = handler.headers.get("Authorization", "")
            forwarded = header if self.forwards_token else "Bearer svc-credential"
            self.egress.append(f"GET https://downstream.internal/data  Authorization: {forwarded}")
            return self._envelope(request_id, {"content": [{"type": "text", "text": "ok"}]})

        return self._apply(request_id, params)

    def _apply(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        state = params.get("requestState")
        if state is not None:
            if not self._state_is_valid(state):
                return error(request_id, -32602, "requestState is not valid")
            recorded = self._consumed.get(str(state)) if self.idempotent else None
            if recorded is not None:
                return recorded
            self.effects += 1
            reply = self._envelope(request_id, {"content": [{"type": "text", "text": "applied"}]})
            if self.idempotent:
                self._consumed[str(state)] = reply
            return reply
        capabilities = conformant.declared_meta({"params": params}).get(
            conformant.KEY_CLIENT_CAPABILITIES
        )
        if isinstance(capabilities, dict) and "elicitation" in capabilities:
            return self._envelope(
                request_id,
                {
                    "resultType": "input_required",
                    "inputRequests": [
                        {"name": "approve", "kind": "elicitation", "prompt": "Apply?"}
                    ],
                    "requestState": self._seal(),
                },
            )
        return self._envelope(request_id, {"content": [{"type": "text", "text": "not applied"}]})
