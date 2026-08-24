"""Raw HTTP transport for the conformance probe.

Every request is built by hand. `docs/HANDOFF.md` §9.4: an SDK "would paper over
exactly the deviations you are trying to detect — an SDK that helpfully adds
`Mcp-Method` makes the rule 'requires `Mcp-Method`' untestable."

So this module offers no conveniences. It sends the bytes it is given, with the
headers it is given, and returns what came back without interpreting it. Rules
that need to send something malformed — absent `_meta`, a mismatched header, a
forged `requestState` — can, because nothing here will correct them.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

#: Default per-request timeout. A hung target must not hang the scan (§9.4).
DEFAULT_TIMEOUT = 10.0

#: "The client MUST include an Accept header listing both application/json and
#: text/event-stream as supported content types."
ACCEPT_VALUE = "application/json, text/event-stream"


@dataclass(slots=True)
class RawResponse:
    """What came back, uninterpreted."""

    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_s: float
    #: Set when the request never completed. Rules distinguish "the server
    #: refused" from "the server was unreachable"; conflating them turns an
    #: outage into a conformance failure.
    transport_error: str | None = None

    @property
    def reached_server(self) -> bool:
        return self.transport_error is None

    def json(self) -> Any:
        """Parse the body, or raise. Rules call `.envelope()` instead."""
        return json.loads(self.body)

    def envelope(self) -> dict[str, Any] | None:
        """The JSON-RPC envelope, or None if the body was not a JSON object.

        A server that returns something unparseable has failed whatever rule
        called this; returning None lets the rule say so rather than crashing
        the whole scan.
        """
        try:
            parsed = json.loads(self.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    def result(self) -> dict[str, Any] | None:
        env = self.envelope()
        if env is None:
            return None
        result = env.get("result")
        return result if isinstance(result, dict) else None

    def error(self) -> dict[str, Any] | None:
        env = self.envelope()
        if env is None:
            return None
        err = env.get("error")
        return err if isinstance(err, dict) else None

    def error_code(self) -> int | None:
        err = self.error()
        if err is None:
            return None
        code = err.get("code")
        return code if isinstance(code, int) else None


@dataclass(slots=True)
class Request:
    """A request, exactly as it will be sent.

    Nothing is defaulted in that a conformant client would have to supply.
    `method` does not populate the `Mcp-Method` header, `params` does not gain a
    `_meta`, and an omitted field stays omitted. Building a *correct* request is
    `probe.client`'s job; this type's job is to send whatever it is handed.
    """

    method: str
    params: dict[str, Any] | None = None
    request_id: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    #: Overrides the whole body, for rules that need to send something a dict
    #: cannot express — malformed JSON, a missing `jsonrpc`, a duplicate key.
    raw_body: bytes | None = None

    def body(self) -> bytes:
        if self.raw_body is not None:
            return self.raw_body
        envelope: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self.request_id if self.request_id is not None else str(uuid.uuid4()),
            "method": self.method,
        }
        if self.params is not None:
            envelope["params"] = self.params
        return json.dumps(envelope).encode()


class Transport:
    """Sends requests to one endpoint."""

    def __init__(
        self,
        endpoint: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        bearer_token: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.bearer_token = bearer_token
        self._client = httpx.Client(timeout=timeout, follow_redirects=False)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Transport:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def send(self, request: Request) -> RawResponse:
        headers = {
            "Content-Type": "application/json",
            "Accept": ACCEPT_VALUE,
            **request.headers,
        }
        if self.bearer_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        started = time.perf_counter()
        try:
            resp = self._client.post(self.endpoint, content=request.body(), headers=headers)
        except httpx.RequestError as exc:
            return RawResponse(
                status=0,
                headers={},
                body=b"",
                elapsed_s=time.perf_counter() - started,
                transport_error=f"{type(exc).__name__}: {exc}",
            )

        return RawResponse(
            status=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            body=resp.content,
            elapsed_s=time.perf_counter() - started,
        )
