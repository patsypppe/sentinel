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

import contextlib
import http.client
import json
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx

#: Default per-request timeout. A hung target must not hang the scan (§9.4).
DEFAULT_TIMEOUT = 10.0

#: "The client MUST include an Accept header listing both application/json and
#: text/event-stream as supported content types."
ACCEPT_VALUE = "application/json, text/event-stream"

#: How many times a request that never reached the server is retried. A scan is
#: long and a single dropped connection should not turn a conformant rule into
#: an INDETERMINATE.
DEFAULT_RETRIES = 2

#: Backoff between attempts: BACKOFF_BASE_S * 2**attempt.
BACKOFF_BASE_S = 0.1

#: Sent on every request, so the operator of a scanned server can see what is
#: talking to it and where to read about it. Overridable, never omitted.
DEFAULT_USER_AGENT = "sentinel-mcp-conformance (+https://github.com/patsypppe/sentinel)"


def sse_messages(body: bytes) -> list[Any]:
    """The JSON payloads of every event in a text/event-stream body.

    A server may answer a POST with `Content-Type: text/event-stream` and carry
    the JSON-RPC response as an SSE event. Reading only bare JSON would score
    every such reply as "no JSON-RPC response", which is a scanner bug wearing
    the costume of a server defect. Events are split on blank lines, their
    `data:` lines joined with newlines as the SSE format specifies, and an event
    whose data is not JSON is skipped rather than guessed at.
    """
    try:
        text = body.decode()
    except UnicodeDecodeError:
        return []
    messages: list[Any] = []
    data: list[str] = []
    for line in [*text.replace("\r\n", "\n").split("\n"), ""]:
        if line == "":
            if data:
                with contextlib.suppress(json.JSONDecodeError):
                    messages.append(json.loads("\n".join(data)))
                data = []
            continue
        if line.startswith("data:"):
            value = line[len("data:") :]
            data.append(value[1:] if value.startswith(" ") else value)
    return messages


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

    @property
    def is_event_stream(self) -> bool:
        return "text/event-stream" in self.headers.get("content-type", "")

    def envelope(self) -> dict[str, Any] | None:
        """The JSON-RPC envelope, or None if the body was not a JSON object.

        A server that returns something unparseable has failed whatever rule
        called this; returning None lets the rule say so rather than crashing
        the whole scan.

        A text/event-stream reply carries its response inside an SSE event, so
        the envelope is the first event that is a JSON-RPC *response* (it has
        `result` or `error`); notifications streamed before it are skipped.
        """
        if self.is_event_stream:
            messages = [m for m in sse_messages(self.body) if isinstance(m, dict)]
            for message in messages:
                if "result" in message or "error" in message:
                    return message
            return messages[0] if messages else None
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
    #: `None` means *notification*: `body()` omits `"id"` entirely, which is
    #: what makes a notification a notification rather than a request whose id
    #: nobody looked at.
    request_id: Any | None = None
    headers: dict[str, str] = field(default_factory=dict)
    #: Overrides the whole body, for rules that need to send something a dict
    #: cannot express — malformed JSON, a missing `jsonrpc`, a duplicate key.
    raw_body: bytes | None = None

    def body(self) -> bytes:
        if self.raw_body is not None:
            return self.raw_body
        envelope: dict[str, Any] = {"jsonrpc": "2.0"}
        if self.request_id is not None:
            envelope["id"] = self.request_id
        envelope["method"] = self.method
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
        verify: bool | str = True,
        proxy: str | None = None,
        client_cert: str | tuple[str, str] | None = None,
        retries: int = DEFAULT_RETRIES,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.endpoint = endpoint
        self.user_agent = user_agent
        self.timeout = timeout
        self.bearer_token = bearer_token
        self.verify = verify
        self.proxy = proxy
        self.client_cert = client_cert
        self.retries = max(0, retries)
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=verify,
            # httpx 0.28 removed the plural `proxies=`; `proxy=` is the
            # surviving spelling and takes a single URL.
            proxy=proxy,
            cert=client_cert,
        )

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
            "User-Agent": self.user_agent,
            **request.headers,
        }
        if self.bearer_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        started = time.perf_counter()
        last_error: str | None = None
        for attempt in range(self.retries + 1):
            try:
                resp = self._client.post(self.endpoint, content=request.body(), headers=headers)
            except httpx.RequestError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < self.retries:
                    # Transport failures only. A response the server actually
                    # sent is never retried: re-running a tools/call would
                    # re-run its side effects and make every idempotency rule
                    # in the catalog meaningless.
                    time.sleep(BACKOFF_BASE_S * (2**attempt))
                    continue
                return RawResponse(
                    status=0,
                    headers={},
                    body=b"",
                    elapsed_s=time.perf_counter() - started,
                    transport_error=last_error,
                )
            return RawResponse(
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=resp.content,
                elapsed_s=time.perf_counter() - started,
            )
        raise AssertionError("unreachable: the loop returns on every path")

    def send_verbatim_headers(self, request: Request) -> RawResponse:
        """Send with header values exactly as given, padding included.

        httpx refuses a header value with leading or trailing whitespace before
        it reaches the wire, which is right for a client and useless for testing
        whether a SERVER trims it. `http.client` checks only for line breaks, so
        this path sends what it is handed. It does not go through a proxy or
        present a client certificate; when the scan uses either, it says so
        rather than sending the request a different way than every other one.
        """
        if self.proxy is not None or self.client_cert is not None:
            return RawResponse(
                status=0, headers={}, body=b"", elapsed_s=0.0,
                transport_error="this check sends raw headers and cannot use --proxy or "
                "--client-cert",
            )
        parts = urllib.parse.urlsplit(self.endpoint)
        headers = {
            "Content-Type": "application/json",
            "Accept": ACCEPT_VALUE,
            "User-Agent": self.user_agent,
            **request.headers,
        }
        if self.bearer_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            context = ssl.create_default_context()
            if self.verify is False:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            elif isinstance(self.verify, str):
                context.load_verify_locations(self.verify)
            conn = http.client.HTTPSConnection(
                parts.hostname or "", parts.port, timeout=self.timeout, context=context
            )
        else:
            conn = http.client.HTTPConnection(
                parts.hostname or "", parts.port, timeout=self.timeout
            )
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        started = time.perf_counter()
        try:
            conn.putrequest("POST", path, skip_accept_encoding=True)
            body = request.body()
            for name, value in headers.items():
                conn.putheader(name, value)
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            resp = conn.getresponse()
            return RawResponse(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.getheaders()},
                body=resp.read(),
                elapsed_s=time.perf_counter() - started,
            )
        except (OSError, http.client.HTTPException) as exc:
            return RawResponse(
                status=0, headers={}, body=b"", elapsed_s=time.perf_counter() - started,
                transport_error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            conn.close()

    def send_until_first_message(self, request: Request) -> RawResponse:
        """Send, and stop reading after the first complete message.

        `subscriptions/listen` answers with an SSE stream that stays open for as
        long as the client wants notifications. Reading it to the end would hang
        until the timeout and report a working server as unreachable, so this
        reads the stream only until its first event is complete, then closes it.
        A bare JSON reply is read whole, as `send` would. Never retried: the
        request reached the server or it did not, and either is the answer.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": ACCEPT_VALUE,
            "User-Agent": self.user_agent,
            **request.headers,
        }
        if self.bearer_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        started = time.perf_counter()
        try:
            with self._client.stream(
                "POST", self.endpoint, content=request.body(), headers=headers
            ) as resp:
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
                if "text/event-stream" not in response_headers.get("content-type", ""):
                    body = resp.read()
                else:
                    lines: list[str] = []
                    has_data = False
                    for line in resp.iter_lines():
                        lines.append(line)
                        if line.startswith("data:"):
                            has_data = True
                        elif line == "" and has_data:
                            break
                    body = ("\n".join(lines) + "\n\n").encode()
                return RawResponse(
                    status=resp.status_code,
                    headers=response_headers,
                    body=body,
                    elapsed_s=time.perf_counter() - started,
                )
        except httpx.RequestError as exc:
            return RawResponse(
                status=0,
                headers={},
                body=b"",
                elapsed_s=time.perf_counter() - started,
                transport_error=f"{type(exc).__name__}: {exc}",
            )
