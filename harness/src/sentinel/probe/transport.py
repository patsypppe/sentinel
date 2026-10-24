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
import json
import os
import queue
import ssl
import subprocess
import threading
import time
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


_CONTEXTS: dict[tuple[str, str], ssl.SSLContext] = {}
_CONTEXT_LOCK = threading.Lock()


def _verify_argument(verify: bool | str, client_cert: object) -> bool | str | ssl.SSLContext:
    """What to hand httpx as `verify`.

    Building a verifying client loads the whole CA bundle, about 40 ms. A scan
    runs every rule on its own probe so no two rules share an HTTP client, which
    would make that cost 55 or more times per scan. An `SSLContext` is safe to
    share across threads, so one is built per distinct trust configuration and
    reused. A client certificate is loaded into the context by httpx, so a probe
    that has one builds its own rather than sharing a context with those that do
    not.
    """
    if verify is False or client_cert is not None:
        return verify
    key = ("default", "") if verify is True else ("cafile", str(verify))
    with _CONTEXT_LOCK:
        context = _CONTEXTS.get(key)
        if context is None:
            context = httpx.create_ssl_context(verify=verify)
            _CONTEXTS[key] = context
        return context


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

    #: Statuses that say the request was refused or dropped for a reason unrelated to the rule
    #: being tested: a rate limit, a gateway failure, a credential demand. Reading them as the
    #: server's answer turns a busy or protected server into a conformance failure.
    UNRELATED_STATUSES = frozenset({401, 407, 429, 502, 503, 504})

    def unusable_reason(self) -> str | None:
        """Why this response cannot be judged by a conformance rule, or None if it can."""
        if self.transport_error is not None:
            return self.transport_error
        if self.status in self.UNRELATED_STATUSES:
            return f"HTTP {self.status} (refused or dropped for a reason unrelated to this rule)"
        return None

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
            verify=_verify_argument(verify, client_cert),
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


class StdioTransport:
    """Sends requests to a server run as a child process, one JSON message per line.

    Most published MCP servers are stdio programs, not HTTP endpoints. This speaks their
    transport with the same interface as `Transport`, so every rule that only reads a
    server's answers works unchanged. The command comes from the person running the scan
    and is run without a shell. HTTP headers mean nothing here and are ignored.
    """

    #: What a stdio server inherits: enough to find its interpreter, nothing from the
    #: scanner's own environment such as tokens.
    _ENV_KEYS = (
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "TMPDIR",
        "SYSTEMROOT",
        "NODE_PATH",
        # So `npx` / `uvx` can fetch a package through the operator's proxy and CA bundle.
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "XDG_CACHE_HOME",
        "NPM_CONFIG_CACHE",
        "UV_CACHE_DIR",
    )

    def __init__(
        self,
        command: list[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        self.endpoint = "stdio:" + " ".join(command)
        self.command = command
        self.timeout = timeout
        self.env = env or {}
        self.cwd = cwd
        # Attributes `Probe` copies when it makes a sibling probe; none apply to a pipe.
        self.bearer_token: str | None = None
        self.verify: bool | str = True
        self.proxy: str | None = None
        self.client_cert: str | tuple[str, str] | None = None
        self.retries = 0
        self._proc: subprocess.Popen[bytes] | None = None
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        # One request at a time: replies are matched by id off a single pipe, so two
        # threads sharing a process must not both be reading it.
        self._lock = threading.Lock()

    def _start(self) -> str | None:
        if self._proc is not None:
            return None
        env = {k: os.environ[k] for k in self._ENV_KEYS if k in os.environ}
        env.update(self.env)
        try:
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
                cwd=self.cwd,
            )
        except OSError as exc:
            return f"{type(exc).__name__}: {exc}"
        threading.Thread(target=self._pump, args=(self._proc,), daemon=True).start()
        return None

    def _pump(self, proc: subprocess.Popen[bytes]) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def send(self, request: Request) -> RawResponse:
        with self._lock:
            return self._send(request)

    def _send(self, request: Request) -> RawResponse:
        started = time.perf_counter()

        def failed(reason: str) -> RawResponse:
            return RawResponse(
                status=0,
                headers={},
                body=b"",
                elapsed_s=time.perf_counter() - started,
                transport_error=reason,
            )

        if (error := self._start()) is not None:
            return failed(error)
        assert self._proc is not None and self._proc.stdin is not None
        try:
            self._proc.stdin.write(request.body().replace(b"\n", b" ") + b"\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            return failed(f"the server process closed its input: {exc}")
        if request.request_id is None:
            return RawResponse(202, {}, b"", time.perf_counter() - started)

        deadline = time.monotonic() + self.timeout
        while True:
            try:
                line = self._lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                return failed(f"no reply within {self.timeout:g}s")
            if line is None:
                return failed("the server process exited before replying")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # a banner or log line on stdout is not a reply
            # Skip server-initiated messages and answers to other requests.
            if isinstance(message, dict) and message.get("id") == request.request_id:
                return RawResponse(
                    status=200,
                    headers={"content-type": "application/json"},
                    body=line.strip(),
                    elapsed_s=time.perf_counter() - started,
                )

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        with contextlib.suppress(OSError):
            if proc.stdin:
                proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
