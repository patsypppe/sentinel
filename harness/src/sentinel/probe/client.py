"""A deliberately literal MCP client.

`docs/HANDOFF.md` §9.4 is explicit that this must NOT be built on an SDK: an SDK
that helpfully adds `Mcp-Method` makes the rule requiring `Mcp-Method`
untestable, and one that normalizes a missing `resultType` makes the rule
requiring `resultType` untestable. Every deviation an SDK would smooth over is a
deviation this tool exists to detect.

So `Probe` builds each request from the specification text. Its convenience
methods produce *correct* requests; every one of them also takes overrides, so a
rule can send a request that is correct in every respect but one — which is what
makes a failure attributable.
"""

from __future__ import annotations

import uuid
from typing import Any

from sentinel import SPEC_REVISION
from sentinel.probe.transport import DEFAULT_TIMEOUT, RawResponse, Request, Transport

#: `_meta` keys, spelled exactly as the specification spells them.
KEY_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
KEY_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
KEY_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
KEY_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
KEY_TRACEPARENT = "traceparent"

HEADER_MCP_METHOD = "Mcp-Method"
HEADER_MCP_NAME = "Mcp-Name"

#: Methods that take a name, and the params field carrying it (§8.2).
NAME_BEARING = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}

CLIENT_INFO = {"name": "sentinel-probe", "version": "0.1.0"}

#: Distinguishes "the caller did not mention the version" from "the caller
#: asked for it to be omitted". `None` is a meaningful value here — it is the
#: unversioned request §8.1 treats as a legacy fallback — so it cannot double as
#: the default.
_UNSET: Any = object()


class Probe:
    """A literal MCP client with an override on every convenience."""

    def __init__(
        self,
        endpoint: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        bearer_token: str | None = None,
        protocol_version: str = SPEC_REVISION,
    ) -> None:
        self.endpoint = endpoint
        self.protocol_version = protocol_version
        self._transport = Transport(endpoint, timeout=timeout, bearer_token=bearer_token)

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> Probe:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- request construction ---------------------------------------------

    def meta(self, *, version: Any = _UNSET) -> dict[str, Any]:
        """Build a `_meta` object.

        `version=None` omits the protocol version entirely — the unversioned
        case §8.1 treats as a legacy fallback — which is different from not
        passing the argument at all.
        """
        meta: dict[str, Any] = {KEY_CLIENT_INFO: CLIENT_INFO}
        resolved = self.protocol_version if version is _UNSET else version
        if resolved is not None:
            meta[KEY_PROTOCOL_VERSION] = resolved
        return meta

    def expected_name(self, method: str, params: dict[str, Any] | None) -> str:
        """What `Mcp-Name` must be for this request (§8.2)."""
        field = NAME_BEARING.get(method)
        if field is None:
            return method
        value = (params or {}).get(field)
        return str(value) if value is not None else method

    def build(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        version: Any = _UNSET,
        include_meta: bool = True,
        headers: dict[str, str] | None = None,
        omit_mcp_method: bool = False,
        omit_mcp_name: bool = False,
        mcp_method: str | None = None,
        mcp_name: str | None = None,
        request_id: Any = None,
    ) -> Request:
        """Build a conformant request, then apply whatever the caller overrode."""
        body_params = dict(params or {})
        if include_meta:
            body_params["_meta"] = self.meta(version=version)

        built: dict[str, str] = {}
        if not omit_mcp_method:
            built[HEADER_MCP_METHOD] = mcp_method if mcp_method is not None else method
        if not omit_mcp_name:
            built[HEADER_MCP_NAME] = (
                mcp_name if mcp_name is not None else self.expected_name(method, params)
            )
        built.update(headers or {})

        return Request(
            method=method,
            params=body_params if body_params else None,
            request_id=request_id if request_id is not None else str(uuid.uuid4()),
            headers=built,
        )

    def call(
        self, method: str, params: dict[str, Any] | None = None, **overrides: Any
    ) -> RawResponse:
        """Build and send in one step."""
        return self._transport.send(self.build(method, params, **overrides))

    def send(self, request: Request) -> RawResponse:
        """Send a request built by hand, unchanged."""
        return self._transport.send(request)

    # -- the method surface, as convenience wrappers -----------------------

    def discover(self, **overrides: Any) -> RawResponse:
        return self.call("server/discover", **overrides)

    def tools_list(self, **overrides: Any) -> RawResponse:
        return self.call("tools/list", **overrides)

    def tools_call(
        self, name: str, arguments: dict[str, Any] | None = None, **overrides: Any
    ) -> RawResponse:
        return self.call(
            "tools/call", {"name": name, "arguments": arguments or {}}, **overrides
        )

    def resources_list(self, **overrides: Any) -> RawResponse:
        return self.call("resources/list", **overrides)

    def resource_templates_list(self, **overrides: Any) -> RawResponse:
        return self.call("resources/templates/list", **overrides)

    def resources_read(self, uri: str, **overrides: Any) -> RawResponse:
        return self.call("resources/read", {"uri": uri}, **overrides)

    def prompts_list(self, **overrides: Any) -> RawResponse:
        return self.call("prompts/list", **overrides)

    # -- facts a rule may need more than once -----------------------------

    def first_tool_name(self) -> str | None:
        """The name of any tool the server advertises, or None."""
        resp = self.tools_list()
        result = resp.result()
        if result is None:
            return None
        tools = result.get("tools")
        if not isinstance(tools, list) or not tools:
            return None
        first = tools[0]
        if not isinstance(first, dict):
            return None
        name = first.get("name")
        return name if isinstance(name, str) else None
