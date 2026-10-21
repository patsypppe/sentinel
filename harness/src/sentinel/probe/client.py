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
from dataclasses import replace
from typing import Any

from sentinel import SPEC_REVISION
from sentinel.budget import BudgetPolicy
from sentinel.probe.transport import (
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    RawResponse,
    Request,
    Transport,
)

#: `_meta` keys, spelled exactly as the specification spells them.
KEY_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
KEY_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
KEY_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
KEY_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
KEY_TRACEPARENT = "traceparent"

HEADER_MCP_METHOD = "Mcp-Method"
HEADER_MCP_NAME = "Mcp-Name"
#: Required on EVERY POST, and its value MUST match the protocolVersion in the
#: body's _meta. A server enforcing this rejects a request without it outright,
#: which means a probe that omits it cannot grade anything.
HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"

#: Methods that take a name, and the params field carrying it (§8.2).
NAME_BEARING = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}

CLIENT_INFO = {"name": "sentinel-probe", "version": "0.1.0"}

#: The probe declares no client capabilities, which is the truth: it cannot
#: sample, elicit, or serve roots. Declaring capabilities it does not have would
#: invite servers into MRTR flows the probe cannot complete, and the spec is
#: explicit that a server MUST NOT ask for a capability the client did not
#: declare -- which is itself a rule worth being able to test.
CLIENT_CAPABILITIES: dict[str, Any] = {}

#: Distinguishes "the caller did not mention the version" from "the caller
#: asked for it to be omitted". `None` is a meaningful value here — it is the
#: unversioned request §8.1 treats as a legacy fallback — so it cannot double as
#: the default.
_UNSET: Any = object()

#: The transport_error a safe-mode probe reports for a tools/call it declined to
#: send. Rules already treat "did not reach the server" as INDETERMINATE, so a
#: declined call degrades every rule that needs it to an honest "could not
#: verify" without any rule having to know safe mode exists.
SAFE_MODE_REFUSAL = "not sent: safe mode does not invoke"


def is_read_only(tool: dict[str, Any]) -> bool:
    """Whether a tool's own annotations promise that calling it changes nothing.

    `readOnlyHint` is the server's statement that a tool does not modify its
    environment; `destructiveHint` defaults to true in the specification, so a
    tool is only treated as safe when it is explicitly read-only AND not
    explicitly destructive. An unannotated tool is not read-only: the absence
    of a promise is not a promise.
    """
    annotations = tool.get("annotations")
    if not isinstance(annotations, dict):
        return False
    read_only = annotations.get("readOnlyHint") is True
    return read_only and annotations.get("destructiveHint") is not True


class Probe:
    """A literal MCP client with an override on every convenience."""

    def __init__(
        self,
        endpoint: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        bearer_token: str | None = None,
        protocol_version: str = SPEC_REVISION,
        verify: bool | str = True,
        proxy: str | None = None,
        client_cert: str | tuple[str, str] | None = None,
        retries: int = DEFAULT_RETRIES,
        budgets: BudgetPolicy | None = None,
        safe: bool = False,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.endpoint = endpoint
        #: Inputs a rule may need beyond the wire: a baseline snapshot for the
        #: drift rule, supplied evidence for the gray-box rules. Carried on the
        #: probe, like the budgets, so every input a rule reads is reachable from
        #: its single argument and two scans in one process cannot share one.
        self.context: dict[str, Any] = context if context is not None else {}
        #: Safe mode is for scanning servers you do not own. Every rule still
        #: runs, but a tools/call naming a tool the server advertises is only
        #: sent when that tool is annotated read-only; otherwise the call is
        #: reported as not sent and the rule that needed it is INDETERMINATE.
        #: Calls to invented tool names are still sent -- refusing an unknown
        #: tool is the behaviour those rules test, and it has no side effect.
        self.safe = safe
        self._advertised: dict[str, bool] | None = None
        self.protocol_version = protocol_version
        #: Operator-supplied ceilings for the SENTINEL/OPS budget rules. Carried
        #: here rather than read from a module global so two scans in one
        #: process cannot silently share one, and so every input a rule reads is
        #: reachable from its single argument.
        self.budgets = budgets if budgets is not None else BudgetPolicy()
        self._transport = Transport(
            endpoint,
            timeout=timeout,
            bearer_token=bearer_token,
            verify=verify,
            proxy=proxy,
            client_cert=client_cert,
            retries=retries,
        )

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> Probe:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def new_connection(self) -> Probe:
        """A second probe to the same endpoint over a separate HTTP client.

        The specification says a list result "MUST NOT vary per-connection".
        Proving that needs two connections; a rule holding one `Probe` has one.
        The caller owns the returned probe and must close it.
        """
        return Probe(
            self.endpoint,
            timeout=self._transport.timeout,
            bearer_token=self._transport.bearer_token,
            protocol_version=self.protocol_version,
            # The second connection must differ from the first in exactly one
            # respect -- being a second connection. A probe that reached the
            # target through a proxy and a client certificate but whose twin
            # did not would be comparing two different servers.
            verify=self._transport.verify,
            proxy=self._transport.proxy,
            client_cert=self._transport.client_cert,
            retries=self._transport.retries,
            safe=self.safe,
            budgets=self.budgets,
            context=self.context,
        )

    # -- request construction ---------------------------------------------

    def meta(
        self,
        *,
        version: Any = _UNSET,
        omit_client_capabilities: bool = False,
        client_capabilities: Any = _UNSET,
    ) -> dict[str, Any]:
        """Build a `_meta` object.

        `protocolVersion` and `clientCapabilities` are Required: Yes on every
        request; `clientInfo` is Required: No but SHOULD be sent, so it is.

        `version=None` omits the protocol version entirely — the unversioned
        case §8.1 treats as a legacy fallback — which is different from not
        passing the argument at all. `omit_client_capabilities` is the same idea
        for the other required field: a rule that tests the MUST has to be able
        to break it deliberately.
        """
        meta: dict[str, Any] = {KEY_CLIENT_INFO: CLIENT_INFO}
        resolved = self.protocol_version if version is _UNSET else version
        if resolved is not None:
            meta[KEY_PROTOCOL_VERSION] = resolved
        if not omit_client_capabilities:
            meta[KEY_CLIENT_CAPABILITIES] = (
                CLIENT_CAPABILITIES if client_capabilities is _UNSET else client_capabilities
            )
        return meta

    def expected_name(self, method: str, params: dict[str, Any] | None) -> str | None:
        """What `Mcp-Name` must be for this request, or None where the header is
        not defined for the method (§8.2).

        The Standard Request Headers table sources `Mcp-Name` from `params.name`
        or `params.uri` and requires it for `tools/call`, `resources/read` and
        `prompts/get` — "All requests" is `Mcp-Method`'s row. A method with
        neither field has nothing for a header to be matched against, so sending
        one would assert a body value that does not exist, and a server strict
        enough to reject that would be right to. The probe would then grade a
        conformant server as broken on every rule at once.
        """
        field = NAME_BEARING.get(method)
        if field is None:
            return None
        value = (params or {}).get(field)
        return str(value) if value is not None else None

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
        omit_client_capabilities: bool = False,
        client_capabilities: Any = _UNSET,
        omit_protocol_version_header: bool = False,
        protocol_version_header: str | None = None,
        request_id: Any = None,
    ) -> Request:
        """Build a conformant request, then apply whatever the caller overrode."""
        body_params = dict(params or {})
        if include_meta:
            body_params["_meta"] = self.meta(
                version=version,
                omit_client_capabilities=omit_client_capabilities,
                client_capabilities=client_capabilities,
            )

        built: dict[str, str] = {}
        if not omit_mcp_method:
            built[HEADER_MCP_METHOD] = mcp_method if mcp_method is not None else method
        if not omit_mcp_name:
            resolved_name = (
                mcp_name if mcp_name is not None else self.expected_name(method, params)
            )
            # Omitted ENTIRELY, not sent empty: a method the header table does
            # not name has no body field for the header to match, and an empty
            # header value is still a claim that one exists.
            if resolved_name is not None:
                built[HEADER_MCP_NAME] = resolved_name
        if not omit_protocol_version_header:
            declared = self.meta(version=version).get(KEY_PROTOCOL_VERSION)
            resolved_header = (
                protocol_version_header if protocol_version_header is not None else declared
            )
            # When the caller asked for an unversioned body there is nothing for
            # the header to agree with, so sending one would manufacture the
            # very mismatch the header rule exists to detect.
            if resolved_header is not None:
                built[HEADER_PROTOCOL_VERSION] = str(resolved_header)
        built.update(headers or {})

        return Request(
            method=method,
            params=body_params if body_params else None,
            request_id=request_id if request_id is not None else str(uuid.uuid4()),
            headers=built,
        )

    def build_notification(
        self, method: str, params: dict[str, Any] | None = None, **overrides: Any
    ) -> Request:
        """A JSON-RPC notification: no id, and no response is expected."""
        return replace(self.build(method, params, **overrides), request_id=None)

    def call(
        self, method: str, params: dict[str, Any] | None = None, **overrides: Any
    ) -> RawResponse:
        """Build and send in one step."""
        return self._transport.send(self.build(method, params, **overrides))

    def notify(
        self, method: str, params: dict[str, Any] | None = None, **overrides: Any
    ) -> RawResponse:
        """Send a notification. The HTTP response is still returned: whether a
        server answers an id-less POST at all is itself a thing rules test."""
        return self._transport.send(self.build_notification(method, params, **overrides))

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
        if self.safe and not self._safe_to_invoke(name):
            return RawResponse(
                status=0,
                headers={},
                body=b"",
                elapsed_s=0.0,
                transport_error=(
                    f"{SAFE_MODE_REFUSAL} {name!r}, which is not annotated "
                    "readOnlyHint=true (run without --safe to verify this rule "
                    "against a server you own)"
                ),
            )
        return self.call(
            "tools/call", {"name": name, "arguments": arguments or {}}, **overrides
        )

    def _safe_to_invoke(self, name: str) -> bool:
        """In safe mode, whether calling `name` could change anything.

        A name the server does not advertise is safe to send: the server is
        expected to refuse it, and the rules that send one are testing exactly
        that refusal. An advertised name is safe only if its annotations say so.
        """
        if self._advertised is None:
            self._advertised = {}
            result = self.tools_list().result()
            tools = (result or {}).get("tools")
            if isinstance(tools, list):
                for tool in tools:
                    if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                        self._advertised[tool["name"]] = is_read_only(tool)
        return self._advertised.get(name, True)

    def resources_list(self, **overrides: Any) -> RawResponse:
        return self.call("resources/list", **overrides)

    def resource_templates_list(self, **overrides: Any) -> RawResponse:
        return self.call("resources/templates/list", **overrides)

    def resources_read(self, uri: str, **overrides: Any) -> RawResponse:
        return self.call("resources/read", {"uri": uri}, **overrides)

    def prompts_list(self, **overrides: Any) -> RawResponse:
        return self.call("prompts/list", **overrides)

    def prompts_get(
        self, name: str, arguments: dict[str, Any] | None = None, **overrides: Any
    ) -> RawResponse:
        return self.call("prompts/get", {"name": name, "arguments": arguments or {}}, **overrides)

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
