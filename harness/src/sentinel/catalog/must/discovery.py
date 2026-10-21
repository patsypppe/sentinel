"""MUST rules for discovery and negotiation (`SN-CAP-01`).

`server/discover` became mandatory in 2026-07-28, replacing the `initialize`
handshake. It negotiates like every other request: the final text says a server
MAY answer it with UnsupportedProtocolVersionError, and that error is itself how
a client learns which versions exist. (0.1.0 through 0.3.0 read the release
candidate's framing as an exemption; see `discover-without-negotiated-version`.)
"""

from __future__ import annotations

from sentinel.catalog.base import (
    SPEC_BASE,
    BaseRule,
    RuleResult,
    Severity,
    Verifiability,
    rule,
)
from sentinel.probe.client import KEY_SERVER_INFO, Probe
from sentinel.probe.transport import RawResponse

CHANGELOG = f"{SPEC_BASE}/changelog"
LIFECYCLE = f"{SPEC_BASE}/basic/versioning"


@rule(
    id="MCP/2026-07-28/MUST/discover-implemented",
    title="server/discover is implemented",
    severity=Severity.MUST,
    citation=f"{CHANGELOG}#major-changes",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Implement server/discover. It replaced the initialize handshake in this revision "
        "and is how every client learns which protocol versions, capabilities and tools "
        "this server offers."
    ),
)
def discover_implemented(probe: Probe) -> RuleResult:
    resp = probe.discover()
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    result = resp.result()
    if result is not None:
        return RuleResult.passed("server/discover answered with a result")

    err = resp.error()
    if err is None:
        return RuleResult.failed(
            "server/discover returned neither a result nor a JSON-RPC error",
            evidence=resp.body[:400].decode(errors="replace"),
        )
    if err.get("code") == -32601:
        return RuleResult.failed(
            "server/discover returned method-not-found; this server does not implement it",
            evidence=str(err),
        )
    return RuleResult.failed(f"server/discover returned an error: {err}", evidence=str(err))


@rule(
    id="MCP/2026-07-28/MUST/discover-without-negotiated-version",
    title="server/discover answers without a negotiated protocol version",
    severity=Severity.MUST,
    citation=f"{LIFECYCLE}#protocol-version-negotiation",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Exempt server/discover from version negotiation. Its purpose is to let a client "
        "find out which versions exist BEFORE committing to one, so refusing it for an "
        "absent or unknown version makes the server undiscoverable."
    ),
    deprecated_in="0.4.0",
    superseded_by="MCP/2026-07-28/MUST/unsupported-version-error-shape",
)
def discover_without_version(probe: Probe) -> RuleResult:
    # Wrong against the final 2026-07-28 text, which says server/discover MAY
    # answer an unsupported version with UnsupportedProtocolVersionError, and
    # whose Server Validation rejects a request missing the version header.
    # Found by running the official conformance suite's reference server through
    # Sentinel: it negotiates discover like any request -- correctly -- and this
    # rule failed it. Superseded rather than edited, because ids are permanent.
    absent = probe.discover(version=None)
    if not absent.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {absent.transport_error}")

    if absent.result() is None:
        return RuleResult.failed(
            "server/discover was refused when no protocol version was declared: "
            f"{absent.error()}",
            evidence=str(absent.error()),
        )

    # And at a version this server has certainly never heard of. A client that
    # guessed wrong still has to be able to find out what to guess next.
    future = probe.discover(version="2099-01-01")
    if future.result() is None:
        return RuleResult.failed(
            "server/discover was refused for an unknown protocol version "
            f"(2099-01-01): {future.error()}. A client that guessed wrong cannot "
            "discover what to guess instead.",
            evidence=str(future.error()),
        )

    return RuleResult.passed("server/discover answered with no version and with an unknown one")


@rule(
    id="MCP/2026-07-28/MUST/discover-reports-supported-versions",
    title="server/discover reports supportedVersions",
    severity=Severity.MUST,
    citation=f"{LIFECYCLE}#protocol-version-negotiation",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Include a non-empty supportedVersions array in the server/discover result. "
        "Without it a client has no way to choose a version and must guess."
    ),
)
def discover_reports_versions(probe: Probe) -> RuleResult:
    result = probe.discover().result()
    if result is None:
        return RuleResult.not_applicable("server/discover did not return a result")

    versions = result.get("supportedVersions")
    if not isinstance(versions, list) or not versions:
        return RuleResult.failed(
            f"supportedVersions is absent or empty: {versions!r}", evidence=str(result)[:400]
        )
    if not all(isinstance(v, str) for v in versions):
        return RuleResult.failed(f"supportedVersions contains non-strings: {versions!r}")
    return RuleResult.passed(f"supportedVersions = {versions}")


@rule(
    id="MCP/2026-07-28/MUST/discover-reports-server-info",
    title="server/discover identifies the server",
    severity=Severity.MUST,
    citation=f"{SPEC_BASE}/server/discover#response",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Report serverInfo with at least a name from server/discover. Clients key cache "
        "entries on the server's identity, so a server that will not name itself cannot "
        "be cached against."
    ),
)
def discover_reports_server_info(probe: Probe) -> RuleResult:
    result = probe.discover().result()
    if result is None:
        return RuleResult.not_applicable("server/discover did not return a result")

    # Either shape is accepted: at the top level, or echoed in `_meta` the way
    # every other result carries it.
    info = result.get("serverInfo")
    if not isinstance(info, dict):
        meta = result.get("_meta")
        if isinstance(meta, dict):
            info = meta.get(KEY_SERVER_INFO)

    if not isinstance(info, dict) or not info.get("name"):
        return RuleResult.failed(
            "server/discover does not report a serverInfo with a name",
            evidence=str(result)[:400],
        )
    return RuleResult.passed(f"serverInfo.name = {info['name']!r}")


@rule(
    id="MCP/2026-07-28/MUST/discover-reports-capabilities",
    title="server/discover reports capabilities",
    severity=Severity.MUST,
    citation=f"{SPEC_BASE}/server/discover#response",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Report a capabilities object from server/discover. A client cannot tell an "
        "unimplemented capability from an undeclared one, so an absent object forces it "
        "to probe every method to find out."
    ),
)
def discover_reports_capabilities(probe: Probe) -> RuleResult:
    result = probe.discover().result()
    if result is None:
        return RuleResult.not_applicable("server/discover did not return a result")

    caps = result.get("capabilities")
    if not isinstance(caps, dict):
        return RuleResult.failed(
            f"capabilities is absent or not an object: {caps!r}", evidence=str(result)[:400]
        )
    return RuleResult.passed(f"capabilities declared: {sorted(caps)}")


@rule(
    id="MCP/2026-07-28/MUST/unsupported-version-rejected",
    title="An unsupported protocol version is rejected with -32022",
    severity=Severity.MUST,
    citation=f"{LIFECYCLE}#protocol-version-negotiation",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Return -32022 UnsupportedProtocolVersion, with the supported versions in the "
        "error data, when a request declares a version this server does not implement. "
        "Serving the request anyway leaves the client believing a version was agreed."
    ),
)
def unsupported_version_rejected(probe: Probe) -> RuleResult:
    resp = probe.tools_list(version="2099-01-01")
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    code = resp.error_code()
    if code == -32022:
        return RuleResult.passed("tools/list at 2099-01-01 returned -32022")
    if resp.result() is not None:
        return RuleResult.failed(
            "tools/list was SERVED at protocol version 2099-01-01, which this server "
            "cannot implement; the client now believes a version was agreed",
            evidence=str(resp.result())[:400],
        )
    return RuleResult.failed(
        f"an unsupported version returned {code} rather than -32022", evidence=str(resp.error())
    )


#: Certainly not implemented by anyone; a later real revision cannot collide.
_FUTURE_VERSION = "2099-01-01"


@rule(
    id="MCP/2026-07-28/MUST/unsupported-version-error-shape",
    title="An unsupported version gets HTTP 400 and an error naming supported and requested",
    severity=Severity.MUST,
    citation=f"{LIFECYCLE}#protocol-version-negotiation",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Answer a request at a protocol version this server does not implement -- "
        "server/discover included -- with HTTP 400 and -32022 whose data carries "
        "`supported` (a non-empty array of the versions you implement) and `requested` "
        "(the version the client asked for). The 400 is what tells a dual-era client "
        "this is a modern server to retry rather than a legacy one to fall back to, and "
        "`supported` is the only way it learns what to retry with."
    ),
    introduced_in="0.4.0",
)
def unsupported_version_error_shape(probe: Probe) -> RuleResult:
    problems: list[str] = []
    evidence: list[str] = []
    attempts: list[tuple[str, RawResponse]] = [
        ("server/discover", probe.discover(version=_FUTURE_VERSION)),
        ("tools/list", probe.tools_list(version=_FUTURE_VERSION)),
    ]
    for label, resp in attempts:
        if not resp.reached_server:
            return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")
        evidence.append(f"{label}: HTTP {resp.status}, {resp.error() or resp.result()}")
        if resp.result() is not None:
            problems.append(f"{label} was SERVED at {_FUTURE_VERSION}")
            continue
        error = resp.error() or {}
        if error.get("code") != -32022:
            problems.append(f"{label} returned code {error.get('code')}, not -32022")
            continue
        if resp.status != 400:
            problems.append(f"{label} returned HTTP {resp.status}, not 400")
        data = error.get("data")
        supported = data.get("supported") if isinstance(data, dict) else None
        if not (
            isinstance(supported, list)
            and supported
            and all(isinstance(v, str) for v in supported)
        ):
            hint = ""
            if isinstance(data, dict) and "supportedVersions" in data:
                hint = " (it sent `supportedVersions`, the DiscoverResult field name)"
            problems.append(f"{label}: error.data.supported is {supported!r}{hint}")
        requested = data.get("requested") if isinstance(data, dict) else None
        if requested != _FUTURE_VERSION:
            problems.append(
                f"{label}: error.data.requested is {requested!r}, not {_FUTURE_VERSION!r}"
            )

    if problems:
        return RuleResult.failed("; ".join(problems), evidence=" | ".join(evidence)[:600])
    return RuleResult.passed(
        "server/discover and tools/list at an unknown version both returned HTTP 400, "
        "-32022, data.supported and data.requested"
    )


#: Capability name in server/discover -> the filter field that subscribes to it.
_LIST_CHANGED_FILTER = {
    "tools": "toolsListChanged",
    "prompts": "promptsListChanged",
    "resources": "resourcesListChanged",
}

ACK_METHOD = "notifications/subscriptions/acknowledged"


@rule(
    id="MCP/2026-07-28/MUST/list-changed-advertised-truthfully",
    title="A declared listChanged capability is backed by subscriptions/listen",
    severity=Severity.MUST,
    citation=f"{CHANGELOG}#major-changes",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Advertise listChanged: false unless subscriptions/listen is implemented. A client "
        "that trusts the declaration will wait for change notifications that never arrive, "
        "and will serve stale tools indefinitely."
    ),
)
def list_changed_is_truthful(probe: Probe) -> RuleResult:
    result = probe.discover().result()
    if result is None:
        return RuleResult.not_applicable("server/discover did not return a result")

    caps = result.get("capabilities")
    if not isinstance(caps, dict):
        return RuleResult.not_applicable("no capabilities were declared")

    claims = [
        name
        for name, value in caps.items()
        if isinstance(value, dict) and value.get("listChanged") is True
    ]
    if not claims:
        return RuleResult.passed("listChanged is not advertised on any capability")

    # A well-formed request: `notifications` names what to subscribe to. 0.3.0
    # sent `{}`, which a server is right to refuse with -32602 -- the official
    # reference server did, and this rule reported its working subscriptions as
    # missing. The stream stays open, so only its first message is read.
    notifications = {
        _LIST_CHANGED_FILTER[name]: True for name in claims if name in _LIST_CHANGED_FILTER
    }
    listen = probe.call_first_message("subscriptions/listen", {"notifications": notifications})
    if not listen.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {listen.transport_error}")

    acknowledged = (listen.envelope() or {}).get("method") == ACK_METHOD

    # ANY error means the method is not there. Checking specifically for -32601
    # would miss a server that returns its own house error for everything it
    # does not implement, which is common and is exactly what the fixture does.
    if not acknowledged and listen.result() is None:
        return RuleResult.failed(
            f"{claims} advertise listChanged: true, but subscriptions/listen does not "
            f"answer (error {listen.error_code()}). A client will wait for notifications "
            "that never arrive and serve a stale manifest indefinitely.",
            evidence=str(listen.error()),
        )

    # A server that answers EVERYTHING answers this too, which is not evidence
    # that it implements it.
    #
    # Without this control, a catch-all route masks the very violation the rule
    # is about: the target replies to subscriptions/listen exactly as it replies
    # to a method nobody has ever defined, and "it responded" reads as support.
    control = probe.call("sentinel/definitely-not-a-real-method", {})
    if control.result() is not None:
        return RuleResult.failed(
            f"{claims} advertise listChanged: true, and subscriptions/listen returns a "
            "result — but so does an invented method name, so this server answers "
            "everything and its support for subscriptions is not demonstrated.",
            evidence=f"subscriptions/listen → {listen.result()}, control → {control.result()}",
        )

    if acknowledged:
        return RuleResult.passed(
            f"{claims} advertise listChanged, and subscriptions/listen opened a stream "
            f"whose first message is {ACK_METHOD}"
        )
    return RuleResult.passed(
        f"{claims} advertise listChanged, and subscriptions/listen answers where an "
        "unknown method does not"
    )


@rule(
    id="MCP/2026-07-28/MUST/initialize-removed",
    title="The initialize handshake is gone",
    severity=Severity.MUST,
    citation=f"{CHANGELOG}#major-changes",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Remove the initialize method and answer method-not-found for it. This revision is "
        "stateless: a handshake that appears to succeed leaves the client believing it "
        "holds a session that does not exist."
    ),
)
def initialize_removed(probe: Probe) -> RuleResult:
    resp = probe.call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    if resp.result() is not None:
        return RuleResult.failed(
            "initialize was served; this server still offers the handshake that was removed "
            "in 2026-07-28, and a client will believe it holds a session",
            evidence=str(resp.result())[:300],
        )
    if resp.error_code() == -32601:
        return RuleResult.passed("initialize returns method-not-found")
    return RuleResult.passed(f"initialize is refused (code {resp.error_code()})")


def _removed_method_rule(method: str, slug: str, why: str, replacement: str) -> BaseRule:
    """Build a rule for a method this revision deleted.

    §9.1: removed methods must answer method-not-found rather than being
    silently absent from the router. A conformance rule checks exactly this, so
    a server that removed the method but not the route still fails.
    """

    @rule(
        id=f"MCP/2026-07-28/MUST/{slug}",
        title=f"{method} is removed",
        severity=Severity.MUST,
        citation=f"{CHANGELOG}#major-changes",
        verifiability=Verifiability.BLACK_BOX,
        remediation=(
            f"Stop serving {method}; it was removed in 2026-07-28. {why} "
            f"Answer method-not-found, ideally naming {replacement} as the replacement, so a "
            "migrating client is told what to use instead."
        ),
    )
    def check(probe: Probe, _method: str = method) -> RuleResult:
        resp = probe.call(_method, {})
        if not resp.reached_server:
            return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")
        if resp.result() is not None:
            return RuleResult.failed(
                f"{_method} was served; it was removed in 2026-07-28",
                evidence=str(resp.result())[:300],
            )
        if resp.error_code() == -32601:
            return RuleResult.passed(f"{_method} returns method-not-found")
        return RuleResult.passed(f"{_method} is refused (code {resp.error_code()})")

    return check


ping_removed = _removed_method_rule(
    "ping",
    "ping-removed",
    "A stateless protocol has no connection to keep alive.",
    "ordinary request timeouts",
)

logging_removed = _removed_method_rule(
    "logging/setLevel",
    "logging-set-level-removed",
    "Log level is carried per-request in _meta now.",
    "_meta.io.modelcontextprotocol/logLevel",
)

resources_subscribe_removed = _removed_method_rule(
    "resources/subscribe",
    "resources-subscribe-removed",
    "Subscriptions moved to a single streaming method.",
    "subscriptions/listen",
)

resources_unsubscribe_removed = _removed_method_rule(
    "resources/unsubscribe",
    "resources-unsubscribe-removed",
    "Subscriptions moved to a single streaming method.",
    "subscriptions/listen",
)

sampling_removed = _removed_method_rule(
    "sampling/createMessage",
    "sampling-create-message-removed",
    "The server never calls the client in this revision.",
    "multi round-trip requests",
)

roots_list_removed = _removed_method_rule(
    "roots/list",
    "roots-list-removed",
    "Roots were deprecated under SEP-2577.",
    "explicit tool arguments",
)
