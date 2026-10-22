"""Beyond-spec security checks.

These are `SENTINEL/SECURITY/*`: properties this project holds a server to that
the specification's security page does not state as requirements. They are the
rules that used to be filed under the spec namespace on the strength of a
citation that, read closely, never said what the rule claimed.
"""

from __future__ import annotations

import datetime
import re
import socket
import ssl
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from sentinel.catalog.base import RuleResult, Severity, Verifiability, rule
from sentinel.catalog.graybox_checks import audit_check
from sentinel.probe.client import Probe


@rule(
    id="SENTINEL/SECURITY/invocations-are-audited",
    title="Every tool invocation is recorded in an append-only log",
    severity=Severity.MUST,
    rationale=(
        "The 2026-07-28 security best-practices page has no audit-logging section, so "
        "no MUST in the specification requires this. It is still the property that "
        "lets an operator answer 'what did this agent do, and as whom' after the "
        "fact, and a server that cannot answer is hard to defend in an incident. "
        "Sentinel holds servers to it as an opinion, not as conformance."
    ),
    verifiability=Verifiability.UNVERIFIABLE,
    remediation=(
        "Write an append-only, hash-chained row for every invocation, and fail the "
        "invocation if the write fails. Enforce append-only with database grants rather "
        "than convention, so the property does not depend on every future code path "
        "remembering it."
    ),
    introduced_in="0.3.0",
)
def invocations_audited(_: Probe) -> RuleResult:
    return RuleResult.indeterminate(
        "An audit log is not exposed over MCP, and a server that claimed to keep one would "
        "be believed on its own word -- which is the opposite of what an audit is for. "
        "To settle it: read the log directly and verify its chain, e.g. with a "
        "verification command the server ships."
    )


invocations_audited.graybox("audit_verify")(audit_check)

# ---------------------------------------------------------------------------
# tool-description-injection
#
# Regex only. This project has no model API key and will not acquire one, so the
# check is a set of patterns for the things that are almost never in an honest tool
# description. It is a heuristic and says so: a hit is a reason to read the
# description, never proof of an attack, and a miss is not a clean bill of health.
# ---------------------------------------------------------------------------

#: Characters that render as nothing, or reorder what is rendered: zero-width
#: space, joiners, word joiner and BOM; the bidirectional overrides and isolates;
#: and Unicode "tag" characters, which are invisible and can spell out text.
_HIDDEN = re.compile("[​‌‍‎‏⁠-⁤﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_STEERING = re.compile(
    r"(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,30}"
    r"\b(instructions?|prompts?|rules?)"
    r"|do\s+not\s+(tell|inform|mention|reveal|show)\b.{0,20}\b(the\s+)?user"
    r"|without\s+(telling|informing|notifying|alerting)\s+the\s+user"
    r"|<\s*/?\s*(important|system|instructions?)\s*>"
    r"|\bsystem\s+prompt\b"
    r"|\bbefore\s+(using|calling|invoking)\s+this\s+tool\b.{0,60}\b(read|send|include|call)\b",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_PATH = re.compile(
    r"(~|\$HOME|/home/\w+|/Users/\w+)?/?\.(ssh|aws|gnupg|kube)\b|id_rsa|\.env\b|/etc/passwd|"
    r"credentials?\.json",
    re.IGNORECASE,
)


def _descriptions(tool: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """Every free-text field a model reads about a tool, with where it sits."""
    for field_name in ("name", "title", "description"):
        value = tool.get(field_name)
        if isinstance(value, str):
            yield field_name, value

    def walk(node: Any, path: str) -> Iterator[tuple[str, str]]:
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}/{key}"
                if key in ("description", "title") and isinstance(value, str):
                    yield here, value
                else:
                    yield from walk(value, here)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                yield from walk(item, f"{path}[{index}]")

    yield from walk(tool.get("inputSchema"), "inputSchema")


def injection_findings(tool: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(category, where, excerpt) for every suspicious thing in a tool's text."""
    found: list[tuple[str, str, str]] = []
    for where, text in _descriptions(tool):
        if _HIDDEN.search(text):
            shown = "".join(f"<U+{ord(c):04X}>" if _HIDDEN.match(c) else c for c in text[:80])
            found.append(("hidden-unicode", where, shown))
        if _HTML_COMMENT.search(text):
            found.append(("html-comment", where, text[:80]))
        match = _STEERING.search(text)
        if match:
            found.append(("steering-phrase", where, match.group(0)[:80]))
        sensitive = _SENSITIVE_PATH.search(text)
        if sensitive:
            found.append(("sensitive-path", where, sensitive.group(0)[:80]))
    return found


@rule(
    id="SENTINEL/SECURITY/tool-description-injection",
    title="Tool descriptions contain no hidden text or instructions aimed at the model",
    severity=Severity.MUST,
    rationale=(
        "A tool description is text a model is steered by, written by whoever "
        "operates the server. Hidden Unicode, HTML comments, phrases that tell the "
        "model to ignore its instructions or conceal something from the user, and "
        "references to credential files have no place in an honest description. The "
        "specification does not forbid them, which is why this is a beyond-spec "
        "check. It is a regex heuristic with no model call: a hit means read the "
        "description, a miss is not proof of safety."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Remove the flagged text from the tool or schema description. If it is "
        "legitimate (a description that really does explain how to handle a secrets "
        "file), waive this rule for the target with a reason and an expiry."
    ),
    introduced_in="0.4.0",
)
def tool_description_injection(probe: Probe) -> RuleResult:
    from sentinel.snapshot import fetch_tools

    tools, why = fetch_tools(probe)
    if tools is None:
        return RuleResult.indeterminate(why)
    if not tools:
        return RuleResult.not_applicable("the server advertises no tools")
    hits: list[str] = []
    keys: list[str] = []
    for name in sorted(tools):
        for category, where, excerpt in injection_findings(tools[name]):
            hits.append(f"{name} {where} [{category}]: {excerpt!r}")
            keys.append(f"{category}:{name}")
    if hits:
        return RuleResult.failed(
            f"{len(hits)} suspicious item(s) in tool text: " + "; ".join(hits[:4]),
            evidence="; ".join(hits[:6]),
            key=",".join(sorted(set(keys))),
        )
    return RuleResult.passed(f"no suspicious text in {len(tools)} tool(s)")


# ---------------------------------------------------------------------------
# wildcard-scopes

_WILDCARD = re.compile(r"(^|[:/._-])(\*|all|full[-_]?access|admin\*?)$|^\*|:\*$", re.IGNORECASE)


@rule(
    id="SENTINEL/SECURITY/wildcard-scopes",
    title="No tool advertises a wildcard or full-access scope",
    severity=Severity.MUST,
    rationale=(
        "A tool that claims `*`, `all` or `full-access` asks for authority a "
        "reviewer cannot reason about, and a token minted for it is a token that "
        "works everywhere. The specification does not forbid broad scopes; narrowing "
        "them is what makes a stolen token survivable."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Replace the wildcard with the specific scopes the tool needs, one per "
        "capability (for example files:read and files:write instead of files:*)."
    ),
    introduced_in="0.4.0",
)
def wildcard_scopes(probe: Probe) -> RuleResult:
    from sentinel.snapshot import extract_scopes, fetch_tools

    tools, why = fetch_tools(probe)
    if tools is None:
        return RuleResult.indeterminate(why)
    claimed = {name: extract_scopes(tool) for name, tool in tools.items()}
    if not any(claimed.values()):
        return RuleResult.not_applicable("no tool advertises scope metadata")
    broad = sorted(
        f"{name}: {scope}"
        for name, scopes in claimed.items()
        for scope in sorted(scopes)
        if _WILDCARD.search(scope)
    )
    if broad:
        return RuleResult.failed(
            f"{len(broad)} wildcard scope(s): " + "; ".join(broad[:5]),
            evidence="; ".join(broad[:5]),
            key=",".join(broad),
        )
    return RuleResult.passed("no advertised scope is a wildcard")


# ---------------------------------------------------------------------------
# manifest-drift


@rule(
    id="SENTINEL/SECURITY/manifest-drift",
    title="The live manifest has no high-severity change against the snapshot",
    severity=Severity.MUST,
    rationale=(
        "A server you depend on can rewrite a tool description after you approved "
        "it, or widen what a tool is allowed to do. The change is invisible to every "
        "type signature and is the single most direct way to steer an agent through "
        "a tool you trusted. This is `sentinel diff` expressed as a rule, so a scan "
        "with --snapshot can gate on it."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Review each high-severity change in `sentinel diff`. If you accept it, take "
        "a new snapshot with `sentinel snapshot`; if you do not, stop using the server "
        "until the change is explained."
    ),
    introduced_in="0.4.0",
)
def manifest_drift(probe: Probe) -> RuleResult:
    from sentinel.snapshot import Level, Snapshot, capture, diff

    baseline = probe.context.get("snapshot")
    if not isinstance(baseline, Snapshot):
        return RuleResult.not_applicable(
            "no snapshot was supplied; pass --snapshot to compare against one"
        )
    try:
        live = capture(probe)
    except Exception as exc:
        return RuleResult.indeterminate(f"the live manifest could not be read: {exc}")
    high = [c for c in diff(baseline, live) if c.level is Level.HIGH]
    if high:
        return RuleResult.failed(
            f"{len(high)} high-severity change(s) since {baseline.captured_at}: "
            + "; ".join(f"{c.kind.value} {c.tool}" for c in high[:5]),
            evidence="; ".join(f"{c.kind.value} {c.tool}: {c.detail}" for c in high[:5]),
            key=",".join(sorted(f"{c.kind.value}:{c.tool}" for c in high)),
        )
    return RuleResult.passed("no high-severity change since the snapshot")


# ---------------------------------------------------------------------------
# tls-posture

#: A certificate this close to expiry fails the rule: not because it has expired
#: but because the next scan will find that it has.
CERT_EXPIRY_WARNING_DAYS = 14


def certificate_problem(cert: dict[str, Any], now: datetime.datetime | None = None) -> str | None:
    """What is wrong with a peer certificate as returned by `ssl.getpeercert()`."""
    stamp = cert.get("notAfter")
    if not isinstance(stamp, str):
        return "the certificate carries no expiry"
    expires = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(stamp), datetime.UTC)
    current = now or datetime.datetime.now(datetime.UTC)
    remaining = expires - current
    if remaining.total_seconds() < 0:
        return f"the certificate expired {expires:%Y-%m-%d}"
    if remaining.days < CERT_EXPIRY_WARNING_DAYS:
        return f"the certificate expires {expires:%Y-%m-%d}, in {remaining.days} day(s)"
    return None


_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _is_loopback(host: str) -> bool:
    return host in {"localhost", "::1"} or host.startswith("127.")


@rule(
    id="SENTINEL/SECURITY/tls-posture",
    title="The endpoint uses TLS 1.2 or later with a valid, unexpiring certificate",
    severity=Severity.MUST,
    rationale=(
        "The specification's authorization model assumes the transport is protected, "
        "but conformance does not require it to be. A bearer token sent over cleartext "
        "or to a host whose certificate does not verify is a token anyone on the path "
        "can use."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Serve the endpoint over HTTPS with TLS 1.2 or later and a certificate that "
        "verifies for its hostname, renewed well before it expires. Loopback addresses "
        "are exempt from the TLS requirement."
    ),
    introduced_in="0.4.0",
)
def tls_posture(probe: Probe) -> RuleResult:
    parts = urlsplit(probe.endpoint)
    host = parts.hostname or ""
    if parts.scheme != "https":
        if _is_loopback(host):
            return RuleResult.not_applicable("loopback endpoint; TLS is not required")
        return RuleResult.failed(
            f"{probe.endpoint} is not HTTPS; a bearer token sent to it is readable on the path",
            evidence=f"scheme {parts.scheme!r}",
            key="cleartext",
        )
    verify = probe._transport.verify  # a rule reads the trust the scan was given
    if verify is False:
        return RuleResult.indeterminate(
            "certificate checks are disabled for this scan (--insecure), so the "
            "certificate cannot be assessed"
        )
    context = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    port = parts.port or 443
    try:
        with (
            socket.create_connection((host, port), timeout=probe._transport.timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            protocol = tls.version() or ""
            cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        return RuleResult.failed(
            f"the certificate does not verify for {host}: {exc.verify_message}",
            evidence=str(exc.verify_message),
            key="certificate-invalid",
        )
    except (OSError, ssl.SSLError) as exc:
        return RuleResult.indeterminate(f"the TLS handshake could not be completed: {exc}")
    if protocol in _WEAK_PROTOCOLS:
        return RuleResult.failed(
            f"the connection negotiated {protocol}", evidence=protocol, key="weak-protocol"
        )
    problem = certificate_problem(cert)
    if problem:
        return RuleResult.failed(problem, evidence=problem, key="certificate-expiry")
    return RuleResult.passed(f"{protocol} with a certificate that verifies and is not near expiry")
