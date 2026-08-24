"""The conformance rule catalog.

Importing this package registers every rule. `sentinel scan` and
`sentinel catalog validate` both import it and then read REGISTRY, so there is
one list and no way for a rule to exist without being validated.
"""

from __future__ import annotations

from sentinel.catalog import must, should
from sentinel.catalog.base import (
    REGISTRY,
    BaseRule,
    Namespace,
    Outcome,
    Registry,
    RuleResult,
    Severity,
    Verifiability,
    validate_registry,
)

__all__ = [
    "REGISTRY",
    "BaseRule",
    "Namespace",
    "Outcome",
    "Registry",
    "RuleResult",
    "Severity",
    "Verifiability",
    "must",
    "should",
    "validate_registry",
]
