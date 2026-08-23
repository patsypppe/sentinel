"""The two fixture servers: the harness's own oracle.

`docs/HANDOFF.md` §9.5. RECALL is the fraction of the non-conformant fixture's
seeded violations the harness detects; the FALSE-POSITIVE RATE is the count of
failures it reports against the conformant one, which must be zero.

They are a package so the harness's tests can import `SEEDED_VIOLATIONS` — the
denominator of the recall measurement — rather than re-deriving it. They import
nothing from `sentinel`, deliberately: a fixture sharing code with the harness
would let a bug in the shared part hide itself from both sides.
"""

from __future__ import annotations

__all__ = ["common", "conformant", "nonconformant"]
