"""The Python half of the cross-language tokenizer contract.

`sentinel.tokens` is a port of `broker/internal/registry/tokens.go`. Two
implementations of one method is exactly the situation where a published number
drifts silently, so both sides are held to one committed corpus:
`tests/harness/data/tokenizer_corpus.jsonl` carries the text and the count Go
produced for it, `TestTokenizerCorpus` asserts Go still agrees, and this module
asserts the port does.

The corpus is not a smoke test. It is built from the divergence classes between
Python's `str` predicates and Go's `unicode` predicates, because the obvious
port is wrong on real input: see `test_the_naive_port_would_have_been_wrong`,
which keeps the reason for this module's existence falsifiable rather than
merely documented in its docstring.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.tokens import TOKENIZER_NAME, estimate_tokens

pytestmark = pytest.mark.unit

CORPUS = Path(__file__).parent / "data" / "tokenizer_corpus.jsonl"


def _corpus() -> list[dict[str, object]]:
    # Split on "\n" rather than with str.splitlines(): the corpus deliberately
    # contains U+0085 NEL and U+2028/U+2029, which splitlines() treats as line
    # boundaries and Go's JSON encoder emits unescaped. Using splitlines() here
    # tears those very rows in half and the corpus fails to parse.
    rows = [
        json.loads(line) for line in CORPUS.read_text(encoding="utf-8").split("\n") if line.strip()
    ]
    assert rows, "corpus is empty; every assertion below would pass vacuously"
    return rows


def _naive_estimate(text: str) -> int:
    """The port this module exists to prevent.

    Uses `str.isspace` / `str.isalpha` / `str.isdigit`, which is what anyone
    writing this port from the Go source by eye would reach for.
    """
    total = 0
    run = 0

    def flush() -> None:
        nonlocal total, run
        if run:
            total += 1
            if run > 4:
                total += (run - 1) // 4
            run = 0

    for ch in text:
        if ch.isspace():
            flush()
        elif ch.isalpha() or ch.isdigit() or ch == "_":
            run += 1
        else:
            flush()
            total += 1
    flush()
    return total


def test_the_port_matches_go_on_every_corpus_case() -> None:
    rows = _corpus()
    mismatches = [
        (row["why"], estimate_tokens(str(row["text"])), row["expected"])
        for row in rows
        if estimate_tokens(str(row["text"])) != row["expected"]
    ]
    assert not mismatches, (
        f"{len(mismatches)} of {len(rows)} cases disagree with Go: {mismatches[:5]}"
    )


def test_the_naive_port_would_have_been_wrong() -> None:
    """The failing direction: a corpus that cannot fail proves nothing.

    If this test ever passes with a low mismatch count, the corpus has lost the
    Unicode cases that make the port non-trivial, and
    `test_the_port_matches_go_on_every_corpus_case` has stopped being evidence.
    """
    rows = _corpus()
    wrong = sum(1 for row in rows if _naive_estimate(str(row["text"])) != row["expected"])
    assert wrong > len(rows) // 4, (
        "the corpus no longer distinguishes the naive port from the correct one; "
        f"only {wrong} of {len(rows)} cases differ"
    )


@pytest.mark.parametrize(
    ("text", "expected", "why"),
    [
        ("", 0, "nothing costs nothing"),
        ("abcd", 1, "a run at the amortization threshold is one token"),
        ("abcde", 2, "one character over charges a second"),
        ("_", 1, "underscore is a run, not punctuation"),
        ("{}", 2, "punctuation is one token each"),
        ("a b", 2, "whitespace separates runs and is itself free"),
    ],
)
def test_documented_boundaries(text: str, expected: int, why: str) -> None:
    assert estimate_tokens(text) == expected, why


def test_the_tokenizer_name_matches_the_broker() -> None:
    """Every number either side publishes must be attributable to one method."""
    go_source = (
        Path(__file__).parents[2] / "broker" / "internal" / "registry" / "tokens.go"
    ).read_text(encoding="utf-8")
    assert f'TokenizerName = "{TOKENIZER_NAME}"' in go_source
