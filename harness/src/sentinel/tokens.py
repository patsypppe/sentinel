"""The sentinel/approx-v1 tokenizer, ported from the broker.

This is a byte-for-byte port of `broker/internal/registry/tokens.go`. It exists
so the harness can price a *foreign* server's tool manifest without a Go
toolchain: the broker can only tokenize the manifest it was compiled with, and
the harness ships two dependencies on purpose (httpx, typer), so shelling out to
a Go binary is not available to it.

TOKENIZER: a deterministic, dependency-free approximation, NOT a model
tokenizer. It splits on whitespace and punctuation boundaries the way BPE
vocabularies tend to, then charges one token per resulting run and one per four
characters of any run longer than four. On JSON manifests this lands within
roughly 10% of cl100k_base. That tolerance is fine for a before/after
comparison, and it is the reason every budget in this module is an explicit
operator-supplied number rather than a default this project would be inventing.

WHY NOT str.isalpha / str.isdigit / str.isspace
-----------------------------------------------
The obvious port is wrong, and wrong on real input rather than in theory.
Python's `str` predicates and Go's `unicode` predicates disagree on 132
codepoints:

  * 128 where Python says digit-or-alpha and Go says neither. All of them are
    category `No` (U+00B2 SUPERSCRIPT TWO, U+2070, the Ethiopic numerals at
    U+1369..U+1371, ...). Go's `unicode.IsDigit` is category `Nd` only, while
    `str.isdigit()` also admits `No`.
  * 4 where Python says space and Go says not: U+001C..U+001F, the file, group,
    record and unit separators. Those are category `Cc`; Go's `unicode.IsSpace`
    lists its whitespace explicitly and does not include them.

Over 5,000 Unicode-heavy fuzz inputs the naive port disagreed with Go on 2,805
of them. Branching on `unicodedata.category` instead reproduces Go exactly.
`tests/harness/test_tokens.py` holds that to a committed differential corpus, so
this claim is checked rather than asserted.
"""

from __future__ import annotations

import unicodedata

__all__ = ["TOKENIZER_NAME", "estimate_tokens"]

#: Printed next to every number this module produces, exactly as the broker
#: prints it, so a figure from either side is attributable to one method.
TOKENIZER_NAME = "sentinel/approx-v1"

#: The amortized cost of a run longer than this many characters.
_CHARS_PER_TOKEN = 4

#: Go's `unicode.IsSpace` for the Latin-1 range, enumerated. Everything above
#: it that Go treats as space is category `Z*`, handled below. Listing these
#: explicitly is what excludes U+001C..U+001F, which `str.isspace()` would
#: wrongly admit.
_GO_SPACE = frozenset("\t\n\v\f\r \x85\xa0")


def estimate_tokens(text: str) -> int:
    """Count tokens in `text` under TOKENIZER_NAME.

    Mirrors `estimate()` in broker/internal/registry/tokens.go: whitespace ends
    a run, letters/digits/underscore extend it, and anything else is its own
    token, which is how JSON's braces, quotes and colons actually price out.
    """
    total = 0
    run_len = 0

    for ch in text:
        category = unicodedata.category(ch)
        if ch in _GO_SPACE or category.startswith("Z"):
            # unicode.IsSpace: flush the run, the separator itself is free.
            if run_len:
                total += 1
                if run_len > _CHARS_PER_TOKEN:
                    total += (run_len - 1) // _CHARS_PER_TOKEN
                run_len = 0
        elif category.startswith("L") or category == "Nd" or ch == "_":
            # unicode.IsLetter or unicode.IsDigit or '_': extend the run.
            run_len += 1
        else:
            # Punctuation, symbols, control characters and category-No digits
            # are each their own token.
            if run_len:
                total += 1
                if run_len > _CHARS_PER_TOKEN:
                    total += (run_len - 1) // _CHARS_PER_TOKEN
                run_len = 0
            total += 1

    if run_len:
        total += 1
        if run_len > _CHARS_PER_TOKEN:
            total += (run_len - 1) // _CHARS_PER_TOKEN

    return total
