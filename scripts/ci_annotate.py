#!/usr/bin/env python3
"""Turn a pytest JUnit report into GitHub annotations.

A failing job's log is a wall of text behind a click. An annotation is the failing test's
name and the first lines of why, on the run's summary page and in the checks API, which
is also what lets someone without access to the raw log see what broke.

    python scripts/ci_annotate.py pytest-report.xml
"""

from __future__ import annotations

import sys
from xml.etree import ElementTree as ET


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(path: str) -> int:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"::error title=no pytest report::{escape(str(exc))}")
        return 0
    failures = 0
    for case in root.iter("testcase"):
        for kind in ("failure", "error"):
            node = case.find(kind)
            if node is None:
                continue
            failures += 1
            name = f"{case.get('classname', '')}::{case.get('name', '')}"
            body = (node.get("message") or "") + "\n" + (node.text or "")
            print(f"::error title={escape(name)}::{escape(body.strip()[:900])}")
    print(f"{failures} failing test(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
