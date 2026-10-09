from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
REPO_ROOTED_FMB = re.compile(
    r"(?:ROOT|PROJECT_ROOT|REPO_ROOT|parents\[\d\]\)?)\s*(?:\n\s*)?/\s*\"\.fmb/"
)


def _opted_in(text: str) -> bool:
    return "pytest.mark.external" in text and "FMB_RETAINED_RECORDS" in text


def test_default_tests_do_not_open_retained_records() -> None:
    offenders = []
    for path in sorted(TESTS.rglob("test_*.py")):
        if path == Path(__file__):
            continue
        text = path.read_text(encoding="utf-8")
        if REPO_ROOTED_FMB.search(text) and not _opted_in(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"tests opening .fmb/ without the external opt-in: {offenders}"

