"""Load bounded, approved test email copy from locale resources only."""

import json
from pathlib import Path


def trigger_test_copy(locale: str) -> dict[str, str]:
    if locale not in {"en", "zh-CN"}:
        raise ValueError("The test notification locale is unsupported")
    path = Path(__file__).parent / "locales" / f"trigger-test.{locale}.json"
    return json.loads(path.read_text(encoding="utf-8"))
