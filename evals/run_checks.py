"""Run only reviewer-owned public eval regression paths from any working directory."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "src", ROOT / "tests/eval"):
    sys.path.insert(0, str(path))


def main():
    import pytest

    return pytest.main(
        [
            "--import-mode=importlib",
            "-p",
            "no:cacheprovider",
            "-q",
            "--tb=short",
            str(ROOT / "tests/eval"),
            str(ROOT / "tests/corpus"),
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
