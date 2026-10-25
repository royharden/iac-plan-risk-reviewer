"""Run only reviewer-owned public eval regression paths from any working directory."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "src", ROOT / "tests/eval"):
    sys.path.insert(0, str(path))


def main():
    import pytest

    # An isolated, newly created root avoids pytest's shared-user temp retention
    # touching other agents' artifacts. The pytest child path does not yet exist.
    scratch = Path(tempfile.mkdtemp(prefix="m4-rv2-eval-")) / "cases"
    return pytest.main(
        [
            "--import-mode=importlib",
            "-p",
            "no:cacheprovider",
            "-q",
            "--tb=short",
            f"--basetemp={scratch}",
            str(ROOT / "tests/eval"),
            str(ROOT / "tests/corpus"),
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
