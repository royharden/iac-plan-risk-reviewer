"""Explicit local operator tool. No default mutation, stale-lock stealing or provider calls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).absolute().parents[1] / "src"))

from iac_review.ledger_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
