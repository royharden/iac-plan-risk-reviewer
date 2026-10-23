"""Synthetic fake-only D/L/P/M plumbing; no live provider adapter or measurement."""
from pathlib import Path
import sys

# Resolve from this script, without changing cwd or installing anything. The
# development eval package deliberately stays outside the product wheel.
_root = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(_root / "src"))
sys.path.insert(0, str(_root))

from eval.model.driver import main


if __name__ == "__main__":
    raise SystemExit(main())
