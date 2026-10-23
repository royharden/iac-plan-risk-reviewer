"""Read-only private evidence/bundle verifier; no browser, provider or fetch."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).absolute().parents[1] / "src"))

from iac_review.source_view import main


if __name__ == "__main__":
    raise SystemExit(main())
