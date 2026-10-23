"""Explicit offline share export entrypoint; not run during source construction."""
from __future__ import annotations


def main(argv=None):
    from iac_review.shareable_export import main as export_main
    return export_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
