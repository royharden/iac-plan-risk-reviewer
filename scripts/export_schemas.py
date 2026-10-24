"""Explicit fixed-registry schema exporter. No application loading on import."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from time import monotonic


def _registry():
    import sys
    root = Path(__file__).resolve().parents[1]
    for directory in (root, root / "src"):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    from eval.runner import schema_registry
    return schema_registry


def boundary_models() -> dict:
    """Legacy callable retained; fixed actual types, no plugin/module option."""
    return _registry().boundary_models()


def schema_bundle() -> dict[str, bytes]:
    """Legacy callable retained; descriptions only, never payload admission."""
    return _registry().schema_documents(boundary_models())


def _bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def _check_path(path: Path) -> None:
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
           for p in (path, *path.parents)):
        raise ValueError("schema destination traverses link/junction")


def export_schemas(out: Path) -> dict:
    """Future explicit local generation. Fresh output only, COMPLETE last."""
    out = Path(out).absolute()
    _check_path(out)
    if ".." in out.parts or str(out).startswith("\\\\") or out.exists():
        raise ValueError("schema destination must be fresh and local")
    if not out.parent.is_dir():
        raise ValueError("schema destination parent must already exist")
    deadline = monotonic() + 30

    def check():
        _check_path(out)
        if monotonic() >= deadline:
            raise ValueError("schema export cooperative deadline")

    check()
    files = schema_bundle()  # All type/schema failures precede destination creation.
    catalogue = _bytes(_registry().catalogue())
    expected = {entry.stable_id + ".schema.json" for entry in _registry().declarations()}
    if set(files) != expected:
        raise ValueError("missing or unexpected required completed schema")
    if len(files) > 128 or sum(len(data) for data in files.values()) > 16 * 1024 * 1024:
        raise ValueError("schema export bound exceeded")
    # Version 2 extends the legacy file-hash manifest with a separate catalogue pin.
    # Existing --out and Python callable signatures/file IDs remain unchanged.
    manifest = {"schema_version": 2, "schema_mode": "validation", "schema_only": True,
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
                "catalogue": {"file": "catalogue.json", "sha256": hashlib.sha256(catalogue).hexdigest()},
                "payload_admission": False, "execution_verified": False,
                "actor_authenticated": False, "provider_activated": False,
                "release_authorized": False, "product_acceptance": False,
                "limitations": list(_registry().LIMITATIONS)}
    data = {**files, "catalogue.json": catalogue, "manifest.json": _bytes(manifest)}
    if sum(len(raw) for raw in data.values()) > 16 * 1024 * 1024:
        raise ValueError("schema export controls exceed byte cap")
    check()
    out.mkdir(exist_ok=False)
    created = []
    marker = out / "schema-export-state.json"

    def write(path, raw):
        check()
        if path.parent != out:
            raise ValueError("schema filename escaped destination")
        _check_path(path)
        with path.open("xb") as stream:
            created.append(path)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    write(marker, _bytes({"state": "ABORTED"}))
    try:
        for name, raw in data.items():
            write(out / name, raw)
        pending = out / ".schema-export-state.pending"
        write(pending, _bytes({"state": "COMPLETE", "schema_only": True}))
        check()
        os.replace(pending, marker)
    except BaseException:
        for path in reversed(created):
            if path != marker:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
        raise
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        export_schemas(args.out)
    except (ValueError, OSError, TypeError, ImportError, RecursionError):
        parser.exit(2, "schema export refused\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
