"""Independent in-memory finite DATA graph. No namespace/trust is installed."""

from copy import deepcopy
from functools import lru_cache
from pathlib import Path, PureWindowsPath

from . import fixture_data as data

LANE = PureWindowsPath(r"C:\INERT-ORIGIN-DATA-RV3\source")
DOCUMENTS = PureWindowsPath(r"C:\INERT-ORIGIN-DATA-RV3\documents")
INVOCATION = r"C:\INERT-EXTERNAL-DATA-RV3\invocation.json"
LAUNCHER = r"C:\INERT-EXTERNAL-DATA-RV3\launcher.py"
HARNESS = b"PUBLIC INERT HARNESS DATA, NOT EXECUTABLE AUTHORITY\n"
LAUNCHER_DATA = b"PUBLIC INERT LAUNCHER DATA, NEVER EXECUTED\n"
EXECUTABLES = {
    r"C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-RV2-eval-db\.venv\Scripts\python.exe": "7f06d4ab8afee27a5fe6a273ef621758290ecbc2f7461ebaf554433efd850e5d",
    r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe": "60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe": "60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f",
}


@lru_cache(maxsize=3)
def binary_data(path):
    """Only fixed public executable bytes, read as DATA, never executed here."""
    assert path in EXECUTABLES
    raw = Path(path).read_bytes()
    assert data.sha(raw) == EXECUTABLES[path]
    return raw


class OriginCase:
    def __init__(self, metadata_type):
        self.metadata_type = metadata_type
        self.manifest, self.grant, self.invocation, _ = data.original_documents(
            {"context.py": data.sha(HARNESS)}
        )
        root = self.manifest["runroot"]
        self.ownership = {
            "schema": "legacy103-runtime-ownership-v1",
            "runroot": root,
            "source_commit": self.manifest["source_commit"],
            "source_tree": self.manifest["source_tree"],
        }
        self.anchor = {
            "schema": "legacy103-runtime-anchor-v1",
            "manifest_sha256": "",
            "grant_sha256": "",
            "source_commit": self.manifest["source_commit"],
            "source_tree": self.manifest["source_tree"],
            "runroot": root,
        }
        self.invocation.update(launcher_path=LAUNCHER, launcher_sha256=data.sha(LAUNCHER_DATA))
        self.process = {
            "pid": 101,
            "parent_pid": 102,
            "image": self.manifest["interpreter"]["path"],
            "image_sha256": self.manifest["interpreter"]["sha256"],
            "argv": ["PUBLIC-INERT-DATA-ONLY"],
            "environment": {"PUBLIC_INERT_DATA": "true"},
            "cwd": self.manifest["snapshot"],
        }
        self.facts = {
            "schema": "legacy103-external-root-facts-runtime-v1",
            "invocation_path": INVOCATION,
            "invocation_sha256": "",
            "manifest_path": str(DOCUMENTS / "manifest.json"),
            "grant_path": str(DOCUMENTS / "grant.json"),
            "anchor_path": str(DOCUMENTS / "anchor.json"),
            "source_directory": str(LANE),
            "ownership_path": str(PureWindowsPath(root) / "OWNERSHIP.json"),
            "ownership_sha256": "",
            "process": deepcopy(self.process),
        }
        self.rebind()

    def rebind(self):
        """Refresh DATA digest edges only; never repair semantic mutations."""
        self.ownership_raw = data.canonical(self.ownership)
        self.manifest["namespace_ownership_sha256"] = data.sha(self.ownership_raw)
        self.manifest_raw = data.canonical(self.manifest)
        self.grant["manifest_sha256"] = data.sha(self.manifest_raw)
        self.grant_raw = data.canonical(self.grant)
        self.anchor.update(
            manifest_sha256=data.sha(self.manifest_raw), grant_sha256=data.sha(self.grant_raw)
        )
        self.anchor_raw = data.canonical(self.anchor)
        self.invocation.update(
            manifest_sha256=data.sha(self.manifest_raw),
            grant_sha256=data.sha(self.grant_raw),
            anchor_sha256=data.sha(self.anchor_raw),
        )
        self.invocation_raw = data.canonical(self.invocation)
        self.facts.update(
            invocation_sha256=data.sha(self.invocation_raw),
            ownership_sha256=data.sha(self.ownership_raw),
        )
        self.facts_raw = data.canonical(self.facts)
        self.files = {
            self.facts["manifest_path"]: self.manifest_raw,
            self.facts["grant_path"]: self.grant_raw,
            self.facts["anchor_path"]: self.anchor_raw,
            self.facts["invocation_path"]: self.invocation_raw,
            self.facts["ownership_path"]: self.ownership_raw,
            str(LANE / "context.py"): HARNESS,
            LAUNCHER: LAUNCHER_DATA,
        }
        for path in EXECUTABLES:
            self.files[path] = binary_data(path)
        self.digests = {
            (
                str(PureWindowsPath(self.manifest["snapshot"]).joinpath(*name.split("/"))),
                row["bytes"],
            ): row["sha256"]
            for name, row in self.manifest["closure32"].items()
        }
        self.rows, self.calls, self.digest_calls = {}, [], []
        self.changed_after_read = set()
        self.read_paths = set()

    def metadata(self, path):
        self.calls.append(("metadata", path))
        if path in self.rows:
            return self.rows[path]
        kind = "file" if path in self.files else "directory"
        identity = (
            "changed-" if path in self.changed_after_read and path in self.read_paths else "stable-"
        ) + data.sha(path.encode())[:20]
        return self.metadata_type(path, kind, identity)

    def read_file(self, path, cap):
        self.calls.append(("read_file", path, cap))
        assert path in self.files, "unexpected inert read"
        raw = self.files[path]
        assert len(raw) <= cap
        self.read_paths.add(path)
        return raw

    def file_digest(self, path, size):
        self.digest_calls.append((path, size))
        assert (path, size) in self.digests, "unexpected inert source32 digest"
        return self.digests[path, size]

    def serialize_facts(self):
        self.facts_raw = data.canonical(self.facts)
        return self.facts_raw
