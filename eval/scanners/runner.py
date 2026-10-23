"""Opt-in scanner capture boundary; never imported by the default product path.

Construction only: no runner in this module was executed during Dirty Mode.
Injected runners are trusted dependencies, not user-supplied commands. Fake receipts
are never eligible for live evidence, including when their JSON is well formed.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Literal, Protocol

if TYPE_CHECKING:
    from .artifacts import Capture, Mapping

Arm = Literal["C", "C-custom", "T"]
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CHECK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
ACTIONS = {("no-op",), ("create",), ("read",), ("update",), ("delete",),
           ("delete", "create"), ("create", "delete")}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_read(path: Path, cap: int) -> bytes:
    """Reject direct symlinks, directories and over-cap streams before JSON parsing."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular file required")
    with path.open("rb") as stream:
        data = stream.read(cap + 1)
    if len(data) > cap:
        raise ValueError("file byte cap exceeded")
    return data


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(_: str) -> object:
    raise ValueError("non-finite JSON constant")


def strict_json(data: bytes) -> object:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=_nonfinite)


@dataclass(frozen=True)
class Limits:
    timeout_seconds: float = 30.0
    stdout_bytes: int = 2 * 1024 * 1024
    stderr_bytes: int = 256 * 1024
    plan_bytes: int = 16 * 1024 * 1024
    max_observations: int = 50_000

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 300:
            raise ValueError("timeout must be finite and at most 300 seconds")
        for value, maximum in ((self.stdout_bytes, 8 * 1024 * 1024),
                               (self.stderr_bytes, 1024 * 1024),
                               (self.plan_bytes, 16 * 1024 * 1024),
                               (self.max_observations, 100_000)):
            if type(value) is not int or not 0 < value <= maximum:
                raise ValueError("capture limit outside hard bound")


@dataclass(frozen=True)
class ScannerPin:
    executable: Path
    version: str | None = None
    executable_sha256: str | None = None
    dependency_manifest_sha256: str | None = None
    version_evidence_sha256: str | None = None
    dependency_manifest_path: Path | None = None
    version_evidence_path: Path | None = None

    def missing(self) -> tuple[str, ...]:
        failures = []
        if not self.executable.is_absolute():
            failures.append("absolute_executable_required")
        if self.executable.suffix.lower() in {".bat", ".cmd", ".ps1", ".sh"}:
            failures.append("shell_wrapper_forbidden")
        if not isinstance(self.version, str) or not self.version.strip():
            failures.append("missing_scanner_version")
        for label, value in (("executable", self.executable_sha256),
                             ("dependencies", self.dependency_manifest_sha256),
                             ("version_evidence", self.version_evidence_sha256)):
            if not isinstance(value, str) or not SHA256.fullmatch(value):
                failures.append("missing_or_invalid_" + label + "_pin")
        if self.dependency_manifest_path is None or self.version_evidence_path is None:
            failures.append("missing_provenance_files")
        return tuple(failures)


@dataclass(frozen=True)
class Invocation:
    argv: tuple[str, ...]
    cwd: Path
    environment: tuple[tuple[str, str], ...]
    limits: Limits
    # Rechecked immediately before and after every trusted runner invocation.
    pinned_files: tuple[tuple[Path, str, int], ...]

    def verify(self) -> None:
        if not self.argv or not Path(self.argv[0]).is_absolute():
            raise ValueError("absolute pinned scanner command required")
        if not self.cwd.is_absolute() or not self.cwd.is_dir() or self.cwd.is_symlink():
            raise ValueError("caller-owned absolute scratch directory required")
        if len(dict(self.environment)) != len(self.environment):
            raise ValueError("duplicate environment key")
        for path, expected, cap in self.pinned_files:
            if not path.is_absolute() or digest(bounded_read(path, cap)) != expected:
                raise ValueError("pinned scanner input changed")


def invocation_digest(invocation: Invocation) -> str:
    """Exact local command/environment/files/bounds fingerprint, no execution."""
    return digest(json.dumps({"argv": invocation.argv, "cwd": str(invocation.cwd),
                              "environment": invocation.environment,
                              "limits": asdict(invocation.limits),
                              "files": [(str(path), sha, cap)
                                        for path, sha, cap in invocation.pinned_files]},
                             sort_keys=True, separators=(",", ":")).encode())


@dataclass(frozen=True)
class ApprovedInvocation:
    arm: Arm
    scanner_name: Literal["checkov", "trivy"]
    scanner_version: str
    plan_sha256: str
    executable_sha256: str
    dependency_manifest_sha256: str
    version_evidence_sha256: str
    config_sha256: str
    policy_sha256: str
    invocation_sha256: str
    check_ids: tuple[str, ...]


@dataclass(frozen=True)
class LocalExecutionGrant:
    grant_id: str
    operator_id: str
    build_sha256: str
    comparison_manifest_sha256: str
    invocations: tuple[ApprovedInvocation, ...]
    approved_bytes_sha256: str


def manifest_digest(manifest: dict) -> str:
    return digest(json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode())


def load_execution_grant(path: Path, *, expected_sha256: str, manifest: dict) -> LocalExecutionGrant:
    """Expected digest comes from the operator, never from the submitted grant.

    This verifies a bounded explicit instruction, not the identity/truthfulness
    of its author or OS confinement. No scanner/process probe occurs here.
    """
    raw = bounded_read(path, 256 * 1024)
    if not SHA256.fullmatch(expected_sha256) or digest(raw) != expected_sha256:
        raise ValueError("operator execution grant differs from its external pin")
    value = strict_json(raw)
    flags = {"dirty_mode_closed", "local_only", "network_denied", "descendants_confined",
             "no_provider_credentials", "synthetic_input_attested"}
    keys = {"schema_version", "grant_id", "operator_id", "build_sha256",
            "comparison_manifest_sha256", "invocations"} | flags
    if (not isinstance(value, dict) or set(value) != keys
            or value["schema_version"] != "m4-local-scanner-execution-grant-v1"
            or any(value[flag] is not True for flag in flags)
            or manifest.get("input_scope") != "development_synthetic"
            or manifest.get("synthetic_input_attested") is not True
            or value["build_sha256"] != manifest.get("build_sha256")
            or value["comparison_manifest_sha256"] != manifest_digest(manifest)):
        raise ValueError("execution grant scope/mode/synthetic attestation mismatch")
    if not isinstance(value["build_sha256"], str) or not SHA256.fullmatch(value["build_sha256"]):
        raise ValueError("exact build pin required")
    for key in ("grant_id", "operator_id"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value[key]):
            raise ValueError("opaque operator/grant identity required")
    declarations = value["invocations"]
    if not isinstance(declarations, list) or not 0 < len(declarations) <= 768:
        raise ValueError("bounded explicit invocation approvals required")
    approved, seen = [], set()
    for item in declarations:
        if not isinstance(item, dict) or set(item) != set(ApprovedInvocation.__dataclass_fields__):
            raise ValueError("closed invocation approval required")
        item = dict(item)
        if not isinstance(item["check_ids"], list):
            raise ValueError("explicit check array required")
        item["check_ids"] = tuple(item["check_ids"])
        record = ApprovedInvocation(**item)
        if (record.arm not in {"C", "C-custom", "T"}
                or record.scanner_name != ("trivy" if record.arm == "T" else "checkov")
                or not isinstance(record.scanner_version, str) or not record.scanner_version
                or len(record.scanner_version) > 128 or not record.check_ids
                or len(record.check_ids) != len(set(record.check_ids))
                or any(not isinstance(check, str) or not CHECK_ID.fullmatch(check) for check in record.check_ids)):
            raise ValueError("invalid approved scanner profile")
        for name in ("plan_sha256", "executable_sha256", "dependency_manifest_sha256",
                     "version_evidence_sha256", "config_sha256", "policy_sha256", "invocation_sha256"):
            pin = getattr(record, name)
            if not isinstance(pin, str) or not SHA256.fullmatch(pin):
                raise ValueError("exact invocation pins required")
        if record.invocation_sha256 in seen:
            raise ValueError("duplicate invocation approval")
        seen.add(record.invocation_sha256)
        approved.append(record)
    return LocalExecutionGrant(value["grant_id"], value["operator_id"], value["build_sha256"],
                               value["comparison_manifest_sha256"], tuple(approved), expected_sha256)


def _local_profile(invocation: Invocation, approved: ApprovedInvocation) -> None:
    """Hard allowlist in addition to the exact operator-approved fingerprint."""
    argv = invocation.argv
    switches = {"--compact", "--skip-download", "--skip-results-upload"} if approved.scanner_name == "checkov" else {
        "--include-non-failures", "--skip-check-update", "--disable-telemetry", "--skip-version-check"}
    pairs = ({"--file", "--framework", "--output", "--check", "--config-file", "--download-external-modules",
              "--external-checks-dir"} if approved.scanner_name == "checkov" else
             {"--format", "--config", "--misconfig-scanners", "--exit-code", "--ignorefile", "--timeout", "--cache-dir"})
    options, index, target = {}, 1, None
    if approved.scanner_name == "trivy":
        if len(argv) < 2 or argv[1] != "config":
            raise PermissionError("only Trivy config is allowed")
        index = 2
    while index < len(argv):
        key = argv[index]
        if key == "--" and approved.scanner_name == "trivy" and index == len(argv) - 2:
            target = argv[index + 1]
            break
        if key in options:
            raise PermissionError("duplicate scanner option")
        if key in switches:
            options[key] = True
            index += 1
        elif key in pairs and index + 1 < len(argv):
            options[key] = argv[index + 1]
            index += 2
        else:
            raise PermissionError("unapproved command, cloud, enrichment or plugin option")
    required = ({"--framework": "terraform_plan", "--output": "json",
                 "--check": ",".join(approved.check_ids), "--download-external-modules": "false"}
                if approved.scanner_name == "checkov" else
                {"--format": "json", "--misconfig-scanners": "terraformplan-json", "--exit-code": "1",
                 "--ignorefile": "", "--timeout": f"{invocation.limits.timeout_seconds:g}s",
                 "--cache-dir": str(invocation.cwd)})
    if any(options.get(key) != value for key, value in required.items()) or any(
            options.get(key) is not True for key in switches):
        raise PermissionError("fixed offline scanner options required")
    target = options.get("--file") if approved.scanner_name == "checkov" else target
    config = options.get("--config-file" if approved.scanner_name == "checkov" else "--config")
    file_pins = {str(path): sha for path, sha, _ in invocation.pinned_files}
    if (file_pins.get(argv[0]) != approved.executable_sha256
            or file_pins.get(target) != approved.plan_sha256 or file_pins.get(config) != approved.config_sha256
            or any(pin not in file_pins.values() for pin in (approved.dependency_manifest_sha256,
                   approved.version_evidence_sha256, approved.policy_sha256))):
        raise PermissionError("approved input/installation/config/policy files differ")
    version_files = [path for path, sha, _ in invocation.pinned_files if sha == approved.version_evidence_sha256]
    version = strict_json(bounded_read(version_files[0], 64 * 1024))
    if not isinstance(version, dict) or any(version.get(key) != expected for key, expected in (
            ("scanner_name", approved.scanner_name), ("version", approved.scanner_version),
            ("executable_sha256", approved.executable_sha256),
            ("dependency_manifest_sha256", approved.dependency_manifest_sha256))):
        raise PermissionError("approved version receipt differs")
    expected_env = dict(fixed_environment(invocation.cwd))
    if approved.arm == "C-custom":
        directory = options.get("--external-checks-dir")
        if not isinstance(directory, str) or not Path(directory).is_absolute():
            raise PermissionError("approved local custom policy directory required")
        expected_env.update(IAC_CUSTOM_PLAN_JSON=target, IAC_CUSTOM_PLAN_SHA256=approved.plan_sha256)
    elif "--external-checks-dir" in options:
        raise PermissionError("custom checks cannot enter a built-in arm")
    if dict(invocation.environment) != expected_env:
        raise PermissionError("only the fixed credential-free environment is permitted")


@dataclass(frozen=True)
class RunResult:
    execution_kind: Literal["fake", "live", "none"]
    exit_code: int | None
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    elapsed_seconds: float
    timed_out: bool = False
    output_truncated: bool = False
    operator_grant_sha256: str | None = None
    start_receipt_sha256: str | None = None
    terminal_receipt_sha256: str | None = None
    error_code: str | None = None


class Runner(Protocol):
    def __call__(self, invocation: Invocation) -> RunResult: ...


@dataclass(frozen=True)
class FakeRunner:
    """A caller-injected fixture, never a measured scanner or oracle."""
    stdout: bytes = field(default=b"{}", repr=False)
    stderr: bytes = field(default=b"", repr=False)
    exit_code: int | None = 0
    timed_out: bool = False

    def __call__(self, invocation: Invocation) -> RunResult:
        return RunResult("fake", self.exit_code,
                         self.stdout[:invocation.limits.stdout_bytes],
                         self.stderr[:invocation.limits.stderr_bytes], 0.0,
                         self.timed_out,
                         len(self.stdout) > invocation.limits.stdout_bytes
                         or len(self.stderr) > invocation.limits.stderr_bytes)


@dataclass(frozen=True)
class BoundedSubprocessRunner:
    """Future explicit activation only; construction does not invoke this runner.

    Captures bounded byte buffers while draining pipes concurrently. The runner
    stops the direct child on timeout/overflow. Descendant/process/network
    confinement must be provided by the later operator-owned sandbox. That
    sandbox is a prerequisite, not a property of Popen or these CLI flags.
    """
    activation_authorized: bool = False
    execution_grant: LocalExecutionGrant | None = None

    def verify_manifest(self, manifest: dict) -> None:
        grant = self.execution_grant
        if (not self.activation_authorized or grant is None
                or manifest.get("synthetic_input_attested") is not True
                or manifest.get("input_scope") != "development_synthetic"
                or manifest.get("build_sha256") != grant.build_sha256
                or manifest_digest(manifest) != grant.comparison_manifest_sha256):
            raise PermissionError("pinned operator grant for this exact synthetic manifest required")

    def approval(self, invocation: Invocation) -> ApprovedInvocation:
        if not self.activation_authorized or self.execution_grant is None:
            raise PermissionError("scanner runtime activation lacks a pinned operator grant")
        matches = [item for item in self.execution_grant.invocations
                   if item.invocation_sha256 == invocation_digest(invocation)]
        if len(matches) != 1:
            raise PermissionError("this exact scanner invocation is not approved")
        invocation.verify()
        _local_profile(invocation, matches[0])
        if any((invocation.cwd / name).exists() for name in (
                ".trivy/modules", "sitecustomize.py", "usercustomize.py")):
            raise PermissionError("unapproved plugin/module content in scanner scratch directory")
        return matches[0]

    @staticmethod
    def _receipt(path: Path, payload: dict) -> str:
        import os
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode()
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return digest(raw)

    def __call__(self, invocation: Invocation) -> RunResult:
        approved = self.approval(invocation)
        import subprocess
        import threading
        import time

        started = time.monotonic()
        grant_sha = self.execution_grant.approved_bytes_sha256
        stem = approved.invocation_sha256
        try:
            start_sha = self._receipt(invocation.cwd / (".scanner-start-" + stem + ".json"), {
                "schema_version": "m4-local-scanner-start-v1", "operator_grant_sha256": grant_sha,
                "invocation_sha256": stem, "plan_sha256": approved.plan_sha256, "arm": approved.arm})
        except FileExistsError as error:
            raise PermissionError("approved invocation already has a start receipt; no automatic retries") from error

        def finish(kind: str, code: int | None, stdout: bytes, stderr: bytes,
                   elapsed: float, timed_out: bool = False, truncated: bool = False,
                   error_code: str | None = None, process_id: int | None = None) -> RunResult:
            terminal_sha = None
            try:
                terminal_sha = self._receipt(invocation.cwd / (".scanner-terminal-" + stem + ".json"), {
                    "schema_version": "m4-local-scanner-terminal-v1", "operator_grant_sha256": grant_sha,
                    "start_receipt_sha256": start_sha, "invocation_sha256": stem,
                    "process_started": kind == "live", "process_id": process_id,
                    "raw_exit_code": code, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
                    "elapsed_seconds": elapsed, "timed_out": timed_out, "output_truncated": truncated,
                    "error_code": error_code})
            except OSError:
                error_code = "terminal_receipt_write_failed"
            return RunResult(kind, code, stdout, stderr, elapsed, timed_out, truncated,
                             grant_sha, start_sha, terminal_sha, error_code)

        try:
            proc = subprocess.Popen(list(invocation.argv), cwd=invocation.cwd,
                                    env=dict(invocation.environment), shell=False,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        except OSError:
            return finish("none", None, b"", b"", time.monotonic() - started,
                          error_code="process_start_failed")
        buffers = [bytearray(), bytearray()]
        overflow = threading.Event()
        read_error = threading.Event()

        def drain(stream, index: int, cap: int) -> None:
            try:
                while chunk := stream.read(8192):
                    available = cap - len(buffers[index])
                    buffers[index].extend(chunk[:max(0, available)])
                    if len(chunk) > available:
                        overflow.set()
            except (OSError, ValueError):
                read_error.set()

        readers = [threading.Thread(target=drain, args=(proc.stdout, 0,
                   invocation.limits.stdout_bytes), daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, 1,
                   invocation.limits.stderr_bytes), daemon=True)]
        for reader in readers:
            reader.start()
        deadline = started + invocation.limits.timeout_seconds
        timed_out = False
        try:
            while proc.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                if overflow.wait(min(0.02, max(0.0, deadline - time.monotonic()))):
                    break
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                timed_out = True
            for reader in readers:
                reader.join(timeout=max(0.0, min(1.0, deadline - time.monotonic())))
            incomplete = any(reader.is_alive() for reader in readers) or read_error.is_set()
            return finish("live", proc.returncode, bytes(buffers[0]), bytes(buffers[1]),
                          time.monotonic() - started, timed_out,
                          overflow.is_set() or incomplete, process_id=proc.pid)
        finally:
            if proc.poll() is None:
                proc.kill()
            # A descendant holding a pipe may keep a daemon reader blocked.
            # Do not call a potentially blocking close from the control thread.


@dataclass(frozen=True)
class Observation:
    check_id: str
    resource_locator: str  # Private scanner identity; never a shareable fact ID.
    status: Literal["passed", "failed", "skipped", "unknown"]


@dataclass(frozen=True)
class ScanArtifact:
    arm: Arm
    scanner_name: Literal["checkov", "trivy"]
    status: Literal["ok", "invalid", "timeout", "error", "not_run"]
    execution_kind: Literal["fake", "live", "none"]
    plan_sha256: str | None
    scanner_version: str | None
    executable_sha256: str | None
    dependency_manifest_sha256: str | None
    version_evidence_sha256: str | None
    config_sha256: str | None
    invocation_sha256: str | None
    policy_sha256: str | None
    mapping_status: Literal["verified", "unverified", "unmapped", "incompatible"]
    check_ids: tuple[str, ...]
    observations: tuple[Observation, ...] = ()
    reasons: tuple[str, ...] = ()
    raw_exit_code: int | None = None
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    elapsed_seconds: float | None = None
    output_truncated: bool = False
    source_enrichment: Literal[False] = False
    operator_grant_sha256: str | None = None
    start_receipt_sha256: str | None = None
    terminal_receipt_sha256: str | None = None

    @property
    def live_eligible(self) -> bool:
        """Capture eligibility only; never proof of exact per-cell semantics."""
        pins = (self.plan_sha256, self.executable_sha256, self.dependency_manifest_sha256,
                self.version_evidence_sha256, self.config_sha256, self.invocation_sha256,
                self.policy_sha256, self.stdout_sha256, self.stderr_sha256)
        return (self.status == "ok" and self.execution_kind == "live"
                and self.mapping_status == "verified" and not self.reasons
                and not self.output_truncated and bool(self.scanner_version)
                and bool(self.check_ids) and type(self.raw_exit_code) is int
                and self.raw_exit_code in (0, 1) and self.elapsed_seconds is not None
                and math.isfinite(self.elapsed_seconds) and self.elapsed_seconds >= 0
                and all(isinstance(value, str) and SHA256.fullmatch(value) for value in pins))

    def as_capture(self) -> Capture:
        """Explicit guarded bridge; no fake can become legacy Capture evidence."""
        if not self.live_eligible:
            raise ValueError("incomplete or simulated artifact cannot become live Capture")
        from .artifacts import Capture
        return Capture(arm=self.arm, plan_sha256=self.plan_sha256,
                       scanner_version=self.scanner_version,
                       executable_sha256=self.executable_sha256,
                       config_sha256=self.config_sha256, enabled_check_ids=self.check_ids,
                       status="ok", raw_exit_code=self.raw_exit_code,
                       stdout_sha256=self.stdout_sha256, stderr_sha256=self.stderr_sha256,
                       elapsed_seconds=self.elapsed_seconds, output_truncated=False)


def fixed_environment(workspace: Path) -> tuple[tuple[str, str], ...]:
    """Do not inherit provider keys, scanner options, home config or Python paths.

    Windows loader bootstrap values only are inherited, not enumerated/logged.
    Runtime dependency discovery and OS sandbox behavior remain unverified.
    """
    import os
    values = {"HOME": str(workspace), "USERPROFILE": str(workspace),
              "TMP": str(workspace), "TEMP": str(workspace),
              "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
              "PYTHONSAFEPATH": "1",
              "CHECKOV_ALLOW_USAGE_METRICS": "false", "LOG_LEVEL": "ERROR"}
    for name in ("SystemRoot", "WINDIR", "SYSTEMDRIVE"):
        if name in os.environ:
            values[name] = os.environ[name]
    return tuple(sorted(values.items()))


def mapping_state(mappings: tuple[Mapping, ...], pin: ScannerPin, arm: Arm,
                  check_ids: tuple[str, ...], policy_sha256: str | None) -> str:
    if not mappings:
        return "unmapped"
    seen = set()
    for item in mappings:
        if item.rule_id in seen:
            raise ValueError("duplicate rule mapping")
        seen.add(item.rule_id)
        if (item.arm != arm or item.version != pin.version
                or item.scanner_name != ("trivy" if arm == "T" else "checkov")
                or item.executable_sha256 != pin.executable_sha256
                or item.policy_sha256 != policy_sha256
                or not set(item.check_ids).issubset(check_ids)):
            raise ValueError("mapping pins/checks do not match invocation")
    if any(item.compatibility == "incompatible" for item in mappings):
        return "incompatible"
    if any(item.compatibility != "verified" or not item.compatibility_evidence_sha256
           or not SHA256.fullmatch(item.compatibility_evidence_sha256) for item in mappings):
        return "unverified"
    return "verified"


def cell_status(artifact: ScanArtifact, mapping: Mapping, resource: dict) -> str:
    """No PASS inference from absent checks or unsupported action/type/provider cells.

    A caller may consume eligible *observations* under its frozen exact mapping.
    This function never invents introduced/unchanged/clear outcomes from scanner
    PASS/FAIL; a configuration check alone does not encode those distinctions.
    """
    if not artifact.live_eligible:
        return "incomplete"
    if (mapping.arm != artifact.arm or mapping.version != artifact.scanner_version
            or mapping.executable_sha256 != artifact.executable_sha256
            or mapping.policy_sha256 != artifact.policy_sha256
            or mapping.compatibility != "verified"):
        return "incomplete"
    if resource.get("mode") == "data":
        return "not_applicable"
    if (resource.get("mode") != "managed"
            or resource.get("provider_name") != "registry.terraform.io/hashicorp/aws"):
        return "unmapped"
    change = resource.get("change")
    actions = change.get("actions") if isinstance(change, dict) else None
    if (not isinstance(actions, list) or any(not isinstance(v, str) for v in actions)
            or tuple(actions) not in mapping.supported_actions
            or resource.get("type") not in mapping.supported_types
            or resource.get("deposed") is not None):
        return "unmapped"
    matching = [row for row in artifact.observations
                if row.resource_locator == resource.get("address")
                and row.check_id in mapping.check_ids]
    if (not mapping.check_ids or len(matching) != len(mapping.check_ids)
            or any(row.status not in {"passed", "failed"} for row in matching)):
        return "incomplete"
    return "eligible"


def simulate_capture(*, arm: Arm, plan_path: Path, runner: FakeRunner,
                     parser: Callable[[object], tuple[Observation, ...]],
                     check_ids: tuple[str, ...], limits: Limits = Limits()) -> ScanArtifact:
    """Explicit fixture-only path with null real pins; cannot fabricate live proof.

    This exercises bounded fake receipts and actual output parsing without needing
    a scanner installation or pretending a fixture executable is a pinned binary.
    """
    from dataclasses import replace
    base = ScanArtifact(arm, "trivy" if arm == "T" else "checkov", "not_run", "fake",
                        None, None, None, None, None, None, None, None, "unverified",
                        check_ids, reasons=("simulated_capture_not_live_evidence",))
    try:
        if type(runner) is not FakeRunner:
            raise ValueError("fixture-only runner required")
        raw = bounded_read(plan_path, limits.plan_bytes)
        plan = strict_json(raw)
        if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes"), list):
            raise ValueError("saved plan required")
        addresses = [row.get("address") for row in plan["resource_changes"]
                     if isinstance(row, dict)]
        if (any(not isinstance(value, str) for value in addresses)
                or len(addresses) != len(plan["resource_changes"])
                or len(addresses) != len(set(addresses))
                or any(row.get("deposed") is not None for row in plan["resource_changes"])):
            raise ValueError("ambiguous scanner resource identity")
        invocation = Invocation(("FAKE_ONLY_NO_EXECUTION",), plan_path.parent, (), limits, ())
        result = runner(invocation)
        base = replace(base, plan_sha256=digest(raw), raw_exit_code=result.exit_code,
                       stdout_sha256=digest(result.stdout), stderr_sha256=digest(result.stderr),
                       elapsed_seconds=result.elapsed_seconds,
                       output_truncated=result.output_truncated)
        if digest(bounded_read(plan_path, limits.plan_bytes)) != digest(raw):
            raise ValueError("plan changed")
        if result.timed_out:
            return replace(base, status="timeout")
        if result.output_truncated:
            return replace(base, status="invalid")
        if result.exit_code not in (0, 1):
            return replace(base, status="error")
        observations = parser(strict_json(result.stdout))
        if len(observations) > limits.max_observations:
            raise ValueError("too many observations")
        identities = [(row.check_id, row.resource_locator) for row in observations]
        if (len(identities) != len(set(identities))
                or any(row.resource_locator not in addresses for row in observations)
                or ((result.exit_code == 1) != any(row.status == "failed" for row in observations))):
            raise ValueError("fake artifact identity/exit mismatch")
        return replace(base, status="ok", observations=observations)
    except (ValueError, OSError, TypeError, KeyError, RecursionError, UnicodeError):
        return replace(base, status="invalid", reasons=("simulated_capture_not_live_evidence",
                                                       "fake_artifact_validation_failed"))


def capture(*, arm: Arm, pin: ScannerPin, plan_path: Path, config_path: Path,
            workspace: Path, runner: Runner, argv_builder: Callable,
            parser: Callable[[object], tuple[Observation, ...]],
            check_ids: tuple[str, ...], mappings: tuple[Mapping, ...] = (),
            policy_sha256: str | None = None, limits: Limits = Limits(),
            policy_manifest_path: Path | None = None,
            extra_files: tuple[tuple[Path, str, int], ...] = (),
            extra_environment: tuple[tuple[str, str], ...] = ()) -> ScanArtifact:
    """Capture raw observations, not detector outcomes or scorer ArmRow records.

    No executable/version probes, installs, writes, retries or implicit runners.
    The caller supplies a controlled empty-config file and scratch directory.
    """
    from dataclasses import replace

    base = ScanArtifact(arm, "trivy" if arm == "T" else "checkov", "not_run", "none",
                        None, pin.version, pin.executable_sha256,
                        pin.dependency_manifest_sha256, pin.version_evidence_sha256,
                        None, None, policy_sha256, "unverified", check_ids)
    try:
        if (not check_ids or len(set(check_ids)) != len(check_ids)
                or any(not CHECK_ID.fullmatch(value) for value in check_ids)):
            raise ValueError("explicit unique enabled check IDs required")
        missing = pin.missing()
        if missing:
            return replace(base, reasons=missing)
        if not policy_sha256 or not SHA256.fullmatch(policy_sha256):
            return replace(base, reasons=("missing_or_invalid_policy_pin",))
        if policy_manifest_path is None:
            return replace(base, reasons=("missing_policy_manifest",))
        if any(not path.is_file() for path in (pin.executable, pin.dependency_manifest_path,
                                               pin.version_evidence_path, policy_manifest_path)):
            return replace(base, reasons=("scanner_installation_or_provenance_unavailable",))
        if not plan_path.is_absolute() or not config_path.is_absolute():
            raise ValueError("absolute plan/config paths required")
        raw = bounded_read(plan_path, limits.plan_bytes)
        raw_config = bounded_read(config_path, 4096)
        if strict_json(raw_config) != {}:
            raise ValueError("only explicit empty scanner config is allowed")
        dependency_bytes = bounded_read(pin.dependency_manifest_path, 1024 * 1024)
        version_bytes = bounded_read(pin.version_evidence_path, 64 * 1024)
        policy_bytes = bounded_read(policy_manifest_path, 1024 * 1024)
        if (digest(dependency_bytes) != pin.dependency_manifest_sha256
                or digest(version_bytes) != pin.version_evidence_sha256
                or digest(policy_bytes) != policy_sha256):
            raise ValueError("provenance file hash mismatch")
        version_receipt = strict_json(version_bytes)
        if not isinstance(version_receipt, dict) or any(
                version_receipt.get(key) != value for key, value in (
                    ("scanner_name", base.scanner_name), ("version", pin.version),
                    ("executable_sha256", pin.executable_sha256),
                    ("dependency_manifest_sha256", pin.dependency_manifest_sha256))):
            raise ValueError("version receipt disagrees with pinned installation")
        policy_receipt = strict_json(policy_bytes)
        if (not isinstance(policy_receipt, dict)
                or policy_receipt.get("check_ids") != list(check_ids)
                or policy_receipt.get("scanner_name") != base.scanner_name):
            raise ValueError("policy manifest/check selection mismatch")
        files = [{"name": path.name, "sha256": sha} for path, sha, _ in extra_files]
        if policy_receipt.get("files") != sorted(files, key=lambda value: value["name"]):
            raise ValueError("policy/bundle inventory differs from manifest")
        plan = strict_json(raw)
        if not isinstance(plan, dict) or plan.get("format_version") not in {"1.0", "1.1", "1.2"}:
            raise ValueError("unsupported saved-plan JSON format")
        changes = plan.get("resource_changes")
        if not isinstance(changes, list):
            raise ValueError("resource_changes array required")
        addresses: dict[str, dict] = {}
        for resource in changes:
            if not isinstance(resource, dict) or not isinstance(resource.get("address"), str):
                raise ValueError("invalid resource identity")
            # Scanner callbacks collapse deposed identity: never score that ambiguity.
            if resource["address"] in addresses or resource.get("deposed") is not None:
                raise ValueError("scanner identity cannot represent duplicate/deposed resources")
            addresses[resource["address"]] = resource
        state = mapping_state(mappings, pin, arm, check_ids, policy_sha256)
        invocation = Invocation(tuple(argv_builder()), workspace,
                                fixed_environment(workspace) + extra_environment, limits,
                                ((plan_path, digest(raw), limits.plan_bytes),
                                 (config_path, digest(raw_config), 4096),
                                 (pin.executable, pin.executable_sha256, 256 * 1024 * 1024),
                                 (pin.dependency_manifest_path,
                                  pin.dependency_manifest_sha256, 1024 * 1024),
                                 (pin.version_evidence_path,
                                  pin.version_evidence_sha256, 64 * 1024),
                                 (policy_manifest_path, policy_sha256, 1024 * 1024))
                                + extra_files)
        invocation.verify()
        invocation_hash = invocation_digest(invocation)
        base = replace(base, plan_sha256=digest(raw), config_sha256=digest(raw_config),
                       invocation_sha256=invocation_hash, mapping_status=state)
        if type(runner) is BoundedSubprocessRunner:
            approval = runner.approval(invocation)
            if (approval.arm != arm or approval.scanner_name != base.scanner_name
                    or approval.scanner_version != pin.version):
                raise PermissionError("approved scanner arm/version differs from capture")
        result = runner(invocation)
        invocation.verify()
        if (result.execution_kind not in {"fake", "live", "none"}
                or not math.isfinite(result.elapsed_seconds) or result.elapsed_seconds < 0
                or (result.exit_code is not None and type(result.exit_code) is not int)
                or type(result.stdout) is not bytes or type(result.stderr) is not bytes):
            raise ValueError("invalid runner receipt")
        truncated = (result.output_truncated or len(result.stdout) > limits.stdout_bytes
                     or len(result.stderr) > limits.stderr_bytes)
        # Never retain raw stdout/stderr in returned records or diagnostic strings.
        base = replace(base, execution_kind=result.execution_kind,
                       raw_exit_code=result.exit_code,
                       stdout_sha256=digest(result.stdout[:limits.stdout_bytes]),
                       stderr_sha256=digest(result.stderr[:limits.stderr_bytes]),
                       elapsed_seconds=result.elapsed_seconds, output_truncated=truncated,
                       operator_grant_sha256=result.operator_grant_sha256,
                       start_receipt_sha256=result.start_receipt_sha256,
                       terminal_receipt_sha256=result.terminal_receipt_sha256)
        if result.execution_kind == "live" and (
                type(runner) is not BoundedSubprocessRunner
                or any(not isinstance(pin, str) or not SHA256.fullmatch(pin) for pin in (
                    result.operator_grant_sha256, result.start_receipt_sha256, result.terminal_receipt_sha256))):
            return replace(base, status="invalid", execution_kind="none",
                           operator_grant_sha256=None, start_receipt_sha256=None, terminal_receipt_sha256=None,
                           reasons=("untrusted_runner_cannot_attest_execution",))
        if result.error_code is not None or result.execution_kind == "none":
            reason = result.error_code if result.error_code in {
                "process_start_failed", "terminal_receipt_write_failed"} else "process_not_started"
            return replace(base, status="error", reasons=(reason,))
        if result.timed_out or result.elapsed_seconds > limits.timeout_seconds + 2:
            return replace(base, status="timeout", reasons=("scanner_timeout",))
        if truncated:
            return replace(base, status="invalid", reasons=("bounded_output_incomplete",))
        if result.exit_code not in (0, 1):
            return replace(base, status="error", reasons=("unknown_scanner_exit_semantics",))
        observations = parser(strict_json(result.stdout))
        if len(observations) > limits.max_observations:
            raise ValueError("too many scanner observations")
        seen = set()
        for row in observations:
            identity = row.check_id, row.resource_locator
            if identity in seen or row.resource_locator not in addresses:
                raise ValueError("duplicate or foreign scanner resource/check")
            seen.add(identity)
        if (result.exit_code == 1) != any(row.status == "failed" for row in observations):
            raise ValueError("exit status contradicts scanner failure records")
        reasons = []
        if result.execution_kind == "fake":
            reasons.append("simulated_capture_not_live_evidence")
        if state != "verified":
            reasons.append("mapping_" + state)
        for check_id in check_ids:
            if not any(row.check_id == check_id and row.status in {"passed", "failed"}
                       for row in observations):
                reasons.append("enabled_check_has_no_decidable_observation")
                break
        return replace(base, status="ok", observations=observations, reasons=tuple(reasons))
    except PermissionError:
        return replace(base, status="not_run", reasons=("runtime_activation_not_authorized",))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return replace(base, status="invalid", reasons=("input_pin_or_artifact_validation_failed",))
