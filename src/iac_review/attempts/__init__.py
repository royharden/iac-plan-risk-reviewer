"""Single-worker append-only accounting with conservative unresolved liabilities.

There is no provider call here. A future authorized adapter must call start(),
flush its request-start reservation, then call terminal() for every attempt.
Crash locks and unresolved billing require explicit operator reconciliation.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

from iac_review.contracts import Wire
from iac_review.ingest import decode_source, read_source_bytes

_HASH = re.compile(r"[0-9a-f]{64}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_HASH_FIELDS = {"build", "corpus", "projection", "prompt", "input", "model", "config"}


class Budget(Wire):
    max_requests: int
    max_input_tokens: int
    max_output_tokens: int
    max_usd: Decimal


class PriceIdentity(Wire):
    provider: str
    model: str
    price_id: str
    price_date: str
    input_usd_per_million: Decimal
    output_usd_per_million: Decimal


class Reservation(Wire):
    input_tokens_upper: int
    output_tokens_upper: int
    request_usd_upper: Decimal
    hashes: dict[str, str]


class JournalError(ValueError):
    """A request may not start or a journal record is inconsistent."""


def _usd(value: Decimal | str) -> Decimal:
    amount = Decimal(value)
    if not amount.is_finite() or amount < 0:
        raise JournalError("cost must be finite and nonnegative")
    return amount


def _tokens(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise JournalError("token bound must be a nonnegative integer")
    return value


class AttemptJournal:
    """Exclusive run ownership; independent processes/instances cannot share it.

    A surviving lock is deliberately never stolen by age or PID. An operator
    first reconciles the crashed worker and recorded liabilities. This class
    cannot authorize spend; it only enforces a separately approved cap.
    """

    def __init__(self, path: Path, budget: Budget, price: PriceIdentity) -> None:
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
               for p in (self.path, self.lock_path, *self.path.parents)):
            raise JournalError("journal path must not traverse symbolic links")
        if not self.path.parent.is_dir():
            raise JournalError("journal parent directory must already exist")
        if self.path.exists() and not self.path.is_file():
            raise JournalError("journal must be a regular local file")
        for count in (budget.max_requests, budget.max_input_tokens, budget.max_output_tokens):
            _tokens(count)
        _usd(budget.max_usd)
        _usd(price.input_usd_per_million)
        _usd(price.output_usd_per_million)
        for label in (price.provider, price.model, price.price_id):
            if not _LABEL.fullmatch(label):
                raise JournalError("price identity is outside the fixed label format")
        date.fromisoformat(price.price_date)
        self.budget, self.price = budget, price
        self._owner = uuid4().hex
        self._mutex = Lock()
        self._closed = False
        self._fd: int | None = None
        self._events: list[dict[str, Any]] = []
        self._loaded_sha256 = hashlib.sha256(b"").hexdigest()
        try:
            self._fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise JournalError("another worker or an unreconciled crash owns this journal") from error
        try:
            os.write(self._fd, self._owner.encode("ascii"))
            os.fsync(self._fd)
            self._events, self._loaded_sha256 = self._read_events(self.path, required=False)
            # Replay validates pair ordering and detects unmatched starts. It does
            # not convert a missing terminal into a free/failed request.
            self._state()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> AttemptJournal:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    @classmethod
    def _read_events(cls, path: Path, *, required: bool) -> tuple[list[dict[str, Any]], str]:
        """One strict bounded reader shared by ordinary replay and read-only snapshots."""
        if not path.exists() and not path.is_symlink():
            if required:
                raise JournalError("journal_missing")
            return [], hashlib.sha256(b"").hexdigest()
        try:
            data = read_source_bytes(path)
            if data and not data.endswith(b"\n"):
                raise JournalError("journal_truncated_line")
            lines = data.splitlines()
            if len(lines) > 100_000:
                raise JournalError("journal_event_limit")
            # Reuse the public strict JSON decoder, including one overall parse budget.
            import time
            started = time.monotonic()
            events = []
            for line in lines:
                event = decode_source(line, started)
                cls._validate_event(event)
                events.append(event)
            return events, hashlib.sha256(data).hexdigest()
        except JournalError:
            raise
        except (ValueError, OSError, TypeError, KeyError, ArithmeticError, RuntimeError):
            raise JournalError("journal_read_invalid") from None

    @classmethod
    def snapshot(cls, path: Path) -> dict[str, Any]:
        """Read existing journal only: no constructor, mkdir, lock or journal writes.

        The snapshot is informational, not budget/spend/start authorization. Lock
        presence is as observed, never a stale-lock or worker-death determination.
        """
        path = Path(path).absolute()
        lock = path.with_suffix(path.suffix + ".lock")
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
               for p in (path, lock, *path.parents)):
            raise JournalError("journal_link_rejected")
        events, digest = cls._read_events(path, required=True)
        # _state depends only on events. Reuse its exact accounting without
        # constructing a worker or introducing a second balance implementation.
        reader = object.__new__(cls)
        reader._events = events
        state = reader._state()
        pending = set(state["pending"])
        attempts = []
        for attempt_id, attempt in state["attempts"].items():
            terminal, reconciled = attempt["terminal"], attempt["reconciled"]
            outcome = reconciled or terminal
            attempts.append({
                "attempt_id": attempt_id, "status": terminal["status"] if terminal else "interrupted",
                "reconciled": reconciled is not None,
                "requires_reconciliation": attempt_id in pending,
                "input_tokens": outcome["input_tokens"] if outcome else None,
                "output_tokens": outcome["output_tokens"] if outcome else None,
                "known_usd": str(_usd(outcome["known_usd"]))
                    if outcome and outcome["known_usd"] is not None else None,
                "receipt_sha256": reconciled["evidence_sha256"] if reconciled else None,
            })
        return {"schema": 1, "read_only": True, "journal_sha256": digest,
                "worker_lock_present": lock.exists(), "start_authorized": False,
                "reservation_overrun": state["overrun"], "summary": cls._summary(state),
                "attempts": attempts}

    @classmethod
    def operator_reconcile(
        cls, path: Path, *, expected_journal_sha256: str, attempt_id: str,
        input_tokens: int, output_tokens: int, known_usd: Decimal, evidence_sha256: str,
    ) -> dict[str, Any]:
        """Explicit existing-journal operation; no start/retry/unlock or cap change."""
        if not isinstance(expected_journal_sha256, str) or not _HASH.fullmatch(expected_journal_sha256):
            raise JournalError("journal_digest_invalid")
        if not isinstance(attempt_id, str) or not re.fullmatch(r"[0-9a-f]{32}", attempt_id):
            raise JournalError("attempt_id_invalid")
        if not isinstance(evidence_sha256, str) or not _HASH.fullmatch(evidence_sha256):
            raise JournalError("receipt_digest_invalid")
        _tokens(input_tokens)
        _tokens(output_tokens)
        _usd(known_usd)
        path = Path(path).absolute()
        before = cls.snapshot(path)
        if before["journal_sha256"] != expected_journal_sha256:
            raise JournalError("journal_digest_mismatch")
        # This private worker can never start a request (zero caps). Its price is
        # not written or substituted into historical reservations; reconcile()
        # appends only actual operator accounting and receipt identity.
        budget = Budget(max_requests=0, max_input_tokens=0, max_output_tokens=0, max_usd=Decimal(0))
        price = PriceIdentity(provider="operator", model="reconciliation-only",
                              price_id="not-a-provider-price", price_date=date.today().isoformat(),
                              input_usd_per_million=Decimal(0), output_usd_per_million=Decimal(0))
        with cls(path, budget, price) as worker:
            if worker._loaded_sha256 != expected_journal_sha256 \
                    or hashlib.sha256(read_source_bytes(path)).hexdigest() != expected_journal_sha256:
                raise JournalError("journal_digest_mismatch")
            worker.reconcile(attempt_id, input_tokens=input_tokens, output_tokens=output_tokens,
                             known_usd=known_usd, evidence_sha256=evidence_sha256)
            after = cls.snapshot(path)
            return {"operation": "reconciliation_recorded", "attempt_id": attempt_id,
                    "receipt_sha256": evidence_sha256, "snapshot": after,
                    "provider_billing_authenticated": False, "start_authorized": False}

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            # Only remove our exact ownership marker, never someone else's lock.
            if self.lock_path.is_file() and not self.lock_path.is_symlink():
                if self.lock_path.read_text(encoding="ascii") == self._owner:
                    self.lock_path.unlink()

    @staticmethod
    def _validate_event(event: Any) -> None:
        if not isinstance(event, dict) or event.get("schema") != 1:
            raise JournalError("invalid journal schema")
        common = {"schema", "event", "attempt_id", "at"}
        keys = {
            "request_start": common | {"input_tokens_upper", "output_tokens_upper", "usd_upper", "price", "hashes"},
            "terminal": common | {"status", "duration_ms", "input_tokens", "output_tokens", "known_usd", "response_sha256"},
            "reconciled": common | {"input_tokens", "output_tokens", "known_usd", "evidence_sha256"},
        }
        kind = event.get("event")
        if kind not in keys or set(event) != keys[kind]:
            raise JournalError("unexpected journal fields")
        if not isinstance(event["attempt_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", event["attempt_id"]):
            raise JournalError("invalid attempt identity")
        datetime.fromisoformat(event["at"])
        if kind == "request_start":
            _tokens(event["input_tokens_upper"])
            _tokens(event["output_tokens_upper"])
            _usd(event["usd_upper"])
            hashes = event["hashes"]
            if not isinstance(hashes, dict) or set(hashes) != _HASH_FIELDS or any(
                not isinstance(value, str) or not _HASH.fullmatch(value) for value in hashes.values()
            ):
                raise JournalError("attempt provenance hashes are incomplete")
            PriceIdentity.model_validate_json(json.dumps(event["price"]))
        else:
            for key in ("input_tokens", "output_tokens"):
                if event[key] is not None:
                    _tokens(event[key])
            if event["known_usd"] is not None:
                _usd(event["known_usd"])
            if kind == "terminal":
                if event["status"] not in {"ok", "invalid", "timeout", "error", "cancelled"}:
                    raise JournalError("invalid terminal status")
                _tokens(event["duration_ms"])
                digest = event["response_sha256"]
            else:
                digest = event["evidence_sha256"]
                if event["known_usd"] is None or event["input_tokens"] is None or event["output_tokens"] is None:
                    raise JournalError("reconciliation requires complete measured usage and cost")
                if not isinstance(digest, str) or not _HASH.fullmatch(digest):
                    raise JournalError("reconciliation requires a real accounting receipt hash")
            if digest is not None and (not isinstance(digest, str) or not _HASH.fullmatch(digest)):
                raise JournalError("invalid accounting receipt hash")

    def _state(self) -> dict[str, Any]:
        attempts: dict[str, dict[str, Any]] = {}
        known_usd = Decimal(0)
        input_tokens = output_tokens = 0
        pending: list[str] = []
        unresolved_usd_upper = Decimal(0)
        overrun = False
        for event in self._events:
            key, kind = event["attempt_id"], event["event"]
            if kind == "request_start":
                if key in attempts:
                    raise JournalError("duplicate request start")
                attempts[key] = {"start": event, "terminal": None, "reconciled": None}
            elif key not in attempts:
                raise JournalError("terminal without request start")
            elif attempts[key][kind] is not None:
                raise JournalError("duplicate terminal or reconciliation")
            else:
                attempts[key][kind] = event
        for key, attempt in attempts.items():
            start = attempt["start"]
            outcome = attempt["reconciled"] or attempt["terminal"]
            unresolved = outcome is None or any(
                outcome[field] is None for field in ("known_usd", "input_tokens", "output_tokens")
            )
            unresolved |= (
                attempt["reconciled"] is None and attempt["terminal"] is not None
                and attempt["terminal"]["status"] == "timeout"
            )
            partial_known = _usd(outcome["known_usd"]) if outcome and outcome["known_usd"] is not None else Decimal(0)
            known_usd += partial_known
            if unresolved:
                pending.append(key)
                unresolved_usd_upper += max(_usd(start["usd_upper"]) - partial_known, Decimal(0))
                input_tokens += max(start["input_tokens_upper"], (outcome or {}).get("input_tokens") or 0)
                output_tokens += max(start["output_tokens_upper"], (outcome or {}).get("output_tokens") or 0)
            else:
                measured = _usd(outcome["known_usd"])
                input_tokens += outcome["input_tokens"]
                output_tokens += outcome["output_tokens"]
                overrun |= measured > _usd(start["usd_upper"])
                overrun |= outcome["input_tokens"] > start["input_tokens_upper"]
                overrun |= outcome["output_tokens"] > start["output_tokens_upper"]
        return {"attempts": attempts, "requests": len(attempts), "known_usd": known_usd,
                "unresolved_usd_upper": unresolved_usd_upper, "input_tokens": input_tokens,
                "output_tokens": output_tokens, "pending": pending, "overrun": overrun}

    def _append(self, event: dict[str, Any]) -> None:
        if self._closed:
            raise JournalError("journal is closed")
        self._validate_event(event)
        data = (json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        with self.path.open("ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self._events.append(event)

    def start(self, reservation: Reservation) -> str:
        """Reserve worst-case exposure and durably record before any future call."""
        with self._mutex:
            state = self._state()
            if state["pending"] or state["overrun"]:
                raise JournalError("unresolved billing or reservation overrun blocks new requests")
            input_bound = _tokens(reservation.input_tokens_upper)
            output_bound = _tokens(reservation.output_tokens_upper)
            bound = _usd(reservation.request_usd_upper)
            required = (Decimal(input_bound) * self.price.input_usd_per_million +
                        Decimal(output_bound) * self.price.output_usd_per_million) / Decimal(1_000_000)
            if bound < required:
                raise JournalError("USD reservation is below the pinned worst-case token price")
            if state["requests"] + 1 > self.budget.max_requests:
                raise JournalError("request cap exceeded")
            if state["input_tokens"] + input_bound > self.budget.max_input_tokens:
                raise JournalError("input-token cap exceeded")
            if state["output_tokens"] + output_bound > self.budget.max_output_tokens:
                raise JournalError("output-token cap exceeded")
            if state["known_usd"] + state["unresolved_usd_upper"] + bound > self.budget.max_usd:
                raise JournalError("USD cap exceeded")
            attempt_id = uuid4().hex
            self._append({
                "schema": 1, "event": "request_start", "attempt_id": attempt_id,
                "at": datetime.now(timezone.utc).isoformat(), "input_tokens_upper": input_bound,
                "output_tokens_upper": output_bound, "usd_upper": str(bound),
                "price": json.loads(self.price.model_dump_json()), "hashes": reservation.hashes,
            })
            return attempt_id

    def terminal(
        self, attempt_id: str, status: Literal["ok", "invalid", "timeout", "error", "cancelled"],
        duration_ms: int, *, input_tokens: int | None = None, output_tokens: int | None = None,
        known_usd: Decimal | None = None, response_sha256: str | None = None,
    ) -> None:
        with self._mutex:
            attempts = self._state()["attempts"]
            if attempt_id not in attempts or attempts[attempt_id]["terminal"] is not None or attempts[attempt_id]["reconciled"] is not None:
                raise JournalError("request is absent or already terminal")
            self._append({
                "schema": 1, "event": "terminal", "attempt_id": attempt_id,
                "at": datetime.now(timezone.utc).isoformat(), "status": status,
                "duration_ms": duration_ms, "input_tokens": input_tokens, "output_tokens": output_tokens,
                "known_usd": None if known_usd is None else str(_usd(known_usd)),
                "response_sha256": response_sha256,
            })

    def reconcile(
        self, attempt_id: str, *, input_tokens: int, output_tokens: int,
        known_usd: Decimal, evidence_sha256: str,
    ) -> None:
        """Operator supplies a real billing receipt, never an assumed zero."""
        with self._mutex:
            state = self._state()
            if attempt_id not in state["pending"]:
                raise JournalError("only unresolved liabilities may be reconciled")
            self._append({
                "schema": 1, "event": "reconciled", "attempt_id": attempt_id,
                "at": datetime.now(timezone.utc).isoformat(), "input_tokens": input_tokens,
                "output_tokens": output_tokens, "known_usd": str(_usd(known_usd)),
                "evidence_sha256": evidence_sha256,
            })

    def summary(self) -> dict[str, Any]:
        with self._mutex:
            return self._summary(self._state())

    @staticmethod
    def _summary(state: dict[str, Any]) -> dict[str, Any]:
        successes = sum(attempt["terminal"] is not None and attempt["terminal"]["status"] == "ok"
                        for attempt in state["attempts"].values())
        return {
            "requests": state["requests"], "successful_attempts": successes,
            "known_usd": str(state["known_usd"]),
            "unresolved_usd_upper": str(state["unresolved_usd_upper"]),
            "billing_known": not state["pending"], "pending_attempt_ids": state["pending"],
            "input_tokens_with_unresolved_bounds": state["input_tokens"],
            "output_tokens_with_unresolved_bounds": state["output_tokens"],
            "cost_per_success_usd": str(state["known_usd"] / successes)
                if successes and not state["pending"] else None,
            "new_requests_blocked": bool(state["pending"] or state["overrun"]),
        }
