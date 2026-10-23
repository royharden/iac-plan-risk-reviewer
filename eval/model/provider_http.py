"""Disabled, journal-bound fixed HTTPS transport SOURCE. No import-time I/O.

Actual environment/network effects are deferred inside explicitly admitted calls.
There is no CLI switch, live-eligibility claim, proxy, redirect or retry machinery.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from time import monotonic
from typing import Callable, Protocol

from iac_review.attempts import AttemptJournal
from eval.model.provider_activation import (
    Admission, StartedAttempt, remaining, require, started_attempt, validate_admission,
)
from eval.model.provider_wire import (
    CREDENTIAL_ENV_NAME, ENDPOINT, FakeHttp, FakeHttpRequest, FakeHttpResponse,
    ProviderConfig, ResponsesWire,
)
from eval.model.transport import Reply, Request, TransportIdentity, Usage
from eval.model.experiment import digest


@dataclass(frozen=True)
class ProviderReply(Reply):
    # False means retained bytes are only an explicitly incomplete prefix/envelope.
    payload_complete: bool = True


class HttpFailure(ValueError):
    """Fixed invariant only; a bounded private prefix never enters exception repr."""

    def __init__(self, status: str, partial: bytes = b"", http_status: int | None = None) -> None:
        super().__init__("provider_http_" + status)
        self.status, self.partial, self.http_status = status, partial, http_status


class Connector(Protocol):
    def exchange(self, wire: FakeHttpRequest, key: str, ip_literal: str,
                 deadline: float) -> FakeHttpResponse: ...


def _environment_key(name: str) -> str:
    # Called only after all admission and durable start checks. Name is fixed.
    import os
    require(name == CREDENTIAL_ENV_NAME, "provider_credential_name_not_fixed")
    value = os.getenv(name)
    require(type(value) is str and 16 <= len(value) <= 2048
            and all(33 <= ord(c) <= 126 for c in value), "provider_credential_unavailable")
    return value


class FixedHttpsConnector:
    """One direct numeric-IP TLS/HTTP1.1 exchange; constructor has no effects.

    Socket/SSL/http imports and OS trust loading occur only inside exchange.
    Numeric approved address avoids an unbounded DNS lookup within the deadline.
    Certificate/SNI/Host always refer to api.openai.com, never the IP literal.
    """

    def exchange(self, wire: FakeHttpRequest, key: str, ip_literal: str,
                 deadline: float) -> FakeHttpResponse:
        import http.client
        import io
        import ipaddress
        import socket
        import ssl

        require(wire.url == ENDPOINT and wire.headers == (("Content-Type", "application/json"),)
                and wire.follow_redirects is False, "provider_fixed_http_request_required")
        require(type(key) is str and 16 <= len(key) <= 2048
                and all(33 <= ord(c) <= 126 for c in key), "provider_credential_unavailable")
        ip = ipaddress.ip_address(ip_literal)
        require(str(ip) == ip_literal and ip.is_global and not ip.is_multicast and not ip.is_reserved,
                "provider_approved_numeric_address_required")
        started = monotonic()
        deadline = min(deadline, started + wire.timeout_seconds)
        remaining(deadline)
        # Unlike create_default_context(), this does not enable SSLKEYLOGFILE.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        context.set_alpn_protocols(["http/1.1"])
        require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
                "provider_tls_verification_required")
        raw = tls = response = None
        partial = bytearray()
        status = None
        try:
            raw = socket.socket(socket.AF_INET if ip.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
            raw.settimeout(remaining(deadline))
            raw.connect((str(ip), 443))
            raw.settimeout(remaining(deadline))
            tls = context.wrap_socket(raw, server_hostname="api.openai.com", do_handshake_on_connect=False)
            raw = None  # Ownership transferred to TLS socket.
            tls.settimeout(remaining(deadline))
            tls.do_handshake()
            require(tls.selected_alpn_protocol() in (None, "http/1.1"), "provider_alpn_invalid")
            header = ("POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n"
                      "Content-Type: application/json\r\nAccept: application/json\r\n"
                      "Accept-Encoding: identity\r\nConnection: close\r\n"
                      "Authorization: Bearer " + key + "\r\nContent-Length: "
                      + str(len(wire.body)) + "\r\n\r\n").encode("ascii")
            tls.settimeout(remaining(deadline))
            tls.sendall(header + wire.body)
            # Bounded raw reads include framing/header overhead; no socket makefile
            # retains its original per-operation timeout across the whole read.
            wire_limit = wire.max_response_bytes + 16384

            class DeadlineReader(io.RawIOBase):
                received = 0
                header_phase = True

                def readable(self):
                    return True

                def readinto(self, target):
                    tls.settimeout(remaining(deadline))
                    room = wire_limit - self.received
                    if self.header_phase:
                        room = min(room, 16384 - self.received)
                    if room <= 0:
                        raise HttpFailure("invalid", bytes(partial), status)
                    data = tls.recv(min(len(target), 4096, room))
                    remaining(deadline)
                    self.received += len(data)
                    target[:len(data)] = data
                    return len(data)

            reader = DeadlineReader()

            class ResponseSocket:
                def makefile(self, mode):
                    return io.BufferedReader(reader, buffer_size=4096)

            response = http.client.HTTPResponse(ResponseSocket(), method="POST")
            response.begin()
            reader.header_phase = False
            status = response.status
            require(reader.received <= 16384, "provider_header_byte_limit")
            lengths = response.headers.get_all("Content-Length", [])
            encodings = response.headers.get_all("Transfer-Encoding", [])
            require(len(lengths) <= 1 and len(encodings) <= 1 and not (lengths and encodings),
                    "provider_ambiguous_response_framing")
            require(not encodings or encodings[0].lower().strip() == "chunked", "provider_transfer_encoding")
            require(response.getheader("Content-Encoding", "identity").lower().strip() == "identity",
                    "provider_compressed_response_refused")
            if lengths:
                require(lengths[0].isascii() and lengths[0].isdigit()
                        and int(lengths[0]) <= wire.max_response_bytes, "provider_response_byte_limit")
            while True:
                remaining(deadline)
                block = response.read(min(4096, wire.max_response_bytes - len(partial) + 1))
                if not block:
                    break
                partial.extend(block)
                if len(partial) > wire.max_response_bytes:
                    raise HttpFailure("invalid", bytes(partial[:wire.max_response_bytes]), status)
            if lengths:
                require(len(partial) == int(lengths[0]), "provider_response_truncated")
            remaining(deadline)
            return FakeHttpResponse(status, bytes(partial), ENDPOINT,
                response.getheader("Content-Type", ""), monotonic() - started)
        except TimeoutError:
            raise HttpFailure("timeout", bytes(partial), status) from None
        except http.client.IncompleteRead as error:
            partial.extend(error.partial[:max(0, wire.max_response_bytes - len(partial))])
            raise HttpFailure("error", bytes(partial), status) from None
        except HttpFailure:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise HttpFailure("error", bytes(partial), status) from None
        finally:
            if response is not None:
                response.close()
            if tls is not None:
                tls.close()
            if raw is not None:
                raw.close()


Controller = Callable[[Request, StartedAttempt, ProviderConfig], Admission]


class ProviderTransport:
    """Future opt-in transport. Ordinary complete() refuses missing journal linkage.

    External controller is trusted authorization code, not a model response/parser.
    It supplies independent expected pins; constructor does not call it or read keys.
    All returned evidence remains unverified/live-ineligible, even after real I/O.
    """

    network_capable = True  # Fake CLI/programmatic fake mode must refuse this transport.

    def __init__(self, config: ProviderConfig, *, enabled: bool = False,
                 controller: Controller | None = None,
                 connector_factory: Callable[[], Connector] | None = None,
                 key_reader: Callable[[str], str] | None = None) -> None:
        self.config, self.enabled, self.controller = config, enabled, controller
        self._factory, self._key_reader = connector_factory, key_reader
        self.identity = TransportIdentity("openai-compatible", config.model, config.model_version, "protocol")
        self._used: set[str] = set()
        self.receipts: list[dict] = []

    def complete(self, request: Request) -> Reply:
        raise ValueError("provider_started_journal_permit_required")

    def complete_started(self, request: Request, *, journal: AttemptJournal, attempt_id: str,
                         deadline_monotonic: float) -> ProviderReply:
        require(self.enabled is True and self.controller is not None, "provider_transport_disabled")
        deadline = min(deadline_monotonic, monotonic() + request.timeout_seconds)
        remaining(deadline)
        start = started_attempt(journal, attempt_id)
        require(attempt_id not in self._used, "provider_attempt_already_used")
        # Consume before controller/key/connector; rejection never implies a retry.
        self._used.add(attempt_id)
        admission = self.controller(request, start, self.config)
        validate_admission(admission, self.config, request, start, deadline)
        codec = ResponsesWire(self.config, FakeHttp(()), enabled=True,
            permit=admission.permit, expected_permit_sha256=admission.expected_permit_sha256)
        wire = codec.prepare(request)  # Finite projection/config/permit checks, no I/O.
        require(started_attempt(journal, attempt_id) == start, "provider_journal_changed_before_exchange")
        remaining(deadline)
        key = None
        reply = None
        try:
            key = (self._key_reader or _environment_key)(CREDENTIAL_ENV_NAME)
            remaining(deadline)
            connector = (self._factory or FixedHttpsConnector)()
            remaining(deadline)
            response = connector.exchange(wire, key, admission.activation.approved_ip_literal, deadline)
            reply = ProviderReply("timeout", response.body[:self.config.max_response_bytes], Usage(), False)
            remaining(deadline)
            # Reuse the existing codec as a pure in-memory response decoder. Its
            # internal fake receipts are deliberately not exported as I/O evidence.
            codec.http = FakeHttp((response,))
            decoded = codec.complete(request)
            complete = True
            if codec.receipts[-1]["response_limit_exceeded"]:
                complete = False
            reply = ProviderReply(decoded.status, decoded.payload, decoded.usage, complete)
            remaining(deadline)
            if len(reply.payload) > admission.activation.max_output_bytes:
                reply = replace(reply, status="invalid", payload_complete=False,
                    payload=reply.payload[:admission.activation.max_output_bytes])
        except HttpFailure as error:
            reply = ProviderReply(error.status, error.partial[:self.config.max_response_bytes], Usage(), False)
        except TimeoutError:
            reply = replace(reply, status="timeout", payload_complete=False) if reply is not None \
                else ProviderReply("timeout", b"", Usage(), False)
        except (OSError, ValueError, TypeError):
            reply = ProviderReply("error", b"", Usage(), False)
        finally:
            key = None  # No secure-erasure claim for immutable Python strings.
        self.receipts.append({"attempt_id": attempt_id, "journal_sha256": start.journal_sha256,
            "start_record_sha256": start.start_record_sha256,
            "model_request_sha256": admission.activation.model_request_sha256,
            "wire_request_sha256": admission.activation.wire_request_sha256,
            "payload_sha256": digest(reply.payload), "payload_complete": reply.payload_complete,
            "status": reply.status, "live_eligible": False, "billing_authenticated": False,
            "connector_origin_authenticated": False})
        return reply
