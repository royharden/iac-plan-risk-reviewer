"""Fixed HTTPS boundary regression SOURCE; only in-memory socket/TLS substitutes.

These tests have NOT been executed during Dirty Mode construction.
"""
from time import monotonic

import pytest

from eval.model.provider_http import FixedHttpsConnector, HttpFailure
from eval.model.provider_wire import ENDPOINT, FakeHttpRequest


def _fake_stack(monkeypatch, response: bytes, *, timeout=False):
    import socket
    import ssl

    effects = []
    class FakeSocket:
        def __init__(self):
            self.data = response
        def settimeout(self, value):
            assert 0 < value <= 1
            effects.append(("timeout", value))
        def connect(self, address):
            effects.append(("connect", address))
        def do_handshake(self):
            effects.append(("handshake",))
        def selected_alpn_protocol(self):
            return "http/1.1"
        def sendall(self, data):
            effects.append(("send", data))
        def recv(self, size):
            if timeout:
                raise TimeoutError("synthetic-private-error-must-not-log")
            data, self.data = self.data[:size], self.data[size:]
            return data
        def close(self):
            effects.append(("close",))
    raw = FakeSocket()
    class FakeContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED
        def load_default_certs(self, purpose):
            effects.append(("trust",))
        def set_alpn_protocols(self, values):
            assert values == ["http/1.1"]
        def wrap_socket(self, sock, *, server_hostname, do_handshake_on_connect):
            assert sock is raw and server_hostname == "api.openai.com"
            assert do_handshake_on_connect is False
            effects.append(("sni", server_hostname))
            return raw
    monkeypatch.setattr(socket, "socket", lambda *args: raw)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: pytest.fail("DNS must not be used"))
    monkeypatch.setattr(ssl, "SSLContext", lambda purpose: FakeContext())
    return effects


def _wire(cap=128):
    return FakeHttpRequest(ENDPOINT, b"{}", 1.0, cap)


@pytest.mark.parametrize("framing", ["length", "chunked"])
def test_fixed_host_tls_numeric_route_and_whole_deadline(monkeypatch, framing):
    """Catches proxy/DNS/redirect routing, TLS hostname drift or per-read deadline reset."""
    tail = b"Content-Length: 2\r\n\r\n{}" if framing == "length" else \
        b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
    effects = _fake_stack(monkeypatch, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + tail)
    response = FixedHttpsConnector().exchange(_wire(), "synthetic-not-a-real-key", "8.8.8.8", monotonic() + 1)
    assert response.body == b"{}" and response.status_code == 200
    assert ("connect", ("8.8.8.8", 443)) in effects
    sends = [v[1] for v in effects if v[0] == "send"]
    assert len(sends) == 1 and b"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n" in sends[0]
    assert b"Connection: close" in sends[0] and b"Proxy-Authorization" not in sends[0]
    assert all(0 < item[1] <= 1 for item in effects if item[0] == "timeout")


def test_redirect_is_returned_without_followup(monkeypatch):
    effects = _fake_stack(monkeypatch, b"HTTP/1.1 307 Redirect\r\nLocation: https://other.invalid\r\n"
        b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
    response = FixedHttpsConnector().exchange(_wire(), "synthetic-not-a-real-key", "8.8.8.8", monotonic() + 1)
    assert response.status_code == 307
    assert len([v for v in effects if v[0] == "connect"]) == 1


@pytest.mark.parametrize("tail", [b"Content-Length: 999\r\n\r\n{}",
    b"Content-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
    b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
    b"Content-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
    b"Content-Length: 4\r\n\r\n{}"])
def test_framing_compression_caps_and_truncation_fail_closed(monkeypatch, tail):
    """Catches ambiguous or truncated envelopes being accepted as complete output."""
    effects = _fake_stack(monkeypatch, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + tail)
    with pytest.raises(HttpFailure):
        FixedHttpsConnector().exchange(_wire(), "synthetic-not-a-real-key", "8.8.8.8", monotonic() + 1)
    assert len([v for v in effects if v[0] == "connect"]) == 1


def test_timeout_is_fixed_error_without_retry_or_secret_text(monkeypatch):
    effects = _fake_stack(monkeypatch, b"", timeout=True)
    with pytest.raises(HttpFailure) as caught:
        FixedHttpsConnector().exchange(_wire(), "synthetic-not-a-real-key", "8.8.8.8", monotonic() + 1)
    assert caught.value.status == "timeout" and "synthetic-private" not in str(caught.value)
    assert len([v for v in effects if v[0] == "connect"]) == 1


def test_expired_or_private_route_rejected_before_socket(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "socket", lambda *args: pytest.fail("must not create socket"))
    with pytest.raises(ValueError, match="numeric_address"):
        FixedHttpsConnector().exchange(_wire(), "synthetic-not-a-real-key", "127.0.0.1", monotonic() + 1)
    with pytest.raises(TimeoutError):
        FixedHttpsConnector().exchange(_wire(), "synthetic-not-a-real-key", "8.8.8.8", monotonic() - 1)
