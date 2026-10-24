"""Future execution-admission regression SOURCE; no execution during Dirty Mode."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from iac_review.attempts import AttemptJournal
from eval.model.experiment import canonical, digest
from eval.model.provider_http import ProviderTransport
from eval.model.provider_wire import ProviderConfig
from eval.model.transport import FakeTransport
from eval.runner.benchmark import (CheckedTransport, PinnedController, SyntheticAuthority,
    coordinate, load_synthetic_authority, validate_config)
from test_benchmark_coordination import fixture


def test_config_boolean_alone_never_enables_execution(tmp_path, monkeypatch):
    """what_bug_this_catches: fake_only=false accidentally bypasses the explicit execution mode."""
    config, path, price = fixture(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark.verify_case", lambda _: pytest.fail("payload access"))
    with AttemptJournal(path, config.budget, price) as journal:
        with pytest.raises(ValueError, match="before_payload_access"):
            coordinate(replace(config, fake_only=False), journal=journal, transport=FakeTransport())


def test_fake_default_refuses_network_capable_transport_before_access(tmp_path, monkeypatch):
    """what_bug_this_catches: provider identity kind=protocol is mistaken for safe fake mode."""
    config, path, price = fixture(tmp_path)
    provider = ProviderTransport(ProviderConfig("fixture-model", "fixture-version"))
    monkeypatch.setattr("eval.runner.benchmark.verify_case", lambda _: pytest.fail("payload access"))
    with AttemptJournal(path, config.budget, price) as journal:
        with pytest.raises(ValueError, match="fake_mode_refuses"):
            coordinate(config, journal=journal, transport=provider)


def test_explicit_mode_still_requires_actual_external_runtime_bindings(tmp_path, monkeypatch):
    """what_bug_this_catches: a mode string replaces approval, controller or actual shared journal."""
    config, path, price = fixture(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark.verify_case", lambda _: pytest.fail("payload access"))
    with AttemptJournal(path, config.budget, price) as journal:
        with pytest.raises(ValueError, match="explicit_actual_approved_runtime_bindings"):
            coordinate(replace(config, fake_only=False), journal=journal, transport=FakeTransport(),
                       execution_mode="approved_synthetic")


def test_authority_requires_external_exact_byte_pin():
    """what_bug_this_catches: a submitted self-hash or merely valid JSON is treated as approval."""
    raw = canonical({"schema_version": "m4-approved-synthetic-benchmark-v1"}).encode()
    with pytest.raises(ValueError, match="external_synthetic_authority_pin"):
        load_synthetic_authority(raw, expected_sha256="0" * 64)
    with pytest.raises(ValueError, match="closed_explicit_synthetic_authority"):
        load_synthetic_authority(raw, expected_sha256=digest(raw))


def test_heldout_rejected_even_with_explicit_approved_mode(tmp_path):
    """what_bug_this_catches: synthetic execution approval silently authorizes hidden data."""
    config, _, _ = fixture(tmp_path)
    with pytest.raises(ValueError, match="before_payload_access"):
        validate_config(replace(config, fake_only=False, input_scope="heldout"), approved_mode=True)


def test_pinned_controller_rejects_non_admission_before_key_or_connector():
    """what_bug_this_catches: a controller callback returns a loose truthy permission object."""
    authority = SyntheticAuthority(canonical({}), "a" * 64)
    controller = PinnedController(authority, lambda *args: object())
    with pytest.raises(ValueError, match="outside_benchmark_authority"):
        controller(None, None, None)


def test_provider_cannot_use_unstarted_complete_path(tmp_path):
    """what_bug_this_catches: wrapping a provider conceals its durable-start requirement."""
    config, _, _ = fixture(tmp_path)
    provider = ProviderTransport(ProviderConfig("fixture-model", "fixture-version"))
    guard = CheckedTransport(provider, config.cases[0])
    with pytest.raises(ValueError, match="durable_started_dispatch"):
        guard.complete(None)


@pytest.mark.parametrize("public_ids,addresses", ((["public_a", "public_a"], ["raw.a", "raw.b"]),
                                               (["public_a", "public_b"], ["raw.a", "raw.a"])))
def test_scanner_aliases_refuse_many_to_one_and_ambiguous_addresses(public_ids, addresses):
    """what_bug_this_catches: a private alias join overwrites identities or conceals duplicate raw addresses."""
    from eval.runner.benchmark import ApprovedScanner, _scanner_aliases
    from eval.scanners.runner import BoundedSubprocessRunner

    binding = ApprovedScanner(json.dumps({"cases": [{"resources": [
        {"resource_id": "scanner_a", "address": "raw.a"},
        {"resource_id": "scanner_b", "address": "raw.b"}]}]}), BoundedSubprocessRunner())
    product = SimpleNamespace(scanner_resources=tuple(zip(public_ids, addresses)))
    with pytest.raises(ValueError, match="resource_join_mismatch"):
        _scanner_aliases(binding, product)
