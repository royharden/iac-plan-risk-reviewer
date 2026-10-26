"""Addendum02 expectations for pure validation/injected metadata backend logic.

This file never invokes an operational issuer or an actual OS backend. Adapter
operations below are provisional UNTIL exact source API is declared; a missing
operation is an unmet seam, never permission to fake validation in the adapter.
"""
from copy import deepcopy


CASES = []


def case(function):
    CASES.append(function)
    return function


def refused(error_class, operation):
    # Use exact declared source errors; broad Exception/PermissionError aliases
    # must be rejected by future adapter preflight.
    try:
        operation()
    except error_class as error:
        assert type(error) is error_class
        return error
    raise AssertionError('required exact source refusal absent')


@case
def descriptive_nested_authority_exact_three_fields(api):
    document = api.metadata_case()
    expected = {'pin_source': 'independently-root-admitted-invocation',
                'current_dispatch_purpose': 'execute-reviewed-legacy103-via-root-bridge',
                'runtime_approved_digest': None}
    assert document['manifest']['grant_authority'] == expected
    api.parse_metadata_manifest(document)
    for key in expected:
        bad = deepcopy(document)
        del bad['manifest']['grant_authority'][key]
        refused(api.Denied, lambda: api.parse_metadata_manifest(bad))
    for field, value in [('runtime_approved_digest', 'a' * 64),
                         ('runtime_approved_digest', False),
                         ('pin_source', 'selfclaimed'),
                         ('current_dispatch_purpose', 'construction-only-exact-924')]:
        bad = deepcopy(document)
        bad['manifest']['grant_authority'][field] = value
        refused(api.Denied, lambda: api.parse_metadata_manifest(bad))
    bad = deepcopy(document)
    bad['manifest']['grant_authority']['approved'] = True
    refused(api.Denied, lambda: api.parse_metadata_manifest(bad))


@case
def pure_admission_missing_untrusted_and_selfclaimed_root_facts(api):
    facts = api.admission_facts()
    # A successful validator result is DATA only, never a context/approval.
    result = api.validate_admission_facts(facts)
    assert api.is_operational_context(result) is False
    for field, value in [('external_root_admission', None),
                         ('external_root_admission', {'approved': True}),
                         ('external_root_admission', {'caller_digest': 'a' * 64})]:
        bad = deepcopy(facts)
        bad[field] = value
        refused(api.Denied, lambda: api.validate_admission_facts(bad))


@case
def admission_origin_process_and_namespace_facts_exact(api):
    for field in ('source_commit', 'source_tree', 'launcher_path',
                  'launcher_sha256', 'interpreter_path', 'interpreter_sha256',
                  'argv', 'environment', 'cwd', 'process_identity',
                  'namespace_owner', 'namespace_identity', 'receipt_origin'):
        facts = api.admission_facts()
        # Each changed observed fact retains independent expected bindings.
        api.mutate_observed_fact(facts, field)
        refused(api.Denied, lambda: api.validate_admission_facts(facts))


@case
def runtime_authority_ancestors_reject_every_reparse_kind(api):
    for tag in (0xA0000003, 0xA000000C, 0x9000701A, 0x9000601A, 1, 0xFFFFFFFF):
        facts = api.admission_facts()
        api.set_injected_ancestor(facts, reparse=True, tag=tag)
        refused(api.Denied, lambda: api.validate_admission_facts(facts))
    facts = api.admission_facts()
    api.set_injected_ancestor(facts, reparse=False, ordinary=False)
    refused(api.Denied, lambda: api.validate_admission_facts(facts))


@case
def finite_external_joins_do_not_embed_grant_digest_in_manifest(api):
    facts = api.admission_facts()
    assert facts['manifest']['grant_authority']['runtime_approved_digest'] is None
    api.validate_admission_facts(facts)
    for field in ('manifest_sha256', 'grant_sha256', 'anchor_sha256',
                  'invocation_sha256', 'ownership_sha256', 'harness_sha256'):
        bad = deepcopy(facts)
        api.mutate_observed_fact(bad, field)
        refused(api.Denied, lambda: api.validate_admission_facts(bad))


@case
def injected_backend_known_exact_owned_link(api):
    for kind in ('symlink', 'junction'):
        facts = api.backend_facts(kind)
        outcome = api.observe_backend_facts(facts)
        assert outcome['known'] is True
        # Injected metadata qualification is a reviewer report limit, not an
        # invented required field in the source's observer representation.
        assert api.is_operational_context(outcome) is False


@case
def injected_backend_unknown_ownership_identity_kind_and_target(api):
    for field in ('ancestor_ordinary', 'owner_known', 'target_identity',
                  'expected_link_kind', 'link_target', 'parent_identity',
                  'unchanged_target', 'unexpected_event', 'nofollow_complete'):
        facts = api.backend_facts('junction')
        api.mutate_observed_fact(facts, field)
        refused(api.Unknown, lambda: api.observe_backend_facts(facts))


@case
def injected_backend_original_error_retention_and_unknown_cause(api):
    original = OSError('reviewer injected error data only')
    facts = api.backend_facts('symlink')
    facts['original_error'] = original
    outcome = api.observe_backend_facts(facts)
    assert outcome['original_error'] is original
    facts = api.backend_facts('symlink')
    facts['original_error'] = original
    api.mutate_observed_fact(facts, 'owner_known')
    error = refused(api.Unknown, lambda: api.observe_backend_facts(facts))
    assert error.__cause__ is original or getattr(error, 'original_error', None) is original


@case
def injected_backend_timeout_and_retained_receipt_unknown(api):
    for field in ('child_termination_known', 'pre_receipt_unchanged',
                  'post_receipt_retained', 'exclusive_receipt_creation',
                  'bounded_metadata_complete'):
        facts = api.backend_facts('junction')
        api.mutate_observed_fact(facts, field)
        refused(api.Unknown, lambda: api.observe_backend_facts(facts))
