"""Independent r1 inert tests. No producer imports, native calls or authority files.

CASE functions receive a mechanically reconciled, preflight-approved adapter.
Missing implementation/seams are failures or not_run, never passing skips.
"""
from copy import deepcopy
import hashlib
import json


CASES = []
SOURCE = '924a9a40d2a597c723887952d82807b517ffec8b'
TREE = '8907bd4007d3f2f8f8a94c86b355bf3c6181aab2'
GRANT_KEYS = {'schema', 'manifest_sha256', 'source_commit', 'source_tree',
              'runroot', 'slots', 'purpose'}
SLOT_KEYS = {'nodeid', 'event', 'token_sha256'}


def case(function):
    CASES.append(function)
    return function


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def validate_case(api, data, raw=None):
    # Repin only inert input metadata so malformed-schema tests actually reach
    # closed/type/canonical checks, rather than passing on stale digest refusal.
    # No independently installed actual root approval can be made by this seam.
    if raw is None:
        raw = canonical(data['grant'])
    trust = api.repin_inert(data, raw)
    return api.validate(data['manifest'], raw, trust)


def refused(error_type, operation):
    try:
        operation()
    except error_type as error:
        return error
    raise AssertionError('required refusal absent')


def fresh(api, kind='symlink'):
    data = api.make_case(kind)
    assert data['manifest']['source_commit'] == SOURCE
    assert data['manifest']['source_tree'] == TREE
    assert len(data['manifest']['slots']) == 8
    assert len(data['results103']) == 103
    assert len(set(data['results103'])) == 103
    assert set(data['slots8']) == {f'{i:02}' for i in range(1, 9)}
    assert set(data['grant']) == GRANT_KEYS
    assert data['grant']['schema'] == 'legacy103-external-INT-grant-r2'
    assert data['grant']['purpose'] == 'execute-reviewed-legacy103'
    assert set(data['grant']['slots']) == set(data['slots8'])
    assert all(set(entry) == SLOT_KEYS for entry in data['grant']['slots'].values())
    return data


def bound(api, kind='symlink'):
    data = fresh(api, kind)
    context = api.bind_inert(data)
    context.current_node = data['slot']['nodeid']
    return data, context


def window(api, data, context, audit=True):
    with context.effect_window(data['slot'], data['call'], data['prehash']):
        assert api.inspect(context)['active'] is not None
        if audit:
            context.audit_inert(data['event'], data['audit_args'])
    assert api.inspect(context)['active'] is None


def all_slots(api, count=8):
    data, context = bound(api)
    selected = data['slots8'][:count]
    for slot_id in selected:
        item = api.slot_case(data, slot_id)
        assert item['manifest'] == data['manifest']
        assert item['grant'] == data['grant']
        assert item['slot']['slot'] == slot_id
        context.current_node = item['slot']['nodeid']
        window(api, item, context)
        context.observe_inert(item['relation'], item['result'], None)
    assert set(api.inspect(context)['used']) == set(selected)
    assert api.inspect(context)['poisoned'] is False
    return data, context


@case
def honest_runtime_version_purpose(api):
    data = fresh(api)
    assert data['manifest']['schema'] == 'legacy103-runtime-manifest-v1'
    assert data['manifest']['purpose'] == 'execute-reviewed-legacy103-via-root-bridge'
    assert type(data['manifest']['watchdog_seconds']) is int
    assert data['manifest']['watchdog_seconds'] == 180
    assert type(data['manifest']['junction_timeout_seconds']) is int
    assert data['manifest']['junction_timeout_seconds'] == 20
    validate_case(api, data)


@case
def old_construction_and_synthetic_refuse(api):
    for field, values in (
        ('schema', ['legacy103-pre-effect-r2', 'legacy103-external-INT-grant-dag-v1']),
        ('purpose', ['construction-only-exact-924', 'synthetic-inert-controls-only']),
    ):
        for value in values:
            data = fresh(api)
            data['manifest'][field] = value
            refused(api.Denied, lambda: validate_case(api, data))
    for field, value in [('schema', 'legacy103-external-INT-grant-dag-v1'),
                         ('purpose', 'synthetic-inert-controls-only')]:
        data = fresh(api)
        data['grant'][field] = value
        refused(api.Denied, lambda: validate_case(api, data))


@case
def absent_and_selfclaimed_operational_trust_refuse(api):
    for trust in (None, {}, {'approved': True}, {'sha256': 'a' * 64},
                  {'context': 'selfclaimed'}, {'environment_digest': 'a' * 64}):
        data = fresh(api)
        refused(api.Denied, lambda: api.operational_entry(data, trust))
    # The explicit positive inert seam is also not actual operational trust.
    data = fresh(api)
    refused(api.Denied, lambda: api.operational_entry(data, data['trust']))


@case
def require_exact_zero_two_and_composition(api):
    data, context = bound(api)
    hashes = digest(canonical(data['manifest'])), digest(canonical(data['grant']))
    assert context.raw == canonical(data['grant'])
    assert context.grant_sha256 == hashes[1]
    context.require_exact()
    context.require_exact(*hashes)
    window(api, data, context)
    # ExactAuditWindow has its own zero-argument callback: composition cannot
    # replace the public method with a callback lacking its two-hash form.
    context.require_exact()
    context.require_exact(*hashes)


@case
def require_exact_arity_and_hash_mismatch(api):
    for args in [('a' * 64,), ('a' * 64,) * 3,
                 ('b' * 64, 'a' * 64), ('a' * 64, 'b' * 64),
                 (None, None), (True, False)]:
        data, context = bound(api)
        # Declarative r1 API explicitly declares Denied for wrong arity/types.
        refused(api.Denied, lambda: context.require_exact(*args))


@case
def immutable_grant_and_hash(api):
    data, context = bound(api)
    raw, pin = context.raw, context.grant_sha256
    assert type(raw) is bytes and type(pin) is str
    for field, value in [('raw', b'{}'), ('grant_sha256', 'b' * 64)]:
        refused((api.Denied, AttributeError, TypeError), lambda: setattr(context, field, value))
    data['grant']['purpose'] = 'synthetic-inert-controls-only'
    assert context.raw == raw and context.grant_sha256 == pin
    context.require_exact()


@case
def closed_seven_key_and_nested_slot_grant(api):
    for key in sorted(GRANT_KEYS):
        data = fresh(api)
        del data['grant'][key]
        refused(api.Denied, lambda: validate_case(api, data))
    for extra in ('nonce_metadata_sha256', 'approved', 'context', 'unknown'):
        data = fresh(api)
        data['grant'][extra] = 'a' * 64
        refused(api.Denied, lambda: validate_case(api, data))
    for slot_id in [f'{i:02}' for i in range(1, 9)]:
        for key in sorted(SLOT_KEYS):
            data = fresh(api)
            del data['grant']['slots'][slot_id][key]
            refused(api.Denied, lambda: validate_case(api, data))
        data = fresh(api)
        data['grant']['slots'][slot_id]['approved'] = True
        refused(api.Denied, lambda: validate_case(api, data))


@case
def missing_extra_duplicate_slot_identity(api):
    for mode in ('missing', 'extra', 'duplicate_node', 'event', 'token'):
        data = fresh(api)
        slots = data['grant']['slots']
        if mode == 'missing': del slots['08']
        elif mode == 'extra': slots['09'] = deepcopy(slots['08'])
        elif mode == 'duplicate_node': slots['08']['nodeid'] = slots['01']['nodeid']
        elif mode == 'event': slots['01']['event'] = 'subprocess.Popen'
        else: slots['01']['token_sha256'] = '0' * 64
        refused(api.Denied, lambda: validate_case(api, data))


@case
def strict_types_and_canonical_bytes(api):
    for field in sorted(GRANT_KEYS):
        for value in (None, True, 1, [], {}):
            data = fresh(api)
            data['grant'][field] = value
            refused(api.Denied, lambda: validate_case(api, data))
    data = fresh(api)
    raw = canonical(data['grant'])
    bad = [raw + b'\n', b' ' + raw, raw.decode('utf-8').encode('utf-16'),
           json.dumps(data['grant'], indent=2).encode(),
           b'{"schema":"duplicate",' + raw[1:], b'{"value":NaN}',
           b'{"value":Infinity}', raw.replace(b'"slots":{', b'"slots":null,"slots":{')]
    for value in bad:
        refused(api.Denied, lambda: validate_case(api, data, value))


@case
def strict_hashes_and_external_trust(api):
    for field in ('manifest_sha256',):
        for value in ('A' * 64, 'g' * 64, 'a' * 63, 'a' * 65, '', True):
            data = fresh(api)
            data['grant'][field] = value
            refused(api.Denied, lambda: validate_case(api, data))
    for trust in (None, {}, {'grant_sha256': 'b' * 64}):
        data = fresh(api)
        refused(api.Denied, lambda: api.validate(data['manifest'], canonical(data['grant']), trust))


@case
def source_origin_namespace_receipt_mismatch(api):
    for field, value in [('source_commit', '0' * 40), ('source_tree', '1' * 40),
                         ('runroot', r'C:\foreign\root'), ('manifest_sha256', 'f' * 64)]:
        data = fresh(api)
        data['grant'][field] = value
        refused(api.Denied, lambda: validate_case(api, data))
    for state in ('source_changed', 'origin_changed', 'namespace_changed', 'receipt_changed'):
        data, context = bound(api)
        api.observe_state(context, **{state: True})
        refused(api.Denied, context.require_exact)


@case
def finite_binding_order_and_cycles(api):
    data = fresh(api)
    api.verify_binding(data, data['binding_edges'])
    # Direction is dependent -> prerequisite. Invocation is outside closure.
    for edge in [('manifest', 'invocation'), ('grant', 'invocation'),
                 ('anchor', 'invocation'), ('source', 'manifest'),
                 ('invocation', 'invocation')]:
        refused(api.Denied, lambda: api.verify_binding(data, data['binding_edges'] + [edge]))


@case
def token_exact_slot_not_alias(api):
    data, context = bound(api)
    assert type(context.token(data['slot'])) is str
    for field, value in [('slot', '09'), ('nodeid', 'foreign'),
                         ('event', 'socket.connect'), ('kind', 'device')]:
        data, context = bound(api)
        bad = deepcopy(data['slot'])
        bad[field] = value
        refused(api.Denied, lambda: context.token(bad))


@case
def prehash_malformed_and_reentry(api):
    for prehash in (None, True, '', 'a' * 63, 'A' * 64, 'g' * 64):
        data, context = bound(api)
        def attempt():
            with context.effect_window(data['slot'], data['call'], prehash):
                raise AssertionError('bad receipt reached dispatch marker')
        refused(api.Denied, attempt)
    data, context = bound(api)
    def nested():
        with context.effect_window(data['slot'], data['call'], data['prehash']):
            with context.effect_window(data['slot'], data['call'], data['prehash']):
                raise AssertionError('nested marker reached')
    refused(api.Denied, nested)
    assert api.inspect(context)['poisoned'] is True


@case
def pending_survives_window_exit_observer_after_exit(api):
    data, context = bound(api)
    window(api, data, context)
    state = api.inspect(context)
    assert state['active'] is None and state['pending'] is not None
    assert data['slot']['slot'] in state['used']
    marker = object()
    result = context.observe_inert(data['relation'], marker, None)
    assert result is marker or (type(result) is dict and result.get('known') is True)
    assert api.inspect(context)['pending'] is None


@case
def observer_inside_window_refuses_and_poisons(api):
    data, context = bound(api)
    def attempt():
        with context.effect_window(data['slot'], data['call'], data['prehash']):
            context.audit_inert(data['event'], data['audit_args'])
            context.observe_inert(data['relation'], None, None)
    refused((api.Denied, api.Unknown), attempt)
    assert api.inspect(context)['poisoned'] is True


@case
def observation_no_pending_replay_wrong_relation(api):
    data, context = bound(api)
    refused((api.Denied, api.Unknown), lambda: context.observe_inert(data['relation'], None, None))
    data, context = bound(api)
    window(api, data, context)
    context.observe_inert(data['relation'], None, None)
    refused((api.Denied, api.Unknown), lambda: context.observe_inert(data['relation'], None, None))
    data, context = bound(api)
    window(api, data, context)
    bad = deepcopy(data['relation'])
    bad['target'] += '-foreign'
    refused((api.Denied, api.Unknown), lambda: context.observe_inert(bad, None, None))
    assert api.inspect(context)['poisoned'] is True


@case
def current_node_and_injected_thread_mismatch(api):
    data, context = bound(api)
    # Select another valid103 node so the window/node join, rather than the
    # controlled setter's membership check, is the rule under test.
    context.current_node = next(node for node in data['results103']
                                if node != data['slot']['nodeid'])
    refused(api.Denied, lambda: window(api, data, context))
    data, context = bound(api)
    def wrong_thread():
        with context.effect_window(data['slot'], data['call'], data['prehash']):
            api.set_thread(context, 'reviewer-different-thread')
            context.audit_inert(data['event'], data['audit_args'])
    refused(api.Denied, wrong_thread)
    assert api.inspect(context)['poisoned'] is True


@case
def outside_missing_duplicate_event_replay(api):
    data, context = bound(api)
    refused(api.Denied, lambda: context.audit_inert(data['event'], data['audit_args']))
    data, context = bound(api)
    refused(api.Denied, lambda: window(api, data, context, audit=False))
    assert api.inspect(context)['poisoned'] is True
    data, context = bound(api)
    def duplicate():
        with context.effect_window(data['slot'], data['call'], data['prehash']):
            context.audit_inert(data['event'], data['audit_args'])
            context.audit_inert(data['event'], data['audit_args'])
    refused(api.Denied, duplicate)
    assert api.inspect(context)['poisoned'] is True
    data, context = bound(api)
    window(api, data, context)
    refused(api.Denied, lambda: window(api, data, context))


@case
def caught_mismatch_persistent_poison(api):
    data, context = bound(api)
    def caught():
        with context.effect_window(data['slot'], data['call'], data['prehash']):
            refused(api.Denied, lambda: context.audit_inert(data['event'], ('bad',)))
    refused(api.Denied, caught)
    assert api.inspect(context)['poisoned'] is True
    refused(api.Denied, lambda: setattr(context, 'current_node', data['slot']['nodeid']))
    refused(api.Denied, context.require_exact)
    refused(api.Denied, lambda: window(api, data, context))


@case
def unexpected_nonoperational_audit_observations(api):
    for event in ('socket.connect', 'os.remove', 'os.symlink', 'subprocess.Popen',
                  'os.startfile/2', 'os.exec', 'os.spawn', 'os.fork'):
        data, context = bound(api)
        def attempt():
            with context.effect_window(data['slot'], data['call'], data['prehash']):
                context.audit_inert(event, ('foreign',))
        refused(api.Denied, attempt)
        assert api.inspect(context)['poisoned'] is True


@case
def original_error_identity_and_unknown_precedence(api):
    data = fresh(api)
    context = api.bind_for_handle(data)
    context.current_node = data['slot']['nodeid']
    original = OSError('reviewer inert original error')
    marker = api.make_marker(data, result=None, error=original)
    error = refused(OSError, lambda: context.handle_inert(data['slot']['nodeid'], data['call'], marker))
    assert error is original
    assert api.inspect(context)['poisoned'] is True
    data = fresh(api)
    context = api.bind_for_handle(data)
    context.current_node = data['slot']['nodeid']
    api.observe_state(context, known=False)
    marker = api.make_marker(data, result=None, error=original)
    unknown = refused(api.Unknown, lambda: context.handle_inert(data['slot']['nodeid'], data['call'], marker))
    assert unknown.__cause__ is original or getattr(unknown, 'original_error', None) is original
    assert api.inspect(context)['poisoned'] is True


@case
def actual_audit_and_original_observer_unavailable(api):
    data, context = bound(api)
    refused(api.Denied, lambda: context.audit(data['event'], data['audit_args']))
    data, context = bound(api)
    refused(api.ActualObserverUnavailable,
            lambda: context.observe_original(data['relation'], data['result'], None))


@case
def observer_unknown_ownership_state_receipt_termination(api):
    for state in ('unknown_owner', 'target_changed', 'unexpected_link_kind',
                  'receipt_changed', 'receipt_failure', 'child_termination_unknown'):
        data, context = bound(api)
        window(api, data, context)
        api.observe_state(context, **{state: True})
        refused(api.Unknown, lambda: context.observe_inert(data['relation'], None, None))
        assert api.inspect(context)['poisoned'] is True


@case
def raw_call_type_exactness(api):
    for kind in ('symlink', 'junction'):
        for mutation in ('args_tuple', 'extra_kw', 'wrong_api', 'bool_timeout',
                         'float_timeout', 'false_directory', 'different_cwd'):
            data, context = bound(api, kind)
            call = deepcopy(data['call'])
            if mutation == 'args_tuple': call['args'] = tuple(call['args'])
            elif mutation == 'extra_kw': call['kwargs']['unapproved'] = None
            elif mutation == 'wrong_api': call['api'] = 'os.startfile'
            elif mutation == 'false_directory':
                if kind != 'symlink': continue
                call['kwargs']['target_is_directory'] = 1
            elif mutation in ('bool_timeout', 'float_timeout'):
                if kind != 'junction': continue
                call['kwargs']['timeout'] = True if mutation == 'bool_timeout' else 20.0
            else: call['inherited_cwd'] = r'C:\foreign'
            def attempt():
                with context.effect_window(data['slot'], call, data['prehash']):
                    raise AssertionError('changed raw tuple reached marker')
            refused(api.Denied, attempt)


@case
def windows_lowered_tuple_exactness(api):
    data, context = bound(api, 'junction')
    lowered = api.lower(data['call'])
    assert type(lowered) is tuple and len(lowered) == 4
    assert lowered[0] is None and lowered[2] is None
    assert type(lowered[1]) is str
    assert lowered[3] == data['call']['kwargs']['env']
    assert lowered == data['audit_args']
    for replacement in (tuple(data['call']['args'][0]),
                        (data['call']['args'][0][0], lowered[1], None, lowered[3]),
                        (None, data['call']['args'][0], None, lowered[3]),
                        (None, lowered[1], data['call']['inherited_cwd'], lowered[3]),
                        (None, lowered[1] + ' ', None, lowered[3]),
                        list(lowered)):
        data, context = bound(api, 'junction')
        def attempt():
            with context.effect_window(data['slot'], data['call'], data['prehash']):
                context.audit_inert('subprocess.Popen', replacement)
        refused(api.Denied, attempt)


@case
def completeness_all103_and_all8(api):
    for mode in ('missing_result', 'extra_result', 'duplicate_result',
                 'reordered', 'seven_slots', 'poison'):
        data, context = all_slots(api, count=7 if mode == 'seven_slots' else 8)
        results = list(data['results103'])
        if mode == 'missing_result': results.pop()
        elif mode == 'extra_result': results.append('foreign')
        elif mode == 'duplicate_result': results[-1] = results[0]
        elif mode == 'reordered': results[0], results[1] = results[1], results[0]
        elif mode == 'poison': api.observe_state(context, known=False, poisoned=True)
        # UNCONFIRMED pre-source predicate: 'reordered' requires INT to decide
        # recording order versus canonical final ordered evidence. Retain it
        # as a question, never call its disagreement alone a source defect.
        def attempt():
            for nodeid in results:
                context.record_result_inert(nodeid, 'PASS')
            context.check_complete_inert()
        refused(api.Denied, attempt)
    for status in (None, True, 1, 'pass', 'UNKNOWN', [], {}):
        data, context = all_slots(api)
        refused(api.Denied, lambda: context.record_result_inert(data['results103'][0], status))


@case
def honest_all8_and_complete103_positive(api):
    data, context = all_slots(api)
    for nodeid in data['results103']:
        context.record_result_inert(nodeid, 'PASS')
    context.check_complete_inert()
    assert api.inspect(context)['poisoned'] is False


def suite_names():
    return [function.__name__ for function in CASES]
