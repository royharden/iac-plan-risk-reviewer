"""Inert review model. No actual context factory or native dispatcher exists."""
from copy import deepcopy
from dataclasses import dataclass
import base64
import re
from subprocess import CompletedProcess

from .audit_window import ExactInertWindow, ORIGINAL_THREAD, render_call, validate_relation
from .errors import (ActualObserverUnavailable, ActualTrustUnavailable, Denied, Unknown,
                     sanitized_stop_reason)
from .observer import observe_inert
from .runtime_manifest import (GrantData, InvocationData, ManifestData, canonical, digest,
                              exact_value, hex64, lexical, load_frozen_bindings, need,
                              parse_grant, parse_invocation, parse_manifest, summarize_results)


@dataclass(frozen=True)
class InertDispatchMarker:
    """Injected event/result/error data, deliberately not a callable dispatcher."""
    events: tuple
    result: object = None
    error: BaseException | None = None


class InertContext:
    def __init__(self, manifest, grant, invocation, *, tokens, pin_reader, observation_reader, receipt_store):
        need(type(manifest) is ManifestData and type(grant) is GrantData and type(invocation) is InvocationData, 'parsed record types required')
        parse_manifest(manifest.raw, expected_harness_pins=manifest.document['harness_pins'], frozen=load_frozen_bindings())
        parse_grant(grant.raw, manifest=manifest)
        parse_invocation(invocation.raw, manifest=manifest, grant=grant)
        slots = manifest.document['slots']
        need(type(tokens) is dict and set(tokens) == {s['slot'] for s in slots}, 'eight inert tokens required')
        need(all(type(v) is str and re.fullmatch('[A-Za-z0-9-]{16,256}', v) for v in tokens.values()), 'plain public token format')
        need(len(set(tokens.values())) == 8, 'distinct slot tokens required')
        need(all(digest(tokens[s['slot']].encode('utf-8')) == grant.document['slots'][s['slot']]['token_sha256'] for s in slots), 'token hash binding differs')
        need(callable(pin_reader) and callable(observation_reader), 'inert readers required')
        need(all(callable(getattr(receipt_store, name, None)) for name in ('create_pre', 'read_pre', 'create_post', 'read_post', 'mark_unknown')), 'inert receipt store interface')
        self._manifest, self._grant, self._invocation = manifest, grant, invocation
        self._tokens = deepcopy(tokens)
        self._pin_reader, self._observation_reader, self._store = pin_reader, observation_reader, receipt_store
        self._node = None
        self._poison_reason = None
        self._poison_cause = None
        self._pending = None
        self._preparing_relation = None
        self._window = ExactInertWindow(self)
        self._finished = set()
        self._results = {}
        self._thread = ORIGINAL_THREAD()
        self.require_exact()

    @property
    def raw(self):
        return self._grant.raw

    @property
    def grant_sha256(self):
        return self._grant.sha256

    @property
    def poisoned(self):
        return self._poison_reason is not None

    @property
    def pending_action(self):
        if self._pending is None:
            return None
        return {k: deepcopy(v) for k, v in self._pending.items() if k != 'clock'}

    def _poison(self, reason, cause=None):
        if self._poison_reason is not None:
            return
        self._poison_reason, self._poison_cause = reason, cause
        if self._pending is not None:
            try:
                self._store.mark_unknown(deepcopy(self._pending['slot']), self._poison_reason)
            except BaseException:
                # Poison is already persistent even if retaining its receipt fails.
                pass

    def stop_inert(self, reason, cause=None):
        """Latch an outer adapter failure without effects or pending-state repair."""
        if self._poison_reason is None:
            self._poison_reason = sanitized_stop_reason(reason)
            self._poison_cause = cause if isinstance(cause, BaseException) else None

    def require_exact(self, *expected):
        try:
            if self.poisoned:
                raise Denied('context permanently poisoned') from self._poison_cause
            need(len(expected) == 0 or (len(expected) == 2 and all(hex64(v) for v in expected)
                 and expected == (self._manifest.sha256, self.grant_sha256)), 'zero or exact two-hash form required')
            parse_grant(self.raw, manifest=self._manifest)
            parse_invocation(self._invocation.raw, manifest=self._manifest, grant=self._grant)
            m = self._manifest.document
            root, snapshot = lexical(m['runroot']), lexical(m['snapshot'])
            pins = {str(root / 'OWNERSHIP.json'): m['namespace_ownership_sha256']}
            pins.update({str(snapshot.joinpath(*name.split('/'))): row['sha256'] for name, row in m['closure32'].items()})
            # Harness pins name this source edition, not the future runtime namespace.
            from pathlib import Path
            lane = lexical(str(Path(__file__).parent))
            pins.update({str(lane / name): value for name, value in m['harness_pins'].items()})
            pins[m['interpreter']['path']] = m['interpreter']['sha256']
            pins[m['powershell']['path']] = m['powershell']['sha256']
            pins[m['powershell']['resolved_path']] = m['powershell']['sha256']
            for path, expected_hash in pins.items():
                actual = self._pin_reader(path)
                need(type(actual) is str and actual == expected_hash, 'inert file pin changed: ' + path)
        except BaseException as exc:
            self._poison('exact input/pin check failed', exc)
            raise

    @property
    def current_node(self):
        return self._node

    @current_node.setter
    def current_node(self, value):
        try:
            need(self._window.active is None and (self._pending is None or value is None), 'active/pending action prohibits node change')
            if value is not None:
                self.require_exact()
                need(type(value) is str and value in load_frozen_bindings().ordered, 'exact103 node required')
            self._node = value
        except BaseException as exc:
            self._poison('node binding failed', exc)
            raise

    def _slot(self, slot):
        need(type(slot) is dict and any(exact_value(slot, s) for s in self._manifest.document['slots']), 'exact full slot required')
        need(self.current_node == slot['nodeid'], 'active node differs')
        return slot

    def token(self, slot):
        try:
            self.require_exact()
            self._slot(slot)
            return self._tokens[slot['slot']]
        except BaseException as exc:
            self._poison('token lookup failed', exc)
            raise

    def _pre(self, slot, call):
        relation = self._preparing_relation if self._pending is None else self._pending['relation']
        need(relation is not None, 'correlated relation missing')
        return {'schema': 'legacy103-inert-action-pre-v1', 'slot': deepcopy(slot), 'nodeid': self.current_node,
                'manifest_sha256': self._manifest.sha256, 'external_grant_sha256': self.grant_sha256,
                'invocation_sha256': self._invocation.sha256, 'nonce_sha256': digest(self.token(slot).encode('utf-8')),
                'relation': deepcopy(relation), 'actual_call': deepcopy(call), 'synthetic': True,
                'status': 'CONSUMED_BEFORE_INERT_EVENT_NOT_SUCCESS'}

    def effect_window(self, slot, call, pre_receipt_sha256):
        return self._window.open(slot, call, pre_receipt_sha256)

    def audit(self, event, args):
        self._poison('actual audit entry attempted')
        raise ActualTrustUnavailable('actual audit authority is uninstalled')

    def audit_inert(self, event, args):
        self._window.audit_inert(event, args)

    def observe_original(self, relation, result, error):
        self._poison('actual observer entry attempted')
        raise ActualObserverUnavailable('actual observer is uninstalled')

    def observe_inert(self, relation, result, error):
        try:
            self.require_exact()
            need(self._window.active is None and self._pending is not None, 'observation requires retained pending action after exit')
            need(self._node == self._pending['slot']['nodeid'], 'observation node differs')
            state = self._observation_reader(deepcopy(relation), result, error)
            return observe_inert(self._pending, relation, result, error, state)
        except BaseException as exc:
            self._poison('post-event observation UNKNOWN', exc)
            if isinstance(exc, Unknown):
                raise
            raise Unknown('post-event observation UNKNOWN') from (error if error is not None else exc)

    def handle_inert(self, nodeid, call, marker):
        original_error = None
        try:
            self.require_exact()
            need(type(marker) is InertDispatchMarker and type(marker.events) is tuple and not callable(marker), 'non-callable inert marker required')
            need(marker.error is None or isinstance(marker.error, BaseException), 'original error data required')
            original_error = marker.error
            need(type(nodeid) is str and self.current_node == nodeid, 'active node required')
            slots = [s for s in self._manifest.document['slots'] if s['nodeid'] == nodeid]
            need(len(slots) == 1, 'exact setup slot node required')
            slot = slots[0]
            need(slot['slot'] not in self._window.completed and self._pending is None, 'action replay/pending')
            # The reviewer supplies a closed pre-effect relation through its inert reader.
            relation = self._observation_reader(None, None, None)
            self._preparing_relation = validate_relation(self._manifest, slot, relation)
            need(exact_value(call, render_call(self._manifest, slot, self._preparing_relation)), 'exact original raw call required')
            pre = self._pre(slot, call)
            need(len(canonical(pre)) <= 65536, 'bounded pre receipt')
            pre_sha = self._store.create_pre(deepcopy(slot), deepcopy(pre))
            need(hex64(pre_sha) and pre_sha == digest(canonical(pre)), 'pre persistence hash differs')
            with self.effect_window(slot, call, pre_sha):
                for item in marker.events:
                    need(type(item) is tuple and len(item) == 2, 'injected event pair required')
                    self.audit_inert(item[0], item[1])
            observed = self.observe_inert(self._preparing_relation, marker.result, marker.error)
            # Serialize original outcome as bounded metadata; return/raise the original object.
            if marker.error is not None:
                outcome = {'error_type': type(marker.error).__name__, 'error_message': str(marker.error)}
            elif slot['kind'] == 'junction':
                result = marker.result
                need(type(result) is CompletedProcess and type(result.returncode) is int
                     and type(result.stdout) is bytes and type(result.stderr) is bytes
                     and exact_value(result.args, call['args'][0]), 'original junction result data required')
                outcome = {'returncode': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode('ascii'),
                           'stderr_base64': base64.b64encode(result.stderr).decode('ascii')}
            else:
                need(marker.result is None, 'original symlink return is None')
                outcome = {'return_value': marker.result}
            need(exact_value(self._store.read_pre(deepcopy(slot)), pre), 'pre receipt changed after injected dispatch')
            post = {'schema': 'legacy103-inert-action-post-v1', 'slot': deepcopy(slot),
                    'pre_sha256': pre_sha, 'observation': observed, 'outcome': outcome,
                    'synthetic': True, 'actual_link_verified': False}
            need(len(canonical(post)) <= 65536, 'bounded post receipt')
            post_sha = self._store.create_post(deepcopy(slot), deepcopy(post))
            need(hex64(post_sha) and post_sha == digest(canonical(post)), 'post persistence hash differs')
            need(exact_value(self._store.read_post(deepcopy(slot)), post), 'post readback differs')
            self._finished.add(slot['slot'])
            self._pending = None
            self._preparing_relation = None
        except BaseException as exc:
            self._poison('inert action failed/UNKNOWN', exc)
            if self._pending is not None:
                raise Unknown('retained pending action UNKNOWN') from (original_error if original_error is not None else exc)
            raise
        if original_error is not None:
            self._poison('original error recorded; remaining actions blocked', original_error)
            raise original_error
        return marker.result

    def record_result_inert(self, nodeid, status):
        try:
            self.require_exact()
            need(self._pending is None and self._window.active is None, 'pending action blocks result')
            need(type(nodeid) is str and nodeid in load_frozen_bindings().ordered and nodeid not in self._results, 'exact103 nonreplayed result')
            need(type(status) is str and status in ('PASS', 'FAIL'), 'explicit inert result required')
            self._results[nodeid] = status
        except BaseException as exc:
            self._poison('result check failed', exc)
            raise

    def check_complete_inert(self):
        try:
            self.require_exact()
            frozen = load_frozen_bindings()
            need(self._pending is None and self._window.active is None
                 and self._finished == {s['slot'] for s in frozen.slots}
                 and set(self._results) == set(frozen.ordered), 'eight slots and complete103 results required')
            summary = summarize_results([{'nodeid': node, 'status': status}
                                         for node, status in self._results.items()])
            return {'synthetic': True, 'actual_runtime_verified': False, 'slots': 8,
                    **summary}
        except BaseException as exc:
            self._poison('incomplete result check', exc)
            raise


def load_actual_context(*args, **kwargs):
    raise ActualTrustUnavailable('actual root trust is uninstalled')


def run_original(*args, **kwargs):
    raise ActualTrustUnavailable('actual root trust is uninstalled')
