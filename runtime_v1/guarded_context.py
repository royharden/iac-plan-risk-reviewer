"""Dormant guarded adapter. Independent root admission has NOT been installed."""
from contextlib import contextmanager
from copy import deepcopy
import base64
import re
from subprocess import CompletedProcess
import threading
import time

from .audit_window import ORIGINAL_CLOCK, ORIGINAL_THREAD, lowered_event, render_call, validate_relation
from .errors import ActualTrustUnavailable, Denied, Unknown
from .metadata_backend import Metadata, ordinary_chain
from .origin_validation import _read, observe_owned, validate_origin
from .runtime_manifest import (canonical, closed, decode_canonical, digest, exact_value, hex64,
                              lexical, load_frozen_bindings, need, parse_grant, parse_manifest,
                              summarize_results)


def _root_admission():
    # No argument/env/digest/test callback can supply this edge. INT must select
    # and independently review exact external artifact origin/owner/process facts.
    raise ActualTrustUnavailable('root-admission artifact/origin/owner/process policy is not installed')


class GuardedContext:
    def __init__(self):
        # Intentionally refuses BEFORE any file read, backend construction or issuance.
        facts, backend, process, tokens = _root_admission()
        data = validate_origin(facts, backend, process)
        self._manifest = parse_manifest(data.manifest_raw,
            expected_harness_pins=decode_canonical(data.manifest_raw)['harness_pins'], frozen=load_frozen_bindings())
        self._grant = parse_grant(data.grant_raw, manifest=self._manifest)
        self._facts, self._backend, self._process = facts, backend, deepcopy(process)
        self._data = data
        need(type(tokens) is dict and set(tokens) == set(self._grant.document['slots']), 'exact eight public tokens')
        need(all(type(v) is str and re.fullmatch('[A-Za-z0-9-]{16,256}', v) for v in tokens.values())
             and len(set(tokens.values())) == 8, 'distinct bounded public tokens')
        need(all(digest(v.encode('utf-8')) == self._grant.document['slots'][k]['token_sha256'] for k, v in tokens.items()), 'token pins differ')
        self._tokens = deepcopy(tokens)
        self._thread = ORIGINAL_THREAD()
        self._node, self._active, self._pending = None, None, None
        self._poison_reason = None
        self._used, self._finished = set(), set()

    @property
    def raw(self):
        return self._grant.raw

    @property
    def grant_sha256(self):
        return self._grant.sha256

    @property
    def manifest_raw(self):
        return self._manifest.raw

    def _fail(self, reason, cause=None):
        if self._poison_reason is None:
            self._poison_reason = reason
        # Original Protocol owns retained pre/post/UNKNOWN writers. Never clean up.
        raise Unknown(reason) from cause

    def _check_post(self):
        pending = self._pending
        if pending is None or 'observation' not in pending:
            return
        original_error = pending['original_error']
        try:
            path = str(lexical(self._manifest.document['runroot']) / 'live-action-receipts' / ('slot-' + pending['slot']['slot'] + '-post.json'))
            post = decode_canonical(_read(self._backend, path))
            expected = {'schema': 'legacy103-action-post-r2', 'pre_receipt_sha256': pending['pre_sha256'],
                        'slot': pending['slot']['slot'], 'result': pending['outcome'],
                        'observation': pending['observation'],
                        'status': ('ORIGINAL_API_ERROR_RECORDED' if original_error is not None
                                   else 'ORIGINAL_API_RETURN_RECORDED')}
            need(exact_value(post, expected), 'retained post receipt differs')
        except BaseException as exc:
            self._fail('post receipt/readback UNKNOWN; pending retained',
                       original_error if original_error is not None else exc)
        self._finished.add(pending['slot']['slot'])
        self._pending = None
        if original_error is not None:
            self._poison_reason = 'original error recorded; remaining effects blocked'
            raise original_error

    def require_exact(self, *expected):
        try:
            need(self._poison_reason is None, 'context permanently poisoned')
            need(time.monotonic is ORIGINAL_CLOCK and threading.get_ident is ORIGINAL_THREAD
                 and ORIGINAL_THREAD() == self._thread, 'original clock/thread required')
            need(len(expected) == 0 or (len(expected) == 2 and all(hex64(v) for v in expected)
                 and expected == (self._manifest.sha256, self.grant_sha256)), 'zero or exact two hashes required')
            # Re-admission is independently sourced, not cached caller input.
            facts, backend, process, tokens = _root_admission()
            need(facts == self._facts and backend is self._backend and exact_value(tokens, self._tokens), 'independent admission changed')
            data = validate_origin(facts, backend, process)
            need(exact_value(data, self._data) and exact_value(process, self._process), 'bound origin/process changed')
            self._check_post()
        except BaseException as exc:
            self._poison_reason = self._poison_reason or 'exact binding failed'
            raise

    @property
    def current_node(self):
        return self._node

    @current_node.setter
    def current_node(self, value):
        try:
            need(self._active is None, 'node change inside action window')
            if value is not None:
                self.require_exact()
                need(self._pending is None and type(value) is str and value in load_frozen_bindings().ordered, 'exact103 node without pending action required')
            self._node = value
        except BaseException:
            self._poison_reason = self._poison_reason or 'node change failed'
            raise

    def _slot(self, slot):
        need(any(exact_value(slot, s) for s in self._manifest.document['slots']) and self._node == slot['nodeid'], 'exact full active slot required')

    def token(self, slot):
        try:
            self.require_exact()
            self._slot(slot)
            return self._tokens[slot['slot']]
        except BaseException:
            self._poison_reason = self._poison_reason or 'slot/token binding failed'
            raise

    def _relation(self, slot, relation):
        closed(relation, 'fixture_root target link physical logical checked_ordinary_ancestors')
        for path in (relation['fixture_root'], relation['target'], relation['physical']):
            ordinary_chain(self._backend, path)
        target = self._backend.metadata(relation['target'])
        link = self._backend.metadata(relation['link'])
        need(type(target) is Metadata and target.kind == 'directory' and type(link) is Metadata and link.kind == 'absent', 'ordinary target/absent link required')
        augmented = dict(relation, ordinary=True, target_identity=target.identity, link_absent=True)
        validate_relation(self._manifest, slot, augmented)
        return augmented

    @contextmanager
    def effect_window(self, slot, call, pre_receipt_sha256):
        try:
            self.require_exact()
            self._slot(slot)
            need(self._active is None and self._pending is None and slot['slot'] not in self._used
                 and hex64(pre_receipt_sha256), 'nested/pending/replayed window or pre digest')
            pre_path = str(lexical(self._manifest.document['runroot']) / 'live-action-receipts' / ('slot-' + slot['slot'] + '-pre.json'))
            pre_raw = _read(self._backend, pre_path)
            need(digest(pre_raw) == pre_receipt_sha256, 'pre digest differs')
            pre = decode_canonical(pre_raw)
            closed(pre, 'schema slot nodeid event nonce_sha256 manifest_sha256 external_grant_sha256 source_commit source_tree harness_pins relation actual_call powershell status')
            m = self._manifest.document
            expected = {'schema': 'legacy103-action-pre-r2', 'slot': slot, 'nodeid': self._node,
                        'event': slot['event'], 'nonce_sha256': digest(self.token(slot).encode('utf-8')),
                        'manifest_sha256': self._manifest.sha256, 'external_grant_sha256': self.grant_sha256,
                        'source_commit': m['source_commit'], 'source_tree': m['source_tree'],
                        'harness_pins': m['harness_pins'], 'powershell': m['powershell'],
                        'actual_call': call, 'status': 'CONSUMED_BEFORE_EFFECT_NOT_SUCCESS'}
            need(all(exact_value(pre[k], v) for k, v in expected.items()), 'pre action bindings differ')
            augmented = self._relation(slot, pre['relation'])
            need(exact_value(call, render_call(self._manifest, slot, augmented)), 'original raw call differs')
            self._pending = {'slot': deepcopy(slot), 'relation': deepcopy(pre['relation']),
                             'target_identity': augmented['target_identity'], 'pre_sha256': pre_receipt_sha256,
                             'pre_path': pre_path, 'pre_raw': pre_raw, 'call': deepcopy(call),
                             'event': lowered_event(call, m['powershell']), 'seen': False}
            self._used.add(slot['slot'])
            self._active = self._pending
            yield
            need(self._active['seen'], 'missing exact audit event')
            self.require_exact()
        except BaseException:
            self._poison_reason = self._poison_reason or 'action window mismatch/uncertainty'
            raise
        finally:
            self._active = None

    def audit(self, event, args):
        try:
            need(self._active is not None and self._poison_reason is None, 'controlled effect outside admitted window')
            need(time.monotonic is ORIGINAL_CLOCK and threading.get_ident is ORIGINAL_THREAD
                 and ORIGINAL_THREAD() == self._thread and self._node == self._active['slot']['nodeid'], 'audit clock/thread/node differs')
            need(not self._active['seen'] and exact_value((event, args), self._active['event']), 'unexpected/replayed audit event')
            self._active['seen'] = True
        except BaseException:
            self._poison_reason = self._poison_reason or 'audit mismatch'
            raise

    def observe_original(self, relation, result, error):
        try:
            self.require_exact()
            pending = self._pending
            need(self._active is None and pending is not None and pending['seen']
                 and self._node == pending['slot']['nodeid'], 'retained post-window correlation required')
            need(_read(self._backend, pending['pre_path']) == pending['pre_raw'], 'pre changed after effect')
            if error is not None:
                need(isinstance(error, BaseException), 'original error identity required')
                outcome = {'error_type': type(error).__name__, 'error_message': str(error)}
                # Junction exceptions/timeout need separately bound supervisor proof.
                terminated = pending['slot']['kind'] == 'symlink'
            elif pending['slot']['kind'] == 'junction':
                need(type(result) is CompletedProcess and type(result.returncode) is int
                     and type(result.stdout) is bytes and type(result.stderr) is bytes
                     and exact_value(result.args, pending['call']['args'][0]), 'original completed junction result required')
                terminated = True
                outcome = {'returncode': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode('ascii'),
                           'stderr_base64': base64.b64encode(result.stderr).decode('ascii')}
            else:
                need(result is None, 'original symlink result required')
                terminated, outcome = True, {'return_value': None}
            minimal = {k: pending[k] for k in ('slot', 'relation', 'target_identity', 'pre_sha256')}
            observed = observe_owned(minimal, relation, result, error, self._backend, child_terminated=terminated)
            # Pending blocks any further slot until outer Protocol post-readback.
            # Error poison is latched after that readback, retaining error identity.
            pending['observation'], pending['outcome'] = deepcopy(observed), outcome
            pending['original_error'] = error
            return observed
        except BaseException as exc:
            self._fail('post-effect UNKNOWN; pending retained and remaining effects blocked', error if error is not None else exc)

    def check_complete(self, results):
        try:
            self.require_exact()
            need(self._pending is None and self._active is None
                 and self._finished == {s['slot'] for s in load_frozen_bindings().slots},
                 'exact eight completed slots/full103 evidence required')
            return {'synthetic': False, 'actual_runtime_verified': False, 'slots': 8,
                    **summarize_results(results)}
        except BaseException:
            self._poison_reason = self._poison_reason or 'incomplete original result evidence'
            raise


def load_actual_context():
    return GuardedContext()
