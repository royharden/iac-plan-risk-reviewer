"""Pure exact-call rendering and injected audit-data window; no audit installation."""
from contextlib import contextmanager
from copy import deepcopy
import re
from subprocess import list2cmdline
import threading
import time

from .errors import Denied
from .runtime_manifest import closed, exact_value, hex64, lexical, need

ORIGINAL_CLOCK = time.monotonic
ORIGINAL_THREAD = threading.get_ident


def validate_relation(manifest, slot, relation):
    m = manifest.document
    need(any(exact_value(slot, s) for s in m['slots']), 'exact slot required')
    closed(relation, 'fixture_root target link physical logical checked_ordinary_ancestors ordinary target_identity link_absent')
    root = lexical(relation['fixture_root'])
    prefix = lexical(m['snapshot']) / '.agent-work' / 'RV2-0040-junction-regression'
    need(root.parent == prefix and re.fullmatch(re.escape(slot['kind'] + '-' + slot['position'] + '-') + '[0-9a-f]{32}', root.name) is not None, 'original fixture UUID relation required')
    target, link = root / 'target', root / 'linked'
    expected = {'target': str(target), 'link': str(link),
                'physical': str(target if slot['position'] == 'direct' else target / 'ordinary-child'),
                'logical': str(link if slot['position'] == 'direct' else link / 'ordinary-child')}
    need(all(exact_value(relation[k], v) for k, v in expected.items()), 'fixture relation differs')
    need(relation['ordinary'] is True and relation['link_absent'] is True, 'ordinary absent-link model required')
    need(type(relation['target_identity']) is str and 0 < len(relation['target_identity']) <= 256, 'target identity required')
    ancestors = relation['checked_ordinary_ancestors']
    need(type(ancestors) is list and 0 < len(ancestors) <= 256, 'ordinary ancestor observations required')
    for value in ancestors:
        lexical(value)
    need(str(root) in ancestors and str(target) in ancestors and relation['physical'] in ancestors, 'owned parent observations required')
    return deepcopy(relation)


def render_call(manifest, slot, relation):
    r = validate_relation(manifest, slot, relation)
    if slot['kind'] == 'symlink':
        return {'api': 'os.symlink', 'args': [r['target'], r['link']], 'kwargs': {'target_is_directory': True}}
    env = {key: r['fixture_root'] for key in ('HOME', 'USERPROFILE', 'TMP', 'TEMP')}
    env.update(PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1', PYTHONSAFEPATH='1', CHECKOV_ALLOW_USAGE_METRICS='false', LOG_LEVEL='ERROR')
    env.update(manifest.document['loader_environment'])
    quote = lambda s: "'" + s.replace("'", "''") + "'"
    argv = [manifest.document['powershell']['path'], '-NoProfile', '-NonInteractive', '-Command',
            "$ErrorActionPreference='Stop'; $null=New-Item -ItemType Junction -Path " + quote(r['link']) + ' -Target ' + quote(r['target'])]
    return {'api': 'subprocess.run', 'args': [argv],
            'kwargs': {'shell': False, 'capture_output': True, 'check': False, 'timeout': 20, 'env': env},
            'inherited_cwd': manifest.document['snapshot'], 'stdin': 'original-default-inheritance'}


def lowered_event(call, powershell):
    need(type(call) is dict, 'call data required')
    if call.get('api') == 'os.symlink':
        need(exact_value(call, {'api': 'os.symlink', 'args': call.get('args'), 'kwargs': {'target_is_directory': True}})
             and type(call['args']) is list and len(call['args']) == 2 and all(type(s) is str for s in call['args']), 'symlink shape')
        return 'os.symlink', (call['args'][0], call['args'][1], -1)
    need(call.get('api') == 'subprocess.run', 'unsupported call')
    closed(call, 'api args kwargs inherited_cwd stdin')
    need(type(call['args']) is list and len(call['args']) == 1 and type(call['args'][0]) is list
         and all(type(v) is str for v in call['args'][0]) and len(call['args'][0]) == 5
         and call['args'][0][0] == powershell['path'], 'junction argv shape')
    closed(call['kwargs'], 'shell capture_output check timeout env')
    kw = call['kwargs']
    need(kw['shell'] is False and kw['capture_output'] is True and kw['check'] is False
         and type(kw['timeout']) is int and kw['timeout'] == 20 and type(kw['env']) is dict, 'original junction flags')
    return 'subprocess.Popen', (None, list2cmdline(call['args'][0]), None, deepcopy(kw['env']))


class ExactInertWindow:
    def __init__(self, owner):
        self.owner = owner
        self.active = None
        self.completed = set()

    @contextmanager
    def open(self, slot, call, pre_sha):
        owner = self.owner
        try:
            owner.require_exact()
            need(time.monotonic is ORIGINAL_CLOCK and threading.get_ident is ORIGINAL_THREAD
                 and ORIGINAL_THREAD() == owner._thread, 'original clock/thread required')
            need(self.active is None and owner._pending is None, 'nested/pending window')
            owner._slot(slot)
            need(slot['slot'] not in self.completed and hex64(pre_sha), 'window replay or invalid receipt')
            pre = owner._store.read_pre(deepcopy(slot))
            expected = owner._pre(slot, call)
            from .runtime_manifest import canonical, digest
            need(exact_value(pre, expected) and digest(canonical(pre)) == pre_sha, 'pre receipt readback differs')
            expected_call = render_call(owner._manifest, slot, pre['relation'])
            need(exact_value(call, expected_call), 'raw call differs')
            expected_event = lowered_event(call, owner._manifest.document['powershell'])
            pending = {'slot': deepcopy(slot), 'call': deepcopy(call), 'relation': deepcopy(pre['relation']),
                       'pre_sha256': pre_sha, 'event': expected_event, 'seen': False,
                       'thread': ORIGINAL_THREAD(), 'clock': ORIGINAL_CLOCK}
            self.completed.add(slot['slot'])
            owner._pending = pending
            self.active = pending
            yield
            need(pending['seen'], 'missing injected audit event')
            need(time.monotonic is ORIGINAL_CLOCK and threading.get_ident is ORIGINAL_THREAD
                 and ORIGINAL_THREAD() == pending['thread'] and owner.current_node == slot['nodeid'], 'exit clock/thread/node binding changed')
            owner.require_exact()
        except BaseException as exc:
            owner._poison('inert window failed', exc)
            raise
        finally:
            self.active = None

    def audit_inert(self, event, args):
        try:
            pending = self.active
            self.owner.require_exact()
            need(pending is not None and not pending['seen'], 'audit outside single-use window')
            need(threading.get_ident is ORIGINAL_THREAD and ORIGINAL_THREAD() == pending['thread'] and time.monotonic is pending['clock'], 'thread/clock binding changed')
            need(self.owner.current_node == pending['slot']['nodeid'], 'node binding changed')
            need(exact_value((event, args), pending['event']), 'lowered audit differs')
            pending['seen'] = True
        except BaseException as exc:
            self.owner._poison('injected audit mismatch', exc)
            raise
