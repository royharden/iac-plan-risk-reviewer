"""Closed data parsers. Parsed records never confer operational authority."""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PureWindowsPath
import re

from .errors import Denied

SOURCE = '924a9a40d2a597c723887952d82807b517ffec8b'
TREE = '8907bd4007d3f2f8f8a94c86b355bf3c6181aab2'
PURPOSE = 'execute-reviewed-legacy103-via-root-bridge'
PARENT = PureWindowsPath(r'C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\RV1-legacy103-successor-scratch')
INTERPRETER = {'path': r'C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-RV2-eval-db\.venv\Scripts\python.exe', 'sha256': '7f06d4ab8afee27a5fe6a273ef621758290ecbc2f7461ebaf554433efd850e5d'}
POWERSHELL = {'path': r'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe', 'resolved_path': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 'sha256': '60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f'}
LOADER = {'SystemRoot': r'C:\WINDOWS', 'WINDIR': r'C:\WINDOWS', 'SYSTEMDRIVE': 'C:'}
BINDING_HASHES = {'closure924.json': 'f98769e142fd795aed5aa86e4d7244513567bd3b1178dc8e14eddb1dfde6537f', 'ordered103.json': '1d7eab290e804bcdb15ca3467e09e5952d72db6cc64bfb115abecc1214ad9df3', 'whitelist12.json': '298f3cae417b7cfa4b9cb0a4e77c62caf132182885e11329a7754485bd072d02'}


def digest(raw):
    return sha256(raw).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError) as exc:
        raise Denied('not canonical JSON data') from exc


def exact_value(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(exact_value(actual[k], v) for k, v in expected.items())
    if type(expected) in (list, tuple):
        return len(actual) == len(expected) and all(exact_value(a, b) for a, b in zip(actual, expected))
    return actual == expected


def need(condition, message):
    if not condition:
        raise Denied(message)


def hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def closed(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), 'closed fields required')


def decode_canonical(raw: bytes, *, cap: int = 65536) -> dict:
    need(type(raw) is bytes and type(cap) is int and 0 < len(raw) <= cap, 'bounded plain bytes required')

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Denied('nonfinite JSON')))
        need(type(value) is dict and canonical(value) == raw, 'canonical object required')
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Denied('invalid canonical JSON') from exc


def lexical(value):
    need(type(value) is str and not any(ord(c) < 32 for c in value) and '%' not in value and '/' not in value, 'plain Windows path required')
    path = PureWindowsPath(value)
    need(path.is_absolute() and len(path.drive) == 2 and path.drive[1] == ':'
         and str(path) == value and '..' not in path.parts
         and all(not part.endswith((' ', '.')) and ':' not in part for part in path.parts[1:]), 'canonical local path required')
    return path


@dataclass(frozen=True)
class Record:
    raw: bytes

    @property
    def sha256(self):
        return digest(self.raw)

    @property
    def document(self):
        return decode_canonical(self.raw)


class ManifestData(Record):
    pass


class GrantData(Record):
    pass


class InvocationData(Record):
    pass


@dataclass(frozen=True)
class FrozenBindings:
    closure_raw: bytes
    ordered_raw: bytes
    whitelist_raw: bytes

    @property
    def closure(self):
        return json.loads(self.closure_raw)['files']

    @property
    def ordered(self):
        return json.loads(self.ordered_raw)

    @property
    def whitelist(self):
        return json.loads(self.whitelist_raw)

    @property
    def slots(self):
        rows = []
        for stem in ('test_workspace_links_refuse_before_approval_writes_or_process', 'test_guarded_staging_links_refuse_without_writes'):
            for position in ('direct', 'ancestor'):
                for kind in ('symlink', 'junction'):
                    rows.append({'slot': f'{len(rows)+1:02}', 'nodeid': 'tests/eval/test_scanner_dev_execution.py::' + stem + f'[{position}-{kind}]', 'kind': kind, 'position': position, 'event': 'os.symlink' if kind == 'symlink' else 'subprocess.run'})
        return rows


def load_frozen_bindings(directory: Path | None = None) -> FrozenBindings:
    directory = Path(__file__).parent / 'bindings' if directory is None else Path(directory)
    raw = {}
    for name, expected in BINDING_HASHES.items():
        raw[name] = (directory / name).read_bytes()
        need(digest(raw[name]) == expected, 'frozen data leaf changed: ' + name)
    frozen = FrozenBindings(raw['closure924.json'], raw['ordered103.json'], raw['whitelist12.json'])
    closure = json.loads(frozen.closure_raw)
    need(closure['candidate'] == SOURCE and closure['tree'] == TREE and len(frozen.closure) == 32, 'source32 binding')
    need(len(frozen.ordered) == 103 and len(set(frozen.ordered)) == 103, 'ordered103 binding')
    need(len(frozen.whitelist) == 12 and len(set(frozen.whitelist)) == 12 and set(frozen.whitelist) <= set(frozen.ordered), 'whitelist12 binding')
    need(all(row['nodeid'] in frozen.ordered for row in frozen.slots), 'slot membership')
    return frozen


def summarize_results(rows):
    """Validate complete result DATA, without conferring effect/slot authority."""
    ordered = load_frozen_bindings().ordered
    need(type(rows) is list and len(rows) == len(ordered), 'complete103 rows required')
    results = {}
    domain = set(ordered)
    for row in rows:
        closed(row, 'nodeid status')
        node, status = row['nodeid'], row['status']
        need(type(node) is str and node in domain and node not in results,
             'exact103 nonreplayed result required')
        need(type(status) is str and status in ('PASS', 'FAIL'), 'explicit result required')
        results[node] = status
    results = {node: results[node] for node in ordered}
    failed = [node for node, status in results.items() if status == 'FAIL']
    return {'complete_data': True, 'all_passed': not failed, 'success': not failed,
            'failed': failed, 'results': results}


def parse_manifest(raw: bytes, *, expected_harness_pins: dict[str, str], frozen: FrozenBindings) -> ManifestData:
    d = decode_canonical(raw)
    closed(d, 'schema purpose runroot snapshot source_commit source_tree closure32 ordered103_sha256 whitelist12_sha256 harness_pins interpreter powershell slots loader_environment namespace_ownership_sha256 watchdog_seconds junction_timeout_seconds no_deletion grant_authority')
    need(d['schema'] == 'legacy103-runtime-manifest-v1' and d['purpose'] == PURPOSE, 'runtime-v1 manifest required')
    need(type(frozen) is FrozenBindings, 'frozen binding type')
    # A forged FrozenBindings object must not substitute a different source binding.
    for value, name in ((frozen.closure_raw, 'closure924.json'), (frozen.ordered_raw, 'ordered103.json'), (frozen.whitelist_raw, 'whitelist12.json')):
        need(type(value) is bytes and digest(value) == BINDING_HASHES[name], 'frozen binding digest')
    expected = {'source_commit': SOURCE, 'source_tree': TREE, 'closure32': frozen.closure,
                'ordered103_sha256': BINDING_HASHES['ordered103.json'], 'whitelist12_sha256': BINDING_HASHES['whitelist12.json'],
                'interpreter': INTERPRETER, 'powershell': POWERSHELL, 'slots': frozen.slots,
                'loader_environment': LOADER, 'watchdog_seconds': 180, 'junction_timeout_seconds': 20,
                'no_deletion': True, 'grant_authority': {'pin_source': 'independently-root-admitted-invocation', 'current_dispatch_purpose': PURPOSE, 'runtime_approved_digest': None}}
    need(all(exact_value(d[k], v) for k, v in expected.items()), 'fixed manifest binding differs')
    need(type(expected_harness_pins) is dict and 0 < len(expected_harness_pins) <= 16, 'bounded external harness map')
    need(all(type(k) is str and re.fullmatch('[A-Za-z0-9_-]+\\.py', k) and hex64(v) for k, v in expected_harness_pins.items()), 'harness pin shape')
    need(exact_value(d['harness_pins'], expected_harness_pins), 'harness pins differ')
    root = lexical(d['runroot'])
    need(root.parent == PARENT and str(lexical(d['snapshot'])) == str(root / 'snapshot'), 'successor scratch direct child required')
    need(hex64(d['namespace_ownership_sha256']), 'ownership hash required')
    return ManifestData(raw)


def parse_grant(raw: bytes, *, manifest: ManifestData) -> GrantData:
    need(type(manifest) is ManifestData, 'parsed manifest required')
    d = decode_canonical(raw)
    m = manifest.document
    closed(d, 'schema manifest_sha256 source_commit source_tree runroot slots purpose')
    expected = {'schema': 'legacy103-external-INT-grant-r2', 'manifest_sha256': manifest.sha256,
                'source_commit': m['source_commit'], 'source_tree': m['source_tree'], 'runroot': m['runroot'], 'purpose': 'execute-reviewed-legacy103'}
    need(all(exact_value(d[k], v) for k, v in expected.items()), 'grant binding differs')
    need(type(d['slots']) is dict and set(d['slots']) == {s['slot'] for s in m['slots']}, 'eight grant slots required')
    for slot in m['slots']:
        row = d['slots'][slot['slot']]
        closed(row, 'nodeid event token_sha256')
        need(exact_value(row['nodeid'], slot['nodeid']) and exact_value(row['event'], slot['event']) and hex64(row['token_sha256']), 'grant slot differs')
    return GrantData(raw)


def parse_invocation(raw: bytes, *, manifest: ManifestData, grant: GrantData) -> InvocationData:
    need(type(manifest) is ManifestData and type(grant) is GrantData, 'parsed inputs required')
    parse_grant(grant.raw, manifest=manifest)
    d = decode_canonical(raw)
    m = manifest.document
    closed(d, 'schema purpose invocation_id manifest_sha256 grant_sha256 anchor_sha256 launcher_path launcher_sha256 runroot source_commit source_tree')
    expected = {'schema': 'legacy103-root-invocation-runtime-v1', 'purpose': PURPOSE, 'manifest_sha256': manifest.sha256,
                'grant_sha256': grant.sha256, 'runroot': m['runroot'], 'source_commit': SOURCE, 'source_tree': TREE}
    need(all(exact_value(d[k], v) for k, v in expected.items()), 'invocation binding differs')
    need(type(d['invocation_id']) is str and re.fullmatch('[A-Za-z0-9-]{16,128}', d['invocation_id']) is not None, 'invocation identifier')
    need(hex64(d['anchor_sha256']) and hex64(d['launcher_sha256']), 'invocation hashes')
    need(not lexical(d['launcher_path']).is_relative_to(lexical(m['runroot'])), 'launcher must be outside runroot')
    return InvocationData(raw)
