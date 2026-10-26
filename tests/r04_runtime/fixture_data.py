"""Independent in-memory fixture DATA, never an authority artifact/installation.

Reads only exact frozen0105 DATA leaves when later explicitly admitted. There
are no writes, imports of original tests/modules, UUID calls, native operations,
root approvals or operational contexts. Source adapters may consume these bytes
only through declared pure parser/inert constructors after parent preflight.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PureWindowsPath
from .stdlib_list2cmdline import list2cmdline


ORIGINAL = Path(__file__).parent / 'data'
DATA_PINS = {
    'activation-manifest.json': '91d5a952f8c066989e85bbc428b4b1d885b487701330890eed6f9611dbf4d12f',
    'closure924.json': 'f98769e142fd795aed5aa86e4d7244513567bd3b1178dc8e14eddb1dfde6537f',
    'ordered103.json': '1d7eab290e804bcdb15ca3467e09e5952d72db6cc64bfb115abecc1214ad9df3',
    'whitelist12.json': '298f3cae417b7cfa4b9cb0a4e77c62caf132182885e11329a7754485bd072d02',
}
INERT_ROOT = PureWindowsPath(r'C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\RV1-legacy103-successor-scratch\runtime-v1-INERT-DATA-0110')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frozen_data(name):
    if name not in DATA_PINS:
        raise ValueError('not an explicitly permitted frozen DATA leaf')
    path = ORIGINAL / name
    for part in [path, *path.parents]:
        if getattr(part.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('frozen DATA path has reparse component')
    raw = path.read_bytes()
    if sha(raw) != DATA_PINS[name]:
        raise ValueError('frozen original DATA digest changed')
    return json.loads(raw)


def original_documents(expected_harness_pins):
    """Return manifest/grant/invocation dicts and public inert token strings.

    The digest pins here prove test DATA correspondence only. No root trust or
    external approval record exists or is written by this function.
    """
    manifest = deepcopy(frozen_data('activation-manifest.json'))
    manifest.update(schema='legacy103-runtime-manifest-v1',
                    purpose='execute-reviewed-legacy103-via-root-bridge',
                    runroot=str(INERT_ROOT), snapshot=str(INERT_ROOT / 'snapshot'),
                    harness_pins=deepcopy(expected_harness_pins),
                    grant_authority={
                        'pin_source': 'independently-root-admitted-invocation',
                        'current_dispatch_purpose': 'execute-reviewed-legacy103-via-root-bridge',
                        'runtime_approved_digest': None,
                    })
    tokens = {slot['slot']: 'reviewer-public-INERT-token-' + slot['slot']
              for slot in manifest['slots']}
    grant = {
        'schema': 'legacy103-external-INT-grant-r2',
        'purpose': 'execute-reviewed-legacy103',
        'manifest_sha256': sha(canonical(manifest)),
        'source_commit': manifest['source_commit'],
        'source_tree': manifest['source_tree'],
        'runroot': manifest['runroot'],
        'slots': {slot['slot']: {'nodeid': slot['nodeid'], 'event': slot['event'],
                                'token_sha256': sha(tokens[slot['slot']].encode())}
                  for slot in manifest['slots']},
    }
    invocation = {
        'schema': 'legacy103-root-invocation-runtime-v1',
        'purpose': manifest['purpose'], 'invocation_id': 'reviewer-INERT-DATA-0110',
        'manifest_sha256': sha(canonical(manifest)),
        'grant_sha256': sha(canonical(grant)),
        'anchor_sha256': sha(b'REVIEWER-INERT-ANCHOR-DATA-NO-ACTUAL-AUTHORITY'),
        'launcher_path': r'C:\INERT-DATA-ONLY-0110\launcher.py',
        'launcher_sha256': sha(b'REVIEWER-INERT-LAUNCHER-DATA-NO-ACTUAL-CODE'),
        'runroot': manifest['runroot'],
        'source_commit': manifest['source_commit'],
        'source_tree': manifest['source_tree'],
    }
    return manifest, grant, invocation, tokens


def original_relation(manifest, slot):
    # A synthetic UUID-shaped DATA operand, never a monkeypatch or UUID call in
    # the original body/fixture. No path below is created or resolved.
    nonce = format(int(slot['slot']), '032x')
    root = PureWindowsPath(manifest['snapshot']) / '.agent-work' / 'RV2-0040-junction-regression' / (
        slot['kind'] + '-' + slot['position'] + '-' + nonce)
    target, link = root / 'target', root / 'linked'
    physical = target if slot['position'] == 'direct' else target / 'ordinary-child'
    ancestors = []
    for leaf in (root, target, physical):
        for ancestor in reversed([leaf, *leaf.parents]):
            if str(ancestor) not in ancestors:
                ancestors.append(str(ancestor))
    return {'fixture_root': str(root), 'target': str(target), 'link': str(link),
            'physical': str(physical),
            'logical': str(link if slot['position'] == 'direct' else link / 'ordinary-child'),
            'checked_ordinary_ancestors': ancestors, 'ordinary': True,
            'target_identity': 'REVIEWER-INERT-target-' + slot['slot'],
            'link_absent': True}


def original_post_state(slot, relation):
    return {'known': True, 'ordinary': True,
            'target_identity': relation['target_identity'],
            'link_kind': slot['kind'], 'link_target': relation['target'],
            'child_terminated': True}


def original_call(manifest, slot, relation):
    if slot['kind'] == 'symlink':
        return {'api': 'os.symlink', 'args': [relation['target'], relation['link']],
                'kwargs': {'target_is_directory': True}}
    environment = {key: relation['fixture_root'] for key in ('HOME', 'USERPROFILE', 'TMP', 'TEMP')}
    environment.update(PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
                       PYTHONSAFEPATH='1', CHECKOV_ALLOW_USAGE_METRICS='false', LOG_LEVEL='ERROR')
    environment.update(manifest['loader_environment'])
    quote = lambda value: "'" + value.replace("'", "''") + "'"
    command = "$ErrorActionPreference='Stop'; $null=New-Item -ItemType Junction -Path " + quote(relation['link']) + ' -Target ' + quote(relation['target'])
    return {'api': 'subprocess.run',
            'args': [[manifest['powershell']['path'], '-NoProfile', '-NonInteractive', '-Command', command]],
            'kwargs': {'shell': False, 'capture_output': True, 'check': False,
                       'timeout': 20, 'env': environment},
            'inherited_cwd': manifest['snapshot'], 'stdin': 'original-default-inheritance'}


def independent_windows_commandline(arguments):
    """Exact copied locked-stdlib AST oracle; no subprocess import/call.

    verify_stdlib_oracle.py proves the source function AST matches pinned
    subprocess.py85d29. Only its read-only os.fsdecode dependency is retained.
    The earlier hand-quoted draft is retained but is not the adopted oracle.
    """
    if any(type(argument) is not str for argument in arguments):
        raise TypeError('plain string argv')
    return list2cmdline(arguments)


def expected_event(call):
    if call['api'] == 'os.symlink':
        return 'os.symlink', (call['args'][0], call['args'][1], -1)
    return 'subprocess.Popen', (None, independent_windows_commandline(call['args'][0]),
                                None, deepcopy(call['kwargs']['env']))
