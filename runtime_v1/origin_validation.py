"""Dormant finite joins and owned-state interpreter; DATA validation is not admission."""
from dataclasses import dataclass
from copy import deepcopy

from .errors import Denied, Unknown
from .metadata_backend import Metadata, ordinary_chain
from .runtime_manifest import (INTERPRETER, SOURCE, TREE, canonical, closed, decode_canonical,
                              digest, exact_value, hex64, lexical, load_frozen_bindings, need,
                              parse_grant, parse_invocation, parse_manifest)


@dataclass(frozen=True)
class ValidatedData:
    facts_raw: bytes
    manifest_raw: bytes
    grant_raw: bytes
    invocation_raw: bytes
    anchor_raw: bytes
    ownership_raw: bytes


def _read(backend, path, cap=65536):
    lexical(path)
    ordinary_chain(backend, path, include_self=False)
    row = backend.metadata(path)
    need(type(row) is Metadata and row.kind == 'file' and row.path == path
         and type(row.identity) is str and bool(row.identity) and row.link_target is None,
         'ordinary origin file required')
    raw = backend.read_file(path, cap)
    need(type(raw) is bytes and len(raw) <= cap, 'bounded plain file bytes')
    need(exact_value(backend.metadata(path), row), 'origin identity changed')
    return raw


def validate_process(value):
    closed(value, 'pid parent_pid image image_sha256 argv environment cwd')
    need(type(value['pid']) is int and value['pid'] > 0 and type(value['parent_pid']) is int and value['parent_pid'] > 0
         and value['pid'] != value['parent_pid'], 'plain process IDs required')
    need(exact_value(value['image'], INTERPRETER['path'])
         and exact_value(value['image_sha256'], INTERPRETER['sha256']), 'process interpreter differs')
    lexical(value['cwd'])
    need(type(value['argv']) is list and 0 < len(value['argv']) <= 64
         and all(type(v) is str and '\x00' not in v and len(v) <= 8192 for v in value['argv']), 'bounded exact argv')
    env = value['environment']
    need(type(env) is dict and 0 < len(env) <= 128 and all(type(k) is str and type(v) is str
         and 0 < len(k) <= 256 and len(v) <= 8192 and '=' not in k and '\x00' not in k + v for k, v in env.items()), 'bounded exact environment')


def validate_origin(facts, backend, process):
    """An injected backend/process/facts can only produce a nonoperational DATA record."""
    f = decode_canonical(facts)
    closed(f, 'schema invocation_path invocation_sha256 manifest_path grant_path anchor_path source_directory ownership_path ownership_sha256 process')
    need(f['schema'] == 'legacy103-external-root-facts-runtime-v1' and hex64(f['invocation_sha256'])
         and hex64(f['ownership_sha256']), 'root facts data shape')
    for name in ('invocation_path', 'manifest_path', 'grant_path', 'anchor_path', 'source_directory', 'ownership_path'):
        lexical(f[name])
    validate_process(f['process'])
    validate_process(process)
    need(exact_value(process, f['process']), 'independent process observation differs')
    manifest_raw = _read(backend, f['manifest_path'])
    preliminary = decode_canonical(manifest_raw)
    pins = preliminary.get('harness_pins')
    manifest = parse_manifest(manifest_raw, expected_harness_pins=pins, frozen=load_frozen_bindings())
    m = manifest.document
    root, lane = lexical(m['runroot']), lexical(f['source_directory'])
    invocation_path = lexical(f['invocation_path'])
    need(not invocation_path.is_relative_to(root) and not invocation_path.is_relative_to(lane)
         and not lane.is_relative_to(root), 'external invocation/source placement differs')
    paths = [f[n] for n in ('invocation_path', 'manifest_path', 'grant_path', 'anchor_path', 'ownership_path')]
    need(len({str(lexical(p)).casefold() for p in paths}) == len(paths), 'distinct finite pin leaves required')
    need(f['ownership_path'] == str(root / 'OWNERSHIP.json') and f['ownership_sha256'] == m['namespace_ownership_sha256'], 'ownership location/hash join')
    need(process['cwd'] == m['snapshot'], 'exact process cwd differs')
    grant_raw = _read(backend, f['grant_path'])
    grant = parse_grant(grant_raw, manifest=manifest)
    invocation_raw = _read(backend, f['invocation_path'])
    need(digest(invocation_raw) == f['invocation_sha256'], 'external invocation digest differs')
    invocation = parse_invocation(invocation_raw, manifest=manifest, grant=grant)
    inv = invocation.document
    anchor_raw = _read(backend, f['anchor_path'])
    a = decode_canonical(anchor_raw)
    closed(a, 'schema manifest_sha256 grant_sha256 source_commit source_tree runroot')
    need(exact_value(a, {'schema': 'legacy103-runtime-anchor-v1', 'manifest_sha256': manifest.sha256,
         'grant_sha256': grant.sha256, 'source_commit': SOURCE, 'source_tree': TREE, 'runroot': m['runroot']})
         and digest(anchor_raw) == inv['anchor_sha256'], 'anchor finite joins differ')
    ownership_raw = _read(backend, f['ownership_path'])
    o = decode_canonical(ownership_raw)
    need(exact_value(o, {'schema': 'legacy103-runtime-ownership-v1', 'runroot': m['runroot'], 'source_commit': SOURCE, 'source_tree': TREE})
         and digest(ownership_raw) == f['ownership_sha256'], 'ownership finite joins differ')
    ordinary_chain(backend, m['snapshot'])
    ordinary_chain(backend, f['source_directory'])
    # No source/harness leaf may alias an authority document or the external invocation.
    leaves = set(p.casefold() for p in paths)
    for name, row in m['closure32'].items():
        path = str(lexical(m['snapshot']).joinpath(*name.split('/')))
        need(path.casefold() not in leaves and backend.file_digest(path, row['bytes']) == row['sha256'], 'source32 exact bytes differ')
    for name, expected in m['harness_pins'].items():
        path = str(lane / name)
        need(path.casefold() not in leaves, 'harness/authority alias')
        raw = _read(backend, path, 1024 * 1024)
        need(digest(raw) == expected, 'exact harness bytes differ')
    for record in (m['interpreter'], m['powershell']):
        need(digest(_read(backend, record['path'], 8 * 1024 * 1024)) == record['sha256'], 'executable bytes differ')
    need(digest(_read(backend, m['powershell']['resolved_path'], 8 * 1024 * 1024)) == m['powershell']['sha256'], 'resolved executable differs')
    need(inv['launcher_path'].casefold() not in leaves and digest(_read(backend, inv['launcher_path'], 1024 * 1024)) == inv['launcher_sha256'], 'launcher leaf differs')
    return ValidatedData(facts, manifest_raw, grant_raw, invocation_raw, anchor_raw, ownership_raw)


def observe_owned(pending, relation, result, error, backend, *, child_terminated):
    try:
        closed(pending, 'slot relation target_identity pre_sha256')
        need(exact_value(relation, pending['relation']) and hex64(pending['pre_sha256']), 'pending action correlation differs')
        ordinary_chain(backend, relation['target'])
        ordinary_chain(backend, relation['physical'])
        ordinary_chain(backend, relation['fixture_root'])
        target = backend.metadata(relation['target'])
        need(type(target) is Metadata and target.path == relation['target']
             and target.kind == 'directory' and target.link_target is None
             and type(target.identity) is str and bool(target.identity)
             and exact_value(target.identity, pending['target_identity']), 'target identity changed')
        need(child_terminated is True, 'supervisor termination proof missing')
        link = backend.metadata(relation['link'])
        need(type(link) is Metadata and link.path == relation['link']
             and type(link.identity) is str and bool(link.identity), 'link metadata missing')
        if link.kind == 'absent':
            need(error is not None and link.link_target is None, 'unexpected absent link after success')
        else:
            need(link.kind == pending['slot']['kind'] and link.link_target == relation['target'] and bool(link.identity), 'unexpected link kind/target')
        return {'known': True, 'synthetic': False, 'actual_link_verified': link.kind != 'absent',
                'target_identity': target.identity, 'link_kind': link.kind, 'link_target': link.link_target,
                'pre_sha256': pending['pre_sha256']}
    except BaseException as exc:
        raise Unknown('owned post-effect observation UNKNOWN') from (error if error is not None else exc)
