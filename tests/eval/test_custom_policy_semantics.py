"""Independent frozen semantic controls; only evaluate_change executes.

No Checkov, bridge, product detector, policy registration, load_resource or scanners.
what_bug_this_catches is preserved per oracle row and in assertion diagnostics.
"""
import dataclasses
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import pytest

from custom_policy_fixtures.loader import load_policy, recheck_candidate

ROOT = Path(__file__).parent / 'custom_policy_fixtures'
policy, MODULE_PATH, PIN = load_policy()
INITIAL_BINDING = recheck_candidate(policy, str(MODULE_PATH), PIN)
ORACLE=json.loads((ROOT/'oracle.json').read_text())
CASES={x['oracle_id']:x['resource'] for x in json.loads((ROOT/'cases.json').read_text())}
OBSERVED=[]

@pytest.mark.parametrize('row',ORACLE,ids=lambda x:x['id'])
def test_frozen_semantics(row):
    resource=CASES[row['id']]
    original=json.dumps(resource,sort_keys=True)
    decision=policy.evaluate_change(resource,row['rule'])
    OBSERVED.append(dict(id=row['id'],expected=row['expected'],certainty=row['certainty'],decision=dataclasses.asdict(decision),actions=resource['change']['actions']))
    assert json.dumps(resource,sort_keys=True)==original, 'pure evaluation mutated synthetic input'
    if row['expected'] is None:
        # No asserted expected label: retained observation requires INT domain disposition.
        return
    expected_outcome={'risk':'introduced_risk','pass':'clear','unknown':'indeterminate'}[row['expected']]
    expected_applicability='supported'
    if row['id']=='r1_unchanged22': expected_outcome='unchanged_risk'
    if row['id']=='r1_malformed_egress': expected_outcome=None; expected_applicability='not_applicable'
    assert (decision.applicability,decision.outcome)==(expected_applicability,expected_outcome), row['what_bug_this_catches']
    assert decision.coverage==(), 'These controls use only declared CIDR sources'
    if row['rule']=='R4' and row['spec'].get('prior') in ('absent','null'):
        assert decision.reason=='contradictory_prior_existence'

@pytest.fixture(scope='module', autouse=True)
def semantic_evidence(tmp_path_factory):
    """Retain observations and verify the actual pure-module origin after every case."""
    results = tmp_path_factory.mktemp('custom-policy-semantics')
    yield
    with (results / 'observations.json').open('x', encoding='utf-8') as stream:
        json.dump(OBSERVED, stream, indent=2)
    final = recheck_candidate(policy, str(MODULE_PATH), PIN)
    with (results / 'binding.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(initial=INITIAL_BINDING, final=final), stream, indent=2)
