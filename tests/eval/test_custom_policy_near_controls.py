"""Independent contract controls. Only the frozen pure evaluate_change executes.

Expected values derive from Plan3a3b624 lines53,57,60,62,68,70,117-119,
not D output. Leading-zero6 is not an admitted canonical TCP token: it cannot
prove non-TCP. Canonical contract therefore requires indeterminate, while any
future explicit numeric normalization would require TCP risk, never clear.
Numeric JSON6/-1 and other unadmitted normalization probes are observations only.
"""
import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from custom_policy_fixtures.loader import load_policy, recheck_candidate

policy, CANDIDATE, SHA = load_policy()
INITIAL_BINDING = recheck_candidate(policy, str(CANDIDATE), SHA)
OBSERVATIONS = []

def r1(protocol, family=4, kind='ingress', world=True, ports=(22,22)):
    after = {'type':kind,'protocol':protocol,
             'cidr_blocks':['0.0.0.0/0' if world else '10.0.0.0/8'] if family == 4 else [],
             'ipv6_cidr_blocks':['::/0' if world else 'fd00::/8'] if family == 6 else []}
    if ports is not None:
        after.update(from_port=ports[0], to_port=ports[1])
    return {'mode':'managed','provider_name':'registry.terraform.io/hashicorp/aws',
            'type':'aws_security_group_rule','change':{'actions':['create'],'before':None,
            'after':after,'before_sensitive':{},'after_sensitive':{},'after_unknown':{}}}

def observe(name, resource, rule, expected):
    before = copy.deepcopy(resource)
    result = policy.evaluate_change(resource, rule)
    OBSERVATIONS.append({'id':name,'rule':rule,'resource':resource,'expected':expected,
                         'decision':dataclasses.asdict(result)})
    assert before == resource, 'pure source must not mutate synthetic inputs'
    if expected is not None:
        assert (result.applicability, result.outcome) == expected
    return result

@pytest.mark.parametrize('family',[4,6])
@pytest.mark.parametrize('protocol',['tcp','6','-1'])
def test_r1_canonical_risk(family, protocol):
    """what_bug_this_catches: malformed repair suppresses canonical TCP/all exposure."""
    observe(f'canonical-{family}-{protocol}',r1(protocol,family,ports=None if protocol=='-1' else (22,22)),
            'R1',('supported','introduced_risk'))

@pytest.mark.parametrize('family',[4,6])
@pytest.mark.parametrize('protocol',['udp','17','icmp','1','icmpv6','58'])
def test_r1_known_other_shortcircuits_ports(family, protocol):
    """what_bug_this_catches: required-port blanket unknown hides known other protocol negative."""
    observe(f'other-{family}-{protocol}',r1(protocol,family,ports=None),'R1',('supported','clear'))

@pytest.mark.parametrize('protocol',['not-a-protocol','256','999','-2','6.0','6e0','+6',' 6','6 ','TCP','all','',None,True,False,[],{},'\uFF16'])
@pytest.mark.parametrize('family',[4,6])
def test_r1_required_malformed_unknown(protocol,family):
    """what_bug_this_catches: malformed necessary protocol becomes benign empty set."""
    observe(f'malformed-{family}-{protocol!r}',r1(protocol,family),'R1',('supported','indeterminate'))

@pytest.mark.parametrize('family',[4,6])
@pytest.mark.parametrize('kind,world,expected',[
    ('egress',True,('not_applicable',None)),
    ('ingress',False,('supported','clear'))])
def test_r1_unnecessary_protocol_shortcircuits(family,kind,world,expected):
    """what_bug_this_catches: protocol repair loses valid egress/private short-circuit."""
    observe(f'shortcircuit-{family}-{kind}',r1('not-a-protocol',family,kind,world,ports=None),'R1',expected)

@pytest.mark.parametrize('family',[4,6])
@pytest.mark.parametrize('protocol',['06','006'])
def test_r1_leading_zero_tcp_cannot_prove_other_protocol(family,protocol):
    """what_bug_this_catches: decimal6 misses TCP branch then falsely proves non-TCP clear."""
    observe(f'noncanonical-six-{family}-{protocol}',r1(protocol,family),'R1',('supported','indeterminate'))

@pytest.mark.parametrize('protocol',[6,-1,6.0,-1.0,17,0,255,256,-2,'0','255','00','000','017','058','-01','-001','0006','00017','-0','0x06','6\n'])
def test_r1_unadmitted_normalization_diagnostics(protocol):
    """No numeric/normalization wire admission or scored semantic conclusion."""
    observe(f'diagnostic-{type(protocol).__name__}-{protocol!r}',r1(protocol),'R1',None)

@pytest.mark.parametrize('type_name',['aws_db_instance','aws_ebs_volume'])
@pytest.mark.parametrize('actions',[['delete'],['delete','create'],['create','delete']])
@pytest.mark.parametrize('prior,mask,expected',[
    ('known',{},('supported','introduced_risk')),
    ('known',True,('supported','indeterminate')),
    ('known',{'tags':{'unrelated':True}},('supported','introduced_risk')),
    ('null',{},('supported','indeterminate')),
    ('absent',{},('supported','indeterminate'))])
def test_r4_prior_root_boundary(type_name,actions,prior,mask,expected):
    """what_bug_this_catches: root mask ignored or unrelated child mask suppresses destruction."""
    change={'actions':actions,'after':None,'after_unknown':True,'before_sensitive':mask,
            'replace_paths':None}
    if prior != 'absent': change['before'] = {'tags':{'unrelated':'synthetic'}} if prior=='known' else None
    resource={'mode':'managed','provider_name':'registry.terraform.io/hashicorp/aws','type':type_name,'change':change}
    decision=observe(f'r4-{type_name}-{actions}-{prior}-{mask}',resource,'R4',expected)
    if prior in ('null','absent'): assert decision.reason=='contradictory_prior_existence'

@pytest.mark.parametrize('type_name',['aws_db_instance','aws_ebs_volume'])
@pytest.mark.parametrize('actions',[['create'],['update'],['no-op']])
def test_r4_benign_actions_do_not_require_prior(type_name,actions):
    """what_bug_this_catches: full-root repair turns non-destructive actions into unknowns."""
    observe(f'r4-benign-{type_name}-{actions}',{'mode':'managed','provider_name':'registry.terraform.io/hashicorp/aws',
            'type':type_name,'change':{'actions':actions,'before':None,'before_sensitive':True}},
            'R4',('supported','clear'))

@pytest.fixture(scope='module', autouse=True)
def near_evidence(tmp_path_factory):
    """Retain unscored diagnostics alongside scored controls without changing labels."""
    results = tmp_path_factory.mktemp('custom-policy-near-controls')
    yield
    with (results / 'near-observations.json').open('x', encoding='utf-8') as stream:
        json.dump(OBSERVATIONS, stream, indent=2)
    final = recheck_candidate(policy, str(CANDIDATE), SHA)
    with (results / 'near-binding.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(initial=INITIAL_BINDING, final=final), stream, indent=2)
