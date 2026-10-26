"""Reviewer-owned semantic-boundary controls. Expectations frozen in ORACLE-r1.

Artificial pinned files/grants and fake Popen only; returned live labels are unit
plumbing, never native execution evidence. No Checkov import or callback.
"""


from dataclasses import asdict, replace


from pathlib import Path


from types import SimpleNamespace


import io, json, os, subprocess, threading, time


import pytest


from eval.scanners import runner as r, driver as d, checkov_adapter as c


from eval.scanners.artifacts import Mapping


CHECK='CKV_SYNTHETIC_TIME'
ADDRESS='aws_db_instance.synthetic'


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',',':')).encode()


class FakeClock:
    """No sleeps/call-count trick: only named business boundaries consume time."""
    def __init__(self): self.now=1000.0; self.events=[]; self.lock=threading.Lock()
    def monotonic(self): return self.now
    def advance(self, phase, seconds):
        with self.lock:
            self.now += seconds
            self.events.append({'phase':phase,'seconds':seconds,'now':self.now})


@pytest.fixture
def clock(monkeypatch, request, tmp_path):
    clock=FakeClock()
    # Shared stdlib time module covers driver, runner, inventory and adapter calls.
    monkeypatch.setattr(time,'monotonic',clock.monotonic)
    yield clock
    # Independent diagnostic artifact outside product wire; retain every case.
    target=tmp_path/'phase-traces'/f'{request.node.name}.json'
    target.parent.mkdir(exist_ok=True)
    with target.open('x') as stream: json.dump(clock.events,stream,indent=2)


def fixture(tmp_path, limits=r.Limits(), custom=False):
    def write(name, raw):
        path=tmp_path/name
        with path.open('xb') as stream: stream.write(raw)
        return path,r.digest(raw)
    plan={'format_version':'1.2','resource_changes':[{'address':ADDRESS,'type':'aws_db_instance',
          'mode':'managed','provider_name':'registry.terraform.io/hashicorp/aws',
          'change':{'actions':['create'],'before':None,'after':{'publicly_accessible':True}}}]}
    source,ps=write('plan.json',encoded(plan)); exe,es=write('scanner.fixture',b'not an executable')
    deps,ds=write('dependencies.json',b'artificial dependency metadata')
    version,vs=write('version.json',encoded({'scanner_name':'checkov','version':'unit-only',
                                          'executable_sha256':es,'dependency_manifest_sha256':ds}))
    config,cs=write('config.json',b'{}')
    extra=(); custom_dir=None; arm='C-custom' if custom else 'C'
    if custom:
        custom_dir=tmp_path/'policies'; custom_dir.mkdir()
        policy_file=custom_dir/'synthetic.py'; raw=b'# inert fixture, never imported\n'
        with policy_file.open('xb') as stream: stream.write(raw)
        extra=((policy_file,r.digest(raw),4096),)
    policy,pols=write('policy.json',encoded({'scanner_name':'checkov','check_ids':[CHECK],
                          'files':[{'name':p.name,'sha256':sha} for p,sha,_ in extra]}))
    argv=(str(exe),'--file',str(source),'--framework','terraform_plan','--output','json','--compact',
          '--check',CHECK,'--config-file',str(config),'--skip-download','--skip-results-upload',
          '--download-external-modules','false')
    env=r.fixed_environment(tmp_path)
    if custom:
        argv+=('--external-checks-dir',str(custom_dir))
        env+=(('IAC_CUSTOM_PLAN_JSON',str(source)),('IAC_CUSTOM_PLAN_SHA256',ps))
    pins=((source,ps,limits.plan_bytes),(config,cs,4096),(exe,es,256*1024*1024),
          (deps,ds,1024*1024),(version,vs,64*1024),(policy,pols,1024*1024))+extra
    inv=r.Invocation(argv,tmp_path,env,limits,pins)
    approved=r.ApprovedInvocation(arm,'checkov','unit-only',ps,es,ds,vs,cs,pols,r.invocation_digest(inv),(CHECK,))
    pin=r.ScannerPin(exe,'unit-only',es,ds,vs,deps,version)
    mapping=Mapping(arm=arm,scanner_name='checkov',version='unit-only',executable_sha256=es,
                    policy_sha256=pols,rule_id='R2',check_ids=(CHECK,),supported_actions=(('create',),),
                    supported_types=('aws_db_instance',),compatibility='verified',compatibility_evidence_sha256='d'*64)
    settings={'check_ids':[CHECK],'workspace':str(tmp_path),'pin':{k:str(v) if isinstance(v,Path) else v for k,v in asdict(pin).items()},
              'config_path':str(config),'policy_manifest_path':str(policy),'policy_sha256':pols,
              'mappings':[mapping.model_dump(mode='json')]}
    if custom:
        settings.update(custom_policy_dir=str(custom_dir),custom_policy_files=[{'path':str(p),'sha256':sha,'max_bytes':cap} for p,sha,cap in extra])
    manifest={'schema_version':'m4-scanner-run-v1','input_scope':'development_synthetic',
              'synthetic_input_attested':True,'build_sha256':'a'*64,'cases':[{'case_id':'case1','plan_path':str(source),
              'plan_sha256':ps,'resources':[{'resource_id':'resource1','address':ADDRESS}]}],'arms':{arm:settings}}
    grant={'schema_version':'m4-local-scanner-execution-grant-v1','grant_id':'synthetic','operator_id':'synthetic',
           'build_sha256':'a'*64,'comparison_manifest_sha256':r.manifest_digest(manifest),'invocations':[asdict(approved)],
           **{k:True for k in ('dirty_mode_closed','local_only','network_denied','descendants_confined','no_provider_credentials','synthetic_input_attested')}}
    gp,gs=write('grant.json',encoded(grant)); loaded=r.load_execution_grant(gp,expected_sha256=gs,manifest=manifest)
    runner=r.BoundedSubprocessRunner(True,loaded)
    output=encoded({'check_type':'terraform_plan','results':{'passed_checks':[{'check_id':CHECK,'resource':ADDRESS,
                   'check_result':{'result':'PASSED'}}],'failed_checks':[],'skipped_checks':[],'parsing_errors':[]}})
    kwargs=dict(plan_path=source,pin=pin,config_path=config,workspace=tmp_path,runner=runner,
                check_ids=(CHECK,),mappings=(mapping,),policy_sha256=pols,limits=limits,policy_manifest_path=policy)
    if custom: kwargs.update(custom_policy_dir=custom_dir,custom_policy_files=extra)
    return SimpleNamespace(inv=inv,runner=runner,manifest=manifest,kwargs=kwargs,output=output,arm=arm)


def fake_process(monkeypatch, f, clock, duration=0, wait_cost=0):
    calls=[]
    class Process:
        pid=424242; returncode=0
        def __init__(self): self.stdout=io.BytesIO(f.output); self.stderr=io.BytesIO(b'synthetic stderr')
        def poll(self): return self.returncode
        def kill(self): self.returncode=-9
        def wait(self,timeout=None):
            calls.append({'wait_timeout':timeout}); clock.advance('process-wait-return',wait_cost); return self.returncode
    def popen(*args,**kwargs):
        calls.append({'popen':True,'at':clock.now,'argv':args[0],'env':kwargs['env']})
        clock.advance('Popen-return',duration)
        return Process()
    monkeypatch.setattr(subprocess,'Popen',popen)
    return calls


def popen_count(calls): return sum('popen' in x for x in calls)


def timed_wrapper(monkeypatch,obj,name,clock,phase,seconds,when='after',predicate=lambda *a,**kw:True):
    original=getattr(obj,name)
    def wrapped(*args,**kwargs):
        hit=predicate(*args,**kwargs)
        if hit and when=='before': clock.advance(phase,seconds)
        result=original(*args,**kwargs)
        if hit and when=='after': clock.advance(phase,seconds)
        return result
    monkeypatch.setattr(obj,name,wrapped)
