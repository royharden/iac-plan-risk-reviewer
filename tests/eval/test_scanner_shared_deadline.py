"""Original corrected 57 reviewed controls, portable repository imports.

Synthetic operation delays establish cooperative deadline behavior only.
The elapsed sample precedes future self hashing/serialization/return CPU.
"""
from shared_deadline_fixtures.helpers import (
    pytest, asdict, replace, Path, SimpleNamespace, io, json, os, subprocess,
    threading, time, r, d, c, Mapping, CHECK, ADDRESS, encoded, FakeClock,
    clock, fixture, fake_process, popen_count, timed_wrapper,
)
from shared_deadline_fixtures.runtime import deny_real_effects

@pytest.mark.parametrize('entry',['adapter','capture','runner','driver'])
@pytest.mark.parametrize('duration',[29.99,30.0,30.01])
def test_entry_final_boundary(tmp_path,monkeypatch,clock,entry,duration):
    """what_bug_this_catches: exact D accepted, +2 grace or missing direct fallback/final gate."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock,duration)
    if entry=='adapter': out=c.scan(**f.kwargs); ok=out.status=='ok' and out.live_eligible
    elif entry=='capture':
        kw={k:v for k,v in f.kwargs.items()}; out=r.capture(arm='C',**kw,argv_builder=lambda:f.inv.argv,parser=c.parse_output)
        ok=out.status=='ok' and out.live_eligible
    elif entry=='runner': out=f.runner(f.inv); ok=not out.timed_out and out.error_code is None
    else:
        out=d.compare(f.manifest,runner=f.runner); rows=[x for x in out['rows'] if x['arm']=='C' and x['rule_id']=='R2']
        ok=all(x['live_eligible'] for x in rows)
    assert popen_count(calls)==1
    assert ok is (duration<30), (entry,duration,out)


@pytest.mark.parametrize('entry',['adapter','capture','driver'])
def test_cumulative_capture_preparation(tmp_path,monkeypatch,clock,entry):
    """what_bug_this_catches: individual bounded reads renew or omit cumulative preparation budget."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    seen=set()
    def first_file(path,cap):
        if path.name in {'plan.json','config.json','dependencies.json','version.json'} and path not in seen:
            seen.add(path); return True
        return False
    timed_wrapper(monkeypatch,r,'bounded_read',clock,'first-pinned-read',8,predicate=first_file)
    if entry=='driver': out=d.compare(f.manifest,runner=f.runner)
    elif entry=='adapter': out=c.scan(**f.kwargs)
    else: out=r.capture(arm='C',**f.kwargs,argv_builder=lambda:f.inv.argv,parser=c.parse_output)
    assert clock.now==1032
    assert popen_count(calls)==0, out


def test_driver_raw_verification_is_inside_attempt(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: driver starts clock after the per-arm raw-byte verification."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    original=d._case_bytes
    def raw(case,limits):
        value=original(case,limits); clock.advance('per-arm-raw-verify',30); return value
    monkeypatch.setattr(d,'_case_bytes',raw)
    report=d.compare(f.manifest,runner=f.runner)
    assert popen_count(calls)==0,report


def test_driver_mapping_preparation_consumes_budget(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: mapping preparation excluded before adapter/capture clock."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    timed_wrapper(monkeypatch,d,'_mappings',clock,'mapping-validation',30)
    report=d.compare(f.manifest,runner=f.runner)
    assert popen_count(calls)==0,report


def test_custom_inventory_before_capture_consumes_budget(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: C-custom directory inventory excluded from direct-entry clock."""
    f=fixture(tmp_path,custom=True); calls=fake_process(monkeypatch,f,clock)
    original=Path.iterdir; hit=False
    def iterdir(path):
        nonlocal hit
        values=list(original(path))
        if path.name=='policies' and not hit:
            hit=True; clock.advance('custom-inventory',30)
        return iter(values)
    monkeypatch.setattr(Path,'iterdir',iterdir)
    out=c.scan(**f.kwargs)
    assert popen_count(calls)==0,out


@pytest.mark.parametrize('approval_costs',[(30,0),(0,30),(16,15)])
def test_both_approval_passes_share_clock(tmp_path,monkeypatch,clock,approval_costs):
    """what_bug_this_catches: either exact authorization/profile pass omitted or reset."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock); original=r.BoundedSubprocessRunner.approval; count=0
    def approval(self,inv):
        nonlocal count
        value=original(self,inv); cost=approval_costs[min(count,1)]; count+=1
        clock.advance('capture-approval' if count==1 else 'runner-approval',cost); return value
    monkeypatch.setattr(r.BoundedSubprocessRunner,'approval',approval)
    out=c.scan(**f.kwargs)
    assert popen_count(calls)==0,out


def test_tighter_budget_does_not_reset_after_prep(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: 4s preparation plus 1s process falsely succeeds under a 5s cap."""
    f=fixture(tmp_path,r.Limits(timeout_seconds=5)); calls=fake_process(monkeypatch,f,clock,1)
    timed_wrapper(monkeypatch,r,'mapping_state',clock,'capture-mapping',4)
    out=c.scan(**f.kwargs)
    assert out.status=='timeout' and not out.live_eligible, out


def test_start_persistence_late_prevents_process(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: authorized start receipt fsync crosses D then Popen still occurs."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    original=r.BoundedSubprocessRunner._receipt
    def receipt(path,payload):
        value=original(path,payload)
        if path.name.startswith('.scanner-start-'): clock.advance('start-receipt-durable-return',30)
        return value
    monkeypatch.setattr(r.BoundedSubprocessRunner,'_receipt',staticmethod(receipt))
    out=c.scan(**f.kwargs)
    assert popen_count(calls)==0,out
    assert list(tmp_path.glob('.scanner-start-*')) and list(tmp_path.glob('.scanner-terminal-*'))


@pytest.mark.parametrize('stage',['native-parser','terminal-fsync','raw-stdout-fsync','raw-stderr-fsync','cleanup-wait'])
def test_late_return_cannot_enable_success(tmp_path,monkeypatch,clock,stage):
    """what_bug_this_catches: postprocess parsing/durability/cleanup excluded from final eligibility."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock,wait_cost=30 if stage=='cleanup-wait' else 0)
    if stage=='native-parser': timed_wrapper(monkeypatch,c,'parse_output',clock,stage,30)
    elif stage!='cleanup-wait':
        original=r.BoundedSubprocessRunner._write_bytes
        prefix={ 'terminal-fsync':'.scanner-terminal-', 'raw-stdout-fsync':'.scanner-stdout-', 'raw-stderr-fsync':'.scanner-stderr-'}[stage]
        def write(path,raw):
            value=original(path,raw)
            if path.name.startswith(prefix): clock.advance(stage,30)
            return value
        monkeypatch.setattr(r.BoundedSubprocessRunner,'_write_bytes',staticmethod(write))
    out=c.scan(**f.kwargs)
    assert popen_count(calls)==1
    assert out.status=='timeout' and not out.live_eligible,out
    assert out.start_receipt_sha256 and out.terminal_receipt_sha256 and out.stdout_sha256


def test_closure_pin_drift_preserves_returned_provenance(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: closure validation discards already durable raw/start/terminal proof."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    original=r.BoundedSubprocessRunner.__call__
    def run(self,inv):
        result=original(self,inv)
        with f.kwargs['config_path'].open('ab') as stream: stream.write(b' ')
        return result
    monkeypatch.setattr(r.BoundedSubprocessRunner,'__call__',run)
    out=c.scan(**f.kwargs)
    assert out.status!='ok' and not out.live_eligible
    assert out.start_receipt_sha256 and out.terminal_receipt_sha256 and out.stdout_sha256,out


@pytest.mark.parametrize('deadline',[999.0,True,float('nan'),float('inf')])
def test_direct_runner_rejects_expired_or_invalid_clock(tmp_path,monkeypatch,clock,deadline):
    """what_bug_this_catches: non-tree invocation silently ignores supplied deadline validity/expiry."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    try: result=f.runner(replace(f.inv,attempt_deadline=deadline))
    except (ValueError,TimeoutError): result=None
    assert popen_count(calls)==0,result


def test_clock_identity_excluded_with_legacy_payload(tmp_path,clock):
    """what_bug_this_catches: process-local clock leaks into legacy fingerprint or adds null bundle."""
    f=fixture(tmp_path); inv=f.inv
    expected=r.digest(encoded({'argv':inv.argv,'cwd':str(inv.cwd),'environment':inv.environment,
        'limits':asdict(inv.limits),'files':[(str(p),sha,cap) for p,sha,cap in inv.pinned_files]}))
    assert r.invocation_digest(inv)==expected==r.invocation_digest(replace(inv,attempt_deadline=1005.0))
    assert f.runner.approval(inv).invocation_sha256==expected


@pytest.mark.parametrize('fault',['hash','parser','permission'])
def test_other_gates_survive_ontime_budget(tmp_path,monkeypatch,clock,fault):
    """what_bug_this_catches: being on time bypasses independent file/parser/authorization checks."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock,29.99)
    if fault=='hash':
        with f.kwargs['config_path'].open('ab') as stream: stream.write(b' ')
    elif fault=='parser': f.output=b'not json'
    else: f.kwargs['runner']=r.BoundedSubprocessRunner(False,None)
    out=c.scan(**f.kwargs)
    assert not out.live_eligible and out.status!='ok'
    if fault!='parser': assert popen_count(calls)==0
    if fault=='permission':
        assert out.start_receipt_sha256 is None and out.terminal_receipt_sha256 is None
        assert not list(tmp_path.glob('.scanner-*'))


def test_missing_runner_and_fake_only_do_not_fabricate_provenance(tmp_path,clock):
    """what_bug_this_catches: fake-only/missing activation promoted to measured execution."""
    f=fixture(tmp_path)
    for fake in (False,True):
        report=d.compare(f.manifest,fake_only=fake)
        assert all(not row['live_eligible'] for row in report['rows'])
        assert all(x['start_receipt_sha256'] is None and x['terminal_receipt_sha256'] is None for x in report['capture_receipts'])
    assert not list(tmp_path.glob('.scanner-*'))


@pytest.mark.parametrize('streams',[('stdout',),('stderr',),('stdout','stderr')])
@pytest.mark.parametrize('fault',['write','flush','fsync'])
def test_raw_faults_retain_both_attempts_and_honest_partial_bytes(tmp_path,monkeypatch,clock,streams,fault):
    """what_bug_this_catches: one stream fault prevents other retention or falsely marks complete."""
    f=fixture(tmp_path); fake_process(monkeypatch,f,clock)
    original_open=Path.open; original_fsync=os.fsync; targeted={}; attempted=[]; failed=set()
    class OpenedFile:
        def __init__(self,stream,path): self.stream=stream; self.path=path
        def __enter__(self): self.stream.__enter__(); return self
        def __exit__(self,*args):
            targeted.pop(self.stream.fileno(),None)
            return self.stream.__exit__(*args)
        def fileno(self): return self.stream.fileno()
        def write(self,raw):
            if fault=='write':
                self.stream.write(raw[:max(1,len(raw)//2)]); self.stream.flush()
                clock.advance('raw-partial-write-failure',30 if not failed else 0); failed.add(self.path)
                raise OSError('synthetic partial write')
            return self.stream.write(raw)
        def flush(self):
            if fault=='flush':
                self.stream.flush(); clock.advance('raw-flush-failure',30 if not failed else 0); failed.add(self.path)
                raise OSError('synthetic flush failure')
            return self.stream.flush()
    def opened(path,*args,**kwargs):
        stream=original_open(path,*args,**kwargs)
        if path.name.startswith(('.scanner-stdout-','.scanner-stderr-')):
            attempted.append(path.name)
            if any(path.name.startswith('.scanner-'+name+'-') for name in streams):
                targeted[stream.fileno()]=path
                return OpenedFile(stream,path)
        return stream
    def fsync(fd):
        if fault=='fsync' and fd in targeted:
            path=targeted[fd]; clock.advance('raw-fsync-failure',30 if not failed else 0); failed.add(path)
            raise OSError('synthetic fsync failure')
        return original_fsync(fd)
    monkeypatch.setattr(Path,'open',opened); monkeypatch.setattr(os,'fsync',fsync)
    out=c.scan(**f.kwargs)
    assert len(attempted)==2 and failed
    terminal=json.loads(next(tmp_path.glob('.scanner-terminal-*')).read_bytes())
    assert terminal['retained_output_complete'] is False
    assert out.status!='ok' and not out.live_eligible
    assert out.start_receipt_sha256 and out.terminal_receipt_sha256
    for path in failed:
        assert path.exists() and path.stat().st_size>0
    assert len(list(tmp_path.glob('.scanner-stdout-*')))==1 and len(list(tmp_path.glob('.scanner-stderr-*')))==1


def test_process_wait_uses_remaining_budget(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: unconditional one-second wait exceeds remaining half-second."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock,29.5)
    out=c.scan(**f.kwargs)
    waits=[x['wait_timeout'] for x in calls if 'wait_timeout' in x]
    assert waits and all(0<=value<=0.5 for value in waits), (waits,out)


def test_process_timeout_recovery_does_not_restore_success(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: valid late raw JSON/retention overrides actual process timeout."""
    f=fixture(tmp_path)
    class Process:
        pid=424242; returncode=None
        stdout=io.BytesIO(f.output); stderr=io.BytesIO(b'late stderr')
        def poll(self): return self.returncode
        def kill(self): self.returncode=-9
        def wait(self,timeout=None): return self.returncode
    def popen(*args,**kwargs): clock.advance('running-process',31); return Process()
    monkeypatch.setattr(subprocess,'Popen',popen)
    out=c.scan(**f.kwargs)
    assert out.status=='timeout' and not out.live_eligible
    terminal=json.loads(next(tmp_path.glob('.scanner-terminal-*')).read_bytes())
    assert terminal['timed_out'] is True and terminal['retained_output_complete'] is True
    assert out.stdout_sha256==r.digest(f.output) and out.terminal_receipt_sha256


@pytest.mark.parametrize('deadline,duration',[(1005.0,5),(1200.0,30),(None,30)])
def test_direct_runner_earliest_or_fallback_budget(tmp_path,monkeypatch,clock,deadline,duration):
    """what_bug_this_catches: earlier owner ignored, later extension accepted or fallback absent."""
    f=fixture(tmp_path); fake_process(monkeypatch,f,clock,duration)
    out=f.runner(replace(f.inv,attempt_deadline=deadline))
    assert out.timed_out or out.error_code is not None,out


def test_corrected_inactive_permission_without_receipts(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: inactive runtime fabricates start/terminal provenance."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    f.kwargs['runner']=r.BoundedSubprocessRunner(False,None)
    out=c.scan(**f.kwargs)
    assert popen_count(calls)==0 and out.status=='not_run' and not out.live_eligible
    assert out.start_receipt_sha256 is None and out.terminal_receipt_sha256 is None
    assert not list(tmp_path.glob('.scanner-*'))


@pytest.mark.parametrize('parser_cost',[0.99,1.0])
def test_cumulative_phase_boundary(tmp_path,monkeypatch,clock,parser_cost):
    """what_bug_this_catches: cumulative valid phases rearm despite individually short durations."""
    f=fixture(tmp_path); fake_process(monkeypatch,f,clock,5)
    timed_wrapper(monkeypatch,r,'mapping_state',clock,'mapping',2)
    timed_wrapper(monkeypatch,r.BoundedSubprocessRunner,'approval',clock,'each-approval',4)
    original=r.BoundedSubprocessRunner._write_bytes
    def write(path,raw):
        value=original(path,raw)
        cost=3 if path.name.startswith(('.scanner-start-','.scanner-terminal-')) else 4
        clock.advance('persist-'+path.suffix,cost)
        return value
    monkeypatch.setattr(r.BoundedSubprocessRunner,'_write_bytes',staticmethod(write))
    timed_wrapper(monkeypatch,c,'parse_output',clock,'native-parser',parser_cost)
    out=c.scan(**f.kwargs)
    assert abs(clock.now-(1029+parser_cost))<1e-8
    assert out.live_eligible is (parser_cost<1.0),out


def test_immediate_pre_popen_directory_late_return(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: last plain-directory check returns late and still starts process."""
    f=fixture(tmp_path); calls=fake_process(monkeypatch,f,clock)
    original=r._plain_directory; charged=False
    def plain(path):
        nonlocal charged
        value=original(path)
        if not charged and list(tmp_path.glob('.scanner-start-*')):
            charged=True; clock.advance('immediate-pre-Popen-directory-return',30)
        return value
    monkeypatch.setattr(r,'_plain_directory',plain)
    out=c.scan(**f.kwargs)
    assert charged and popen_count(calls)==0,out


def test_final_locator_validation_crosses_deadline(tmp_path,monkeypatch,clock):
    """what_bug_this_catches: parser returns on time but final locator validation completes late."""
    f=fixture(tmp_path); fake_process(monkeypatch,f,clock)
    original=c.parse_output
    class Rows(tuple):
        charged=False
        def __iter__(self):
            if not self.charged:
                self.charged=True; clock.advance('native-locator-validation',30)
            return super().__iter__()
    def parser(value): return Rows(original(value))
    monkeypatch.setattr(c,'parse_output',parser)
    out=c.scan(**f.kwargs)
    assert out.status=='timeout' and not out.live_eligible,out
