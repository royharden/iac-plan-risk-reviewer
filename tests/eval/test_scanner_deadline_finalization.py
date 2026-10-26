"""Original nine focused controls, individually collected by pytest.

Factory bodies and their expectation_met expressions are preserved verbatim.
This adapter replaces the manual harness, never its expected results.
"""
import json
import time
import pytest
from shared_deadline_fixtures import helpers as h
from shared_deadline_fixtures.helpers import r, d, c
from shared_deadline_fixtures.runtime import deny_real_effects

def final_cell(delay):
    def check(folder,mp,clock,record):
        """Final per-cell mapping completing at/after D must not create a recorded/live-eligible row."""
        f=h.fixture(folder); calls=h.fake_process(mp,f,clock)
        original=d.cell_status
        def cell(*args,**kwargs):
            value=original(*args,**kwargs)
            clock.advance('final-cell-mapping-return',delay)
            return value
        mp.setattr(d,'cell_status',cell)
        report=d.compare(f.manifest,runner=f.runner)
        row=next(x for x in report['rows'] if x['arm']=='C' and x['rule_id']=='R2')
        receipt=next(x for x in report['capture_receipts'] if x['arm']=='C')
        record.update(delay=delay,popen_calls=h.popen_count(calls),row=row,capture_receipt=receipt,final_clock=clock.now,
                      expected_eligible=delay<30,expectation_met=row['live_eligible'] is (delay<30))
    return check


def strict_decode(delay):
    def check(folder,mp,clock,record):
        """Delayed strict JSON decode of returned stdout consumes D and retains raw/start/terminal provenance."""
        f=h.fixture(folder); calls=h.fake_process(mp,f,clock)
        original=r.strict_json
        def decode(raw):
            result=original(raw)
            if raw==f.output: clock.advance('strict-output-JSON-return',delay)
            return result
        mp.setattr(r,'strict_json',decode)
        out=c.scan(**f.kwargs)
        record.update(delay=delay,popen_calls=h.popen_count(calls),artifact=h.asdict(out),final_clock=clock.now,
                      expectation_met=(out.live_eligible is (delay<30) and bool(out.start_receipt_sha256 and out.terminal_receipt_sha256 and out.stdout_sha256)))
    return check


def tighter(prep,process):
    def check(folder,mp,clock,record):
        """5s owner deadline begins before first plan preparation; only remaining budget reaches Popen and wait."""
        f=h.fixture(folder,r.Limits(timeout_seconds=5)); calls=h.fake_process(mp,f,clock,process)
        original=r.bounded_read; hit=False
        def read(path,cap):
            nonlocal hit
            value=original(path,cap)
            if path==f.kwargs['plan_path'] and not hit:
                hit=True; clock.advance('first-plan-preparation-read',prep)
            return value
        mp.setattr(r,'bounded_read',read)
        out=c.scan(**f.kwargs)
        popens=h.popen_count(calls); waits=[x['wait_timeout'] for x in calls if 'wait_timeout' in x]
        expected=prep+process<5
        record.update(prep=prep,process=process,calls=calls,artifact=h.asdict(out),final_clock=clock.now,
                      expectation_met=(out.live_eligible is expected and popens==(0 if prep>=5 else 1)
                          and all(0<=v<=max(0,5-prep-process) for v in waits)))
    return check


def held_drain(folder,mp,clock,record):
    """A descendant-held pipe cannot renew the remaining drain window or become complete eligible output."""
    f=h.fixture(folder); calls=h.fake_process(mp,f,clock,29.5)
    import threading
    joins=[]
    class HeldReader:
        def __init__(self,**kwargs): pass
        def start(self): pass
        def join(self,timeout=None):
            joins.append(timeout); clock.advance('held-pipe-drain-join',timeout)
        def is_alive(self): return True
    mp.setattr(threading,'Thread',HeldReader)
    out=c.scan(**f.kwargs)
    terminal=json.loads(next(folder.glob('.scanner-terminal-*')).read_bytes())
    record.update(joins=joins,calls=calls,artifact=h.asdict(out),terminal=terminal,final_clock=clock.now,
                  expectation_met=(out.status=='timeout' and not out.live_eligible and joins==[0.5,0.0]
                                   and out.output_truncated and bool(out.start_receipt_sha256 and out.terminal_receipt_sha256)))


def _execute(check, tmp_path, monkeypatch):
    clock = h.FakeClock()
    record = {}
    monkeypatch.setattr(time, 'monotonic', clock.monotonic)
    check(tmp_path, monkeypatch, clock, record)
    with (tmp_path/'focused-result.json').open('x', encoding='utf-8') as stream:
        json.dump({'record': record, 'clock_events': clock.events}, stream, indent=2)
    assert record['expectation_met'], record

@pytest.mark.parametrize('delay', [29.99, 30.0, 30.01])
def test_final_cell(delay, tmp_path, monkeypatch):
    _execute(final_cell(delay), tmp_path, monkeypatch)

@pytest.mark.parametrize('delay', [29.99, 30.0])
def test_strict_decode(delay, tmp_path, monkeypatch):
    _execute(strict_decode(delay), tmp_path, monkeypatch)

@pytest.mark.parametrize('prep,process', [(4.0,0.99), (4.0,1.0), (5.0,0.0)])
def test_tighter(prep, process, tmp_path, monkeypatch):
    _execute(tighter(prep,process), tmp_path, monkeypatch)

def test_held_drain(tmp_path, monkeypatch):
    _execute(held_drain, tmp_path, monkeypatch)
