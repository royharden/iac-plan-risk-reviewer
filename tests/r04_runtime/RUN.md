# R04 reviewer tests

Use Python3.12 with pinned project pytest9.0.3. Invoke from the outer shell:

    <locked-python> -I -B <this-dir>/run_suite.py --candidate <pinned-source-root> --scope runtime --output <new-output>
    <locked-python> -I -B <this-dir>/run_suite.py --candidate <product-root> --scope cli --output <different-new-output>

The runtime source root contains exact frozen runtime_v1/ and runtime_launch/.
The CLI source root contains src/iac_review/. Output parent must exist, and the
output directory must be absent. Prefer ordinary retained CWorktrees paths.
Both runs retain stdout/stderr/JUnit/command/supervisor/results, with pre/post
source/test/data hashes and import origins. The real supervisor bounds180s.
Ambient pytest plugins/options, bytecode, assertion rewrite, cache, FD capture
and logging are disabled. Candidate network/native/link/delete effects refuse.
Windows pytest tool support is initialized before candidate imports. CLI
subprocesses are explicit trusted local commands; the parent guard is not a
child OS sandbox. No original103 bodies, operational contexts or OS backend run.

Historical logical tests/oracles in lineage/ remain byte-identical; they are
provenance, not runnable tests or passing case counts. Own explicit scopes do
not collect lineage or schema-export suites. Four exact0105 data leaves are
copied into data/ with original SHA pins checked on every use. fixture_data.py
mechanically changes its sibling import and DATA root only. No approval record
or operational authority is installed by those synthetic in-memory fixtures.

CONTROLS-r1 and its numbered API-informed addition state normative expectations.
Coverage: inert eight-slot/103 completion, finite parser joins, poison/error/
post-readback, pure process/metadata negatives, default refusal, inert launcher
composition and synthetic CLI privacy/exit/verify/share. Full origin-positive
closure and dormant original protocol/plugin/backend qualification remain
separate incomplete coverage. A green run is not original103/native/product
acceptance; the known91/12 history and schema-generation hold remain unchanged.
