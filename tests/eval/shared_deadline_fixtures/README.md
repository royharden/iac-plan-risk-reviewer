# Shared deadline regression provenance

These are synthetic scanner-boundary unit controls. They exercise ordinary
repository imports from `eval.scanners`, fake subprocess results, inert scanner
fixture bytes and artificial development grants. They establish neither native
scanner compatibility nor physical latency or hard preemption.

The original runner starts real bounded Python reader threads over the fake
process's in-memory `BytesIO` stdout/stderr streams. That execution model is
preserved. The held-drain control instead uses its original `HeldReader` fake
with expected joins `[0.5, 0.0]`; it models no physical descendant-held pipe.
Process, network, link and deletion effects remain forbidden in these tests.

`test_scanner_shared_deadline.py` preserves the original corrected 57 controls
from reviewer 0073's `successor-r2` package. Its original shared helper and
supplemental files had SHA-256 values
`8a7e872773beb9101aefb3baa99ebc97e1d6eb90b1bb19acf612bb83cb1c2259`
and `2e2a0b1d2d8e7c2ab00eb737bdf4f5aeae6d74f5f2fbb2dad124a2d6a3f3f08d`.
These identify provenance; test behavior does not depend on a historical source
hash or an external worktree. Helpers moved into this directory; the clock's
diagnostic trace now lives beneath the case's retained `tmp_path`.

`test_scanner_deadline_finalization.py` preserves the original nine focused
checks from reviewer 0091, frozen by reviewer 0096 with SHA-256
`af1cda6c887059616e65c511f80e8862e8d5891194f5ecbf3c9f6851d481162d`.
The four original factory/function bodies and `expectation_met` predicates are
unchanged. Pytest now collects three final-cell boundaries (29.99, 30, 30.01),
two strict JSON decoding boundaries, three tighter-cap cases and one held-reader
case separately. Each wrapper asserts the existing predicate and retains its
record in the case directory. The frozen helper was byte-identical to the
corrected 57-control helper.

The historical 52-case run, five supplemental cases and one corrected targeted
case are separate observations. Reviewer 0081's complete corrected 57-case
execution reported 21 passes and 36 source assertion failures. Later source 924
author evidence reported 57 passes; reviewer 0101 rederived that report without
independently rerunning those 57. Reviewer 0101 independently ran the original
nine against old f197 (seven pass, two fail) and new 924 (nine pass). Reviewer
0101's additional 57 diagnostics are a separate suite and are not counted here.

Elapsed is a pre-hash sample covering operations before that sample. Future
self hashing, serialization, return CPU and physical IO latency are excluded.
Late observed work must remain ineligible. Source/API-aware instrumentation
requires review when the named phase structure changes. The original legacy
103-case acceptance, entrypoint activation and product acceptance remain separate.
