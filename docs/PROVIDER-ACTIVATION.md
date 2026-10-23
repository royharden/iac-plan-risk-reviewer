# Disabled provider wire and later activation

Dirty Mode source construction: **runtime unverified**. No provider wire, fake HTTP,
network client, credential lookup, model call or regression has been executed. This
package installs no SDK. The wire codec still accepts only exact in-memory FakeHttp;
separate provider_activation/provider_http source now defines a disabled, journal-bound
HTTPS path for later authorized activation. It has not been imported or executed.
The ordinary synthetic CLI has no new live-provider mode.

Official OpenAI documentation was searched and actually opened on 2026-10-23.
The [text guide](https://developers.openai.com/api/docs/guides/text) establishes the
Responses endpoint, instructions/input separation and typed output traversal; the
codec scans message content instead of assuming the first output item is text.
The [migration guide](https://developers.openai.com/api/docs/guides/migrate-to-responses)
documents disabling response storage with `store: false`.
The [reasoning guide](https://developers.openai.com/api/docs/guides/reasoning)
documents reported input/output usage, output tokens including reasoning, and
incomplete responses at output limits. The
[function-calling guide](https://developers.openai.com/api/docs/guides/function-calling)
documents `tool_choice: none` and parallel-call control. No model, availability,
account access, provider price or genuine usage measurement was inferred from examples.
The oversized full API-reference page could not be fetched by the browser; the
opened official guides ground this deliberately narrow wire, not every API field.

`ResponsesWire(ProviderConfig(...), FakeHttp(...))` is disabled by default. Even
fake use requires enabled=True, one ApprovedAttempt and its separately supplied
permit digest. The permit binds exact model/version/endpoint, provider/price/budget/
data-transfer/approval/start-record hashes, opaque attempt ID, safe projection/prompt/
full-request hashes and token bounds. Each permit is used at most once per wire
instance, including timeout/error; no retry grant is inferred. Durable cross-instance
ownership/admission remains the real journal/controller's job. Hashes are declared
approval references, not authenticated authorization or permission to contact OpenAI.

Hash meanings follow `agentops/HASH-SEMANTICS-SEAM.md`: the original journal
`hashes[input]` is canonical MODEL REQUEST `{arm,instruction,payload}`. The codec's
`model_request_digest` matches it exactly and the permit requires that separate pin.
`request_digest(request,config)` is an additional wire/config approval digest; it
does not replace journal input. Raw plan identity remains Context.source_sha256
outside this codec; local wire receipts explicitly leave raw_source_sha256 null.
Capture/index retain artifact.raw_input_sha256 from that raw source, and projection
from the original snapshot's projection hash. No attempt or manifest is cloned,
rewritten or re-pinned; no raw source is inferred from either request hash.

The raw-case cardinality clarification also applies: findings on the same saved
plan share one raw scenario, regardless of distinct request/projection digests.
Independent 24-scenario coverage requires the externally frozen eligible raw-input
inventory. CaseApprovalReference.case_sha256 identifies the exact case RECORD,
not the raw plan, request or projection. A genuine multi-plan aggregate retains
each case's own Context/ExportBundle; this wire creates no scenarios or case pins.

The endpoint is fixed to `https://api.openai.com/v1/responses`. Request data is
canonical finite L/P or safe model-only M input, independently checked against the
existing product capsule builder/M schema and frozen policy. Arbitrary baselines,
raw plan fields, labels/splits/scanner extras and unsafe values are refused before
the fake exchange. No prior response/conversation, metadata, tools or follow-up
actions are exposed. The body sets no storage, no streaming, empty tools, no tool
choice and no parallel tool calls. Returned tool items are refused, never executed.

Only environment **names** `OPENAI_API_KEY` and `IAC_REVIEW_MODEL` appear in source.
No environment value has been read; fake HTTP receives no Authorization header.
The new transport source defers its fixed-name credential read until independently
approved provider/model/price/budget/data-transfer/request admission and exact journal
start checks. A Boolean alone cannot activate it: an external controller must supply
an activation, independent expected activation/permit pins, and a matching active start.
Those supplied hashes are not cryptographic proof of controller/operator identity.

Request/response bytes, generated text, item counts, token caps and timeout are
bounded. Fake responses model timeout/error/redirect cases without I/O. The codec
checks elapsed/returned bounds but does **not** claim hard socket/read interruption.
The new connector source sets the remaining whole-attempt deadline on each connect,
TLS handshake, send and raw read, then checks elapsed time again. No redirect or credential
forwarding, retry, polling, background task or response follow-up exists here.

Reported token counts are preserved independently; missing/invalid/contradictory
usage remains unknown. Reasoning counts are not added again to output totals.
Known USD is always None because token counts and a price hash do not authenticate
actual billing. The attempt journal must keep that liability and refuse further
calls until explicit operator reconciliation. Incomplete/refused/tool/changed-model
responses never become ok even if some text is present. Bounded malformed/error
HTTP envelopes are returned as invalid/error data so opt-in private capture can
retain failures; envelopes above the HTTP cap are explicitly rejected, not silently
treated as successful generated text. Hash/status-only exchange receipts distinguish
HTTP-body identity from returned text/envelope identity; no prompt/body/key text is
logged and no live provenance is asserted.

Before real activation: close Dirty Mode; approve exact model/data terms/prices and
caps; independently verify the source connector, credential access, hard I/O bounds
and durable one-attempt journal linkage; run meaningful fake
and real integration/security/unknown-billing checks; staff/freeze independent corpus
and rubric custody; separately authorize any spend/data transfer. All live measurements
remain NOT MEASURED. The focused fake-HTTP regression source has not been run.

The new source API is `ProviderTransport(config, enabled=False, controller=None,
connector_factory=None, key_reader=None)`. Construction is side-effect free.
`complete(request)` always refuses absent journal linkage. The executor seam
is `complete_started(request, *, journal, attempt_id, deadline_monotonic)` and returns
`ProviderReply`, a compatible Reply subclass with `payload_complete`. It reads the
actual bounded journal through existing helpers, requires the last unmatched start
and no other unresolved attempts/overrun, then verifies the external admission before
key access or connector creation. It never starts, reconciles or retries the journal.
The controller receives only the safe Request, immutable StartedAttempt receipt and
ProviderConfig. It must supply `Admission(activation, permit, expected_activation_sha256,
expected_permit_sha256)` from an externally trusted approval owner. Reuse within a
transport is refused even after rejection. Other instances are prevented from ordinary
reuse by journal terminal/pending state and the exclusively owned worker; this source
does not claim distributed at-most-once authorization across malicious callers/crashes.

The HTTPS source sends one fixed POST, direct to an externally approved public numeric
IP on 443. SNI, certificate hostname validation and Host stay `api.openai.com`.
No DNS, proxy discovery, URL routing, client certificate discovery, SSLKEYLOGFILE,
arbitrary header, redirect following or retry exists. OS CA trust is loaded through
SSLContext(PROTOCOL_TLS_CLIENT); its deployment trust store remains an activation
assumption. No key or response is logged; Python string cleanup is not secure erasure.
The numeric address must be freshly resolved/approved outside this transport; no
address in regression source is an actual provider route or authorized destination.

HTTP1.1 content-length/chunked responses are bounded in raw bytes, headers/framing,
decoded body and generated output. Conflicting framing/compression is refused.
Partial response bytes carry payload_complete=False; counts/USD remain unknown when
the complete usage envelope is unavailable, preserving journal upper liabilities.
Completed responses reuse the established codec in memory; its fake decoder receipts
are not passed off as real HTTP evidence. Transport receipts remain hash/status-only,
connector-origin/billing unauthenticated and live-ineligible. Real DNS/IP rotation,
TLS/Windows interruption/trust behavior, cancellation/crash durability, OS memory
handling, controller authenticity and all regression/integration tests are unverified.
Trusted approval/key/factory callbacks must return promptly; an expired deadline
prevents any subsequent I/O, but Python cannot forcibly preempt arbitrary callback code.

Driver reconciliation is source-complete: run_experiments dispatches the optional
journal-bound method after durable start without changing its public signature.
run_driver adds optional journal=None/provider_mode=False, preserving fake defaults
and the CLI. Explicit programmatic provider mode requires fake=False, an enabled
external controller and a caller-owned journal with the exact budget/price identity.
The driver never closes/replaces that shared journal or substitutes mock-zero prices.
Protocol/fake evidence still has no live admission; no programmatic path was invoked.
Partial ProviderReply flags reach P capture as incomplete diagnostics. Regression
source covers fake-mode exclusion, shared ownership, after-start dispatch, unknown
billing stopping additional starts and prefix-only capture. No regression was run.
