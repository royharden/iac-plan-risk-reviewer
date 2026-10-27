# RX-ID-01 regression oracle r2

Author: 0122_Codex_gpt-61-sol_Sub_ReceiverRegression / workspace0697.
Exact native session: 01a17a80-6f82-79d2-9c87-72e64fb46b50. Effort: High.
Frozen before inspecting any repaired receiver implementation and before candidate
execution. Normative inputs: R04 CONTRACT-R04-semantics-r1 (PFX-01, STATUS-01),
original ORACLE-r1 clauses 1, 4, 8, 9; RV3 SOURCE-REVIEW-0118-r1 finding RX-ID-01.
The diagnostic_identity_r2.py is read only as a permitted reproduction reference.
Original ORACLE-r1 and all 110 controls remain unchanged.

1. RX-ID-01-CAPTURE-CLOSE. After the exclusive capture writer closes and before
   independent readback, return a stable changed regular-file inode through the
   trusted filesystem metadata adapter. The observed writer identity must remain
   the baseline; noncomplete outcome, null complete SHA and retained identity
   fault are required. Same bytes and unchanged real host inode; no replacement.
2. RX-ID-01-STATUS-CLOSE. Apply the same transition only to the status object.
   A changed status object cannot be committed; status_committed=false,
   complete_sha256=null and noncomplete outcome are required. The capture remains
   a retained ordinary file. A local receipt is never global custody proof.
3. RX-ID-01-CAPTURE-FINAL / STATUS-FINAL. Metadata remains stable through writer
   close and independent readback, then changes after the corresponding read
   handle closes, before final-state metadata checks. The outcome cannot COMPLETE;
   complete_sha256=null and status_committed=false are required when status
   identity fails. Writer identity cannot be replaced by any later baseline.
4. RX-ID-01-FIRST-FAULT. A trustworthy short capture write precedes a status
   identity failure. The original SHORT_WRITE code and known prefix count survive;
   complete_sha256 remains null, status_committed=false. A later metadata failure
   cannot replace the first fault. Retain all actual artifacts without retry.
5. RX-ID-01-CONTROLS. Stable injected metadata, for both full and short capture
   writes, must preserve the existing successful or SHORT_WRITE behavior. The
   injection must report the selected phase actually occurred and expose both
   writer and changed observations so a vacuous pass is rejected. Each negative
   case must prove real files retained their original inode and bytes while only
   observed metadata changed. No source-private state changes or host mutation.
6. Effects: only fresh retained ordinary CWorktrees output, exact frozen source,
   literals and tests. Adapter delegates bounded ordinary operations; metadata
   differences exist only in trusted return values. No physical replacement,
   links/native calls/deletion/cleanup/network/live/credentialed/device actions.
   Deadline and unknown-write count prohibitions remain unchanged. Candidate
   import/execution waits for independent full effect-closure preflight.

API-informed case construction may be amended in a new numbered document, never
by weakening these predicates or interpreting candidate outcomes as authority.
This is public issue-informed regression evidence, not hidden holdout/native or
physical custody qualification, product acceptance or release acceptance.
