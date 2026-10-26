# RV4 receiver controls r1

Frozen before candidate inspection, 2026-10-26. Author app0117 / workspace0692,
session01a17a67-8217-73a2-b74c-d82a0b6bb1fd, Medium. Normative inputs:
R03 D10-storage-receiver-interface-r1.md, frozen storage-v3 with both stage
addenda, R04 CONTRACT-R04-semantics-r1.md. These are public synthetic/offline
controls, not a hidden oracle or native custody qualification.

1. Valid bounded wire: immutable reader, existing ordinary destination, fresh
   local reservation, finite future deadline. Capture bytes equal the entire
   wire; complete SHA is SHA256 of independent readback. Local diagnostic cannot
   claim native eligibility/durability/ExternalStatus/FINAL_COMPLETE.
2. Before validation: malformed header, short header/record/trailer, trailing byte,
   wrong header identity, wrong generated identity, bad payload hash, reordered
   record, duplicate record, invalid state, overcap input and absent EOF must
   yield a noncomplete result and null complete hash. No capture file may exist;
   no capture open/write attempt is allowed. Earlier frozen error stages win.
3. Reader over-return/nonbytes/exception/changing snapshot is noncomplete; no
   capture creation. Reader requests stay finite, total buffering <=16MiB+1.
4. Destination: missing/relative/root link/special/foreign owner/changed metadata,
   existing capture/status refuse. Never overwrite. Names use only expected
   Identity; record payload never supplies a host path.
5. Reservation: exact integers, bounds1..16MiB and1..64KiB, bool rejected,
   one-shot consumed on receive admission; second use refuses without host writes.
6. Deadline: finite absolute nonrenewing clock; expired before IO, or crossing
   before/after read/write/flush/fsync/readback/status, cannot complete. Once
   expired no further host writes including diagnostic writes. No hard-preemption
   claim for cooperative adapters.
7. Short write: only returned count charged, retain actual prefix, no retry or
   cleanup; complete hash null. A trustworthy independent readback may supply
   prefix hash, otherwise null. Negative/bool/too-large/noninteger write counts
   or write exception imply unknown count; conservatively charge requested range,
   capture_bytes null, and perform no further host writes, including status.
8. Inject exclusive-open/flush/fsync/readback/metadata/close failures: preserve
   actual artifacts; no cleanup/retry. Changed/truncated/extra readback never
   yields complete hash. Unknown facts remain null. First fault survives a
   later diagnostic fault. Independent readback/hash is not physical durability.
9. Status has its own <=64KiB budget, distinct capture charge, bounded identity
   and counts, always false native/durable flags, no invented reservation-index
   or verification-event hashes. Failure status cannot replace first fault.
10. Effect boundary: trusted fake adapters and ordinary files only, fresh retained
    outputs. No network/subprocess/native/link creation/deletion, hidden input,
    prohibited schema generation, cleanup, actual context, or custody installation.

API-specific case construction may use separately numbered amendments after
inspection. Any ambiguity is reported, not resolved from observed source output.
