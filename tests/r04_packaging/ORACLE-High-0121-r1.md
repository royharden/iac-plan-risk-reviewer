# PKG-TEST-01 repair controls

Author: 0121_Codex_gpt-61-sol_Sub_PackagingRepair; fresh High repair of the
genuine Medium independent failure recorded in TEST-REVIEW-0120-r1.json.
Original ORACLE-r1.md and its nineteen controls remain in force.

Before declared payload reads, enumerate names and non-following metadata only.
Actual files must equal the externally pinned file set. Actual directories must
equal exactly its parent-directory closure. Reject any extra ordinary file,
extra empty directory, missing file, link/reparse, special entry, or multiply
linked file. Never open undeclared payloads or descend into extra directories.
Windows metadata uses Path.lstat: DirEntry.stat omitted st_nlink in the retained
first substantive repair run, which failed eight controls and was corrected.

Twelve additional controls cover an inert undeclared file, empty directory,
five trusted injected metadata variants (symlink, directory reparse, FIFO,
socket, multiply-linked regular file), a missing declaration, and four inert
credential-like names guarded against payload reads. No native links/devices
or credentials are used. Synthetic source manifests now list their own source
receipt, matching the real staged representation and exact membership rule.

The separate supervised run_context.py CLI validates the exact D15 context with
the externally supplied context/source/packaging pins. Every invocation retains
stdout, stderr, native exit, helper hash and a real 180-second timeout. The
public controls runner also retains JUnit. Both runners execute metadata only,
without importing candidate modules or starting Docker/scanners. No product,
image-loaded-bytes or release acceptance is implied. Independent High review
belongs to the RV3 route; this author cannot approve the repair.
