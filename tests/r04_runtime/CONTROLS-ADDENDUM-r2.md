# RV3 numbered API-informed control addition r2

Grounded in D12-persistent-stop-API-r3.md and the existing permanent-poison
contract. Prior source inspection has occurred; no blind-oracle claim.

stop_inert(reason,cause) returns None, keeps first cause by identity, never
finalizes or clears pending. Later require_exact refuses with retained cause,
including when a new wrapper is constructed. Invalid reason/cause objects
must not be stringified. All operational context issuance remains refused.

Pure summarize_results checks canonical103 DATA domain/status/order only; its
acceptance cannot substitute for eight finalized slots in context completion.
Injected process/ordinary-metadata negative controls do not qualify an OS backend.
