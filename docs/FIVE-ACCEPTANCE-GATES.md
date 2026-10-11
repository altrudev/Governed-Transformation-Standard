# GTS five security acceptance gates — evidence ledger

This ledger prevents a test-pass count from being interpreted as five production acceptance gates passed.

| Gate | Current status | Existing proof | Missing proof |
| --- | --- | --- | --- |
| Actual host UID socket | BLOCKED | Linux accounts exist and owner-only observer directory checked on Prometheus | Live broker UID 990 connecting to observer UID 991; unauthorized UID denial under real Linux peer credentials, reviewed unit permissions |
| Broker challenge issuance | PARTIAL | Receiver now optionally consumes scoped, expiring single-use verifier-created tokens; adversarial socket tests reject unissued, reused, substituted cases | Independent trusted issuer, broker delivery without SUT exposure, production service wiring and authenticated issuance origin |
| Observer key custody | BLOCKED | Standalone Ed25519 journal test uses a pinned verifier key | Admin-provisioned private key owner-only, observer-runtime signing, external trust-anchor distribution, broker/SUT denied key access |
| Durable journal recovery | PARTIAL | Prototype fsync-backed hash-chain stores events before ACK, reload verifies edits/truncation and duplicates, injected storage failure prevents ACK | Dedicated observer UID deployment, crash injection, recovery after power loss, external append-only anchor, committed-challenge ordering |
| Sandbox cannot impersonate broker | BLOCKED | Fixture UID rejection and sandbox network isolation exercised separately | Real sandbox subject unable to traverse broker socket, spoof SO_PEERCRED UID or obtain bearer authority while broker can submit legitimately |

## Important design caveats

The existing `Receiver` can still be constructed in legacy challenge mode for compatibility tests; deployment entry point unconditionally refuses startup pending independently controlled challenge issuance. The receiver's optional challenge authority and durable store are exercised by integrated *test fixtures*, not yet by a production service. The hash-linked journal does not establish independent custody: a filesystem writer can rewrite the entire chain. Its events are declarations received via a socket, not independently observed effects. The current challenge is consumed before durable append; a fault may burn an authorization without recording an effect. That is fail-closed for acknowledgements but does not implement transactional replay recovery.

No gate should be labelled PASS based on these prototype tests. The GTS release acceptance remains BLOCKED.

## Observer key-loader development update
The repository now includes an owner-only Ed25519 private-key loader with file-owner, strict 0600, regular-file, single-link, symlink and size checks. Keys are **never generated during service startup**. These checks are local test fixtures only: no signer has been provisioned under gts-observer, no trusted key-distribution protocol exists, and this is not production custody acceptance.
