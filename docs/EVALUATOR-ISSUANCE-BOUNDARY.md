# Trusted evaluator issuance socket: prototype boundary

The module `observer/issuance.py` provides a bounded AF_UNIX request handler backed by `ChallengeAuthority`. The Linux `SO_PEERCRED` UID of the connecting process must equal the explicitly configured evaluator UID. An observer UID can be provided so same-identity configuration is rejected. The handler accepts only a case, `synthetic-effect` purpose, and bounded TTL; a repeated case or unauthenticated caller receives no challenge.

**Security scope:** This code is only an issuance IPC primitive and same-user tests for both accepted and simulated rejected UID. No independently administered evaluator UID, socket ACL or dedicated trust domain is provisioned or tested. The token is returned to the evaluator; secure case-scoped transfer to the broker is not implemented. The evaluator socket must never be mounted inside a sandboxed subject. The in-memory challenge registry is lost on crash. The service startup is still intentionally disabled; this module is not wired to the deployed entry point. No production acceptance gate is satisfied.

The next acceptance tests must run separate evaluator, observer, broker and subject UIDs, deny wrong-UID callers using the real kernel, confirm authorization state and journal recovery across process death, and prove the broker cannot solicit an issuer token or impersonate the evaluator.

## IPC custody correction

The earlier owner-only issuer directory/socket design (`0700`/`0600`)
was incompatible with a genuinely separate evaluator UID. The revised
server supports observer-owned `0710` directory (group `gts-evaluator`)
and `0660` socket while checking the connecting UID with `SO_PEERCRED`.
A restricted broker delivery socket is implemented using the same access
principle with evaluator-group access but broker-owned process identity.
Group access alone is not identity authority; UID checking remains mandatory.

The host accounts, directories, key hierarchy, independent receipt signing
and runtime installation must be established by independently administered
operations. Current unit fixtures are not real cross-account acceptance.
