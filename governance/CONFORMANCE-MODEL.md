# GTS conformance and independent assessment — design v0.1

## Distinct deliverables
**Schema validity** establishes document structure only.
**Protocol conformance** establishes behavior against identified normative MUST requirements under a bounded scenario.
**Security assessment** attempts to falsify explicitly scoped security claims through adversarial testing and independent side-effect observation.
**Third-party assessment** additionally requires a verifier who is independent of the system operator, with its own infrastructure, challenge selection, custody of signing keys, and disclosure of conflicts. None implies universal correctness or legal certification.

## Conformance profiles
- `gts.adapter.stdio.v0.1`: adapter discovery and request/response transport semantics; no authorization guarantee.
- `gts.authorization.v0.1` (planned): independent issuer, explicit policy enforcement boundary, grant binding, expiry and replay protection.
- `gts.evidence.v0.1` (planned): issuer authentication, artifact integrity, action binding, independent observation and freshness.
- `gts.execution.v0.1` (planned): external side effects, isolation, idempotency/retry limits and crash recovery.
- `gts.assessment.v0.1` (planned): independent challenge provenance, negative controls, mutation tests and scoped adjudication.

Only `gts.adapter.stdio.v0.1` has a partial reference fixture today; other profiles must not be advertised as implemented.

## Mandatory assessment record
Subject commit and artifact digest; referenced profile and version; environment and dependencies; tester and control relationship; issuer trust anchor; independent effect oracle; exact inputs and expected outcomes; observed externally recorded effects; negative controls; mutation sensitivity; coverage/known omissions; raw artifact references; result classification; timestamp; verifier signature and signature-verification instructions. Report provenance alone is not truth of its conclusion.

## Trust separation
Never let the system under test supply the verifier's expected outcome, secret challenge cases, observer results, or trust anchors. Self-generated hashes or signatures cannot establish independent evidence. Treat an ambiguous effect as inconclusive. Unsupported or inaccessible test paths must be recorded as not_exercised or unreachable, not silently skipped.

## Acceptance
A report may use `verified_within_scope` only if an externally controlled oracle measured an effect and relevant negative controls demonstrate test sensitivity. A SUT-owned fixture test cannot claim independent verification. Disputed findings are preserved with append-only amendments rather than overwritten.
