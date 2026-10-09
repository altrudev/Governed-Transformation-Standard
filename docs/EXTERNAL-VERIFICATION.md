# External verification protocol — GTS draft 0.1

This is a public, provider-neutral test protocol, not a certification. A result is scoped to an exact artifact, test environment, independently observed effects, known limitations and verifier identity.

## Roles
- System under test (SUT): exposes a documented adapter. Its PASS flags, log records, authorization claims and signatures are untrusted until separately checked.
- Test author: specifies a measurable invariant and its failure mode.
- Runner: executes a frozen subject in a controlled environment; it may not accept scripts supplied by the SUT without explicit sandbox permissions.
- Observer: measures actual effects outside the SUT (for example a fixture API's independent request log).
- Verifier: chooses challenges, controls the observations and signs a scoped report. Owner-operated machines remain internal even when physically separate.
- External reviewer: independently controls a runner, challenge selection and trust root; discloses affiliations and limitations.

## Standard vocabulary
Use: authorization, issuer authentication, trust anchor, provenance, integrity, replay protection, idempotency, isolated execution, independent observation, conformance test, mutation test, and counterexample. Avoid private project terminology in normative requirements.

## Adapter interface
Reference contract: one JSON request per process via standard input, one JSON response via standard output. Request fields: protocol_version ('0.1'), case_id, operation ('capabilities' or 'submit'), parameters. Response fields: protocol_version, case_id, status and evidence_refs. Unknown operations fail. Other transports may be added by separate normative profiles.

## Procedure
1. Freeze subject commit and build digest. Record toolchain, dependencies and runtime.
2. Map each declared claim to a reachable executable interface and independently measurable effect.
3. Select negative controls, attacker-controlled inputs, concurrent and crash-recovery cases.
4. Capture exact commands, exit codes, stdout/stderr and independent effects. A PASS field from the SUT is not an effect.
5. Deliberately remove a security control in an isolated mutation build. The test must detect its removal.
6. Record unexercised and unreachable paths; they cannot pass by default.
7. Have a reviewer outside the SUT operator's control reproduce at least one challenge and publish signed evidence, subject identity and limitations.

## Outcome terms
verified_within_scope; falsified; inconclusive; not_exercised; unreachable; unverifiable. No claim of 100% correctness. A signature proves authenticity of a statement, not truth of its contents.

## Initial challenge families
Self-issued approval; forged issuer and independence label; altered request binding; nonce replay and concurrent duplicates; direct network bypass; fabricated execution outcome; crash after dispatch; tampered or missing evidence.

## Confidentiality
Use synthetic fixtures and test-only credentials. No production attack targets, secret uploads, private Frequency internals or unrestricted code execution. Do not publish sensitive evidence. Third-party status requires an actually independent operator, not a second machine under the same owner.
