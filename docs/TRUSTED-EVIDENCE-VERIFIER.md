# External trust-anchor verification prototype

`observer.trusted_evidence.verify(packet, expected_public_key, expected_subject_digest, expected_challenge)` rejects evidence unless its Ed25519 signature verifies against a **32-byte public key supplied separately by the evaluator**. It also binds the result to an expected subject SHA-256 and evaluator challenge. The public key embedded in a packet is explicitly not trusted. The verifier fails closed when no public trust anchor is supplied.

Negative tests cover a self-signed replacement, key substitution and re-signing, modified observation, wrong subject, wrong challenge and absent trust anchor.

**Trust limitations:** the tests provision the evaluator key inside the test harness for repeatability. This does not establish real external observer custody or third-party independence. Production deployment requires out-of-band key registration, key rotation/revocation, an independent signing principal that genuinely controls observations, cryptographically bound raw journal events, and a standardized signed JSON canonicalization contract (the existing sorted JSON encoding is not RFC 8785). The separate-process and Bubblewrap fixture remains a scoped synthetic test, not production verification.
