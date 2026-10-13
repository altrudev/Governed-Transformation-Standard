# GTS adversarial challenge review — internal sweep

## Demonstrated failure in legacy receiver
The existing `Receiver` checks one global long-lived bearer challenge and a broker UID. A client controlling that UID and secret can submit an *unissued* case ID, which the receiver will record. The characterization test in `tests/test_adversarial_static_challenge.py` reproduces this vulnerability. This receiver must not be deployed as an authorization authority.

## Hardened issuance model (unit tested, not integrated with live socket)
`observer.challenge_authority.ChallengeAuthority` is a verifier-local API that issues random 256-bit single-use bearer tokens tied to a case ID, permitted purpose, and monotonic expiry. It rejects guessed tokens, cross-case substitution, replay, expired tokens, unissued cases, scope changes, duplicate issuance and concurrent replay. Failed attempts do not consume a token. No untrusted socket endpoint may invoke issuance.

## Scope and remaining adversarial gaps
- Unit tests establish bounded *in-memory* case admission semantics, not external identity or side-effect truth.
- Broker compromise still permits actions within tokens legitimately assigned to that broker. Who decides case issuance and delivers the token securely is unresolved.
- No durable replay ledger or crash recovery; restarting could lose challenge state.
- No real separate-host-UID observer/broker socket assessment.
- No key custody, independent challenge signer, journal durability or raw signed outside observation.
- No malicious kernel, sandbox escape or denial-of-service resistance claim.

The production acceptance gate remains blocked. Do not install the legacy service because these unit tests pass.
