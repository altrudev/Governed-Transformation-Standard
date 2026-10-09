# Signed synthetic raw-journal fixture

The internal test format `gts.synthetic-journal.v0.1` binds an ordered list of raw synthetic events using sequence numbers, previous-entry SHA-256 links, entry count and chain root. An Ed25519 signature covers the journal report, subject digest and evaluator challenge. Verification requires a public key supplied out of band. Tests detect reordered, deleted, modified and independently re-signed journal records.

This demonstrates integrity **only for a report signed by the holder of the pinned key**. It does not prove events actually happened, observer independence, durable append-only storage, isolation of the key from the tested process, or completeness of effects recorded outside the journal. The existing sorted-JSON encoding is not RFC 8785. Production custody, independent issuance and key rotation remain open.
