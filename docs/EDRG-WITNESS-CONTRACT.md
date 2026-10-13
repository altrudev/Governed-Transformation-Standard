# EDRG host-witness evidence — fail-closed protocol

The release gate now accepts optional `--witness-dir` and `--trust-anchor` arguments. Neither is implicitly discovered from the tested application. The trust anchor is a raw, 32-byte Ed25519 public key provisioned by the independent assessor out-of-band. It must not be generated or selected by the tested system.

Each of the five mandatory host requirements has two files named `<requirement>.json` and `<requirement>.evidence`. The JSON contains a statement and an Ed25519 signature over canonical JSON (sorted keys, compact encoding; this implementation does **not** assert RFC 8785 conformance). The statement binds exact git commit SHA, requirement ID, PASS outcome, UTC observation timestamp, assessor/witness ID, environment and SHA-256 of original evidence bytes. Signatures, age, key, digest and exact requirement are verified. Invalid or missing evidence stays BLOCKED.

A valid signature authenticates an assessor's statement, **not** whether that assessor is independent or whether the test was competently conducted. Consequently the release consumer must provision and approve the assessor's identity, witness methods and trust anchor separately. Never give the assessed system the assessor private key. Never upload real private keys to the repository.

Example:
```
sh scripts/run-with-disk-tmp.sh python3 -m assurance.full_sweep \
  --witness-dir /path/to/assessor-evidence \
  --trust-anchor /path/to/out-of-band-pinned-ed25519-public.key \
  --report "$HOME/.local/state/altru/reports/gts-release-evidence.json"
```

This protocol does not yet prove independent cross-account test execution, external checkpointing, rollback resistance, installed artifact equivalence, or a completed penetration test. The observer service remains disabled and draft PR #3 remains blocked.
