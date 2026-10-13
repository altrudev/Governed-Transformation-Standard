# Mandatory full sweep — system-wide evidence closure

Status: mandatory fail-closed **release gate** in the GTS `assurance.full_sweep`
tool. The shared Frequency doctrine lives in
`Frequency/docs/FREQ-MANDATORY-FULL-SWEEP-RULE-2026-10-13.md`.

## Why this rule exists

A test can pass while its production function is unwired, its privileged
adapter is disabled, its deployment is stale, or its observer cannot see the
effect. Repeating the same unit test or asking the same component to attest
its own success does not close those gaps. The previous GTS rule tested local
code and five host witnesses but did not require a complete system graph.

**A full sweep is NOT complete until every in-scope dependency and actual
effect boundary has evidence at the intended installed/runtime revision.**
Discovery of an omitted dependency automatically invalidates any previous
claim to scope completeness and reopens its dependent gates.

## Required evidence domains

The new mandatory system-wide rules are:

1. `scope_inventory` — explicitly declared in-scope nodes, assets, hosts,
   versions, deployment surfaces and exclusions; independent review of scope.
2. `dependency_graph_and_adapter_closure` — every required runtime edge,
   third-party or vendor adapter, conditional entrypoint and fallback path.
3. `source_build_installed_equivalence` — source/build identifiers match
   actual installed version and process/runtime revision, not just a branch.
4. `authorization_and_credential_custody` — caller, authority point, exact
   scope, credential custody, revalidation, expiry and revocation.
5. `actual_runtime_wiring` — exercised real process/API/socket/job route;
   simulated/mock/registered interfaces are never promoted as wired live.
6. `independent_effect_observation` — observe concrete effects beyond dispatch
   and independently reconstruct them from separate evidence.
7. `adversarial_mutation_and_bypass_denials` — remove controls deliberately,
   probe equivalent alternate paths and verify that acceptance fails.
8. `restart_recovery_and_rollback` — crashes, ambiguous results, idempotency,
   lost connectivity, power/storage recovery and operator rollback.
9. `provenance_retention_and_data_boundary` — immutable evidence pointers,
   privacy/export limits, retention, license and protected data boundaries.
10. `independent_evaluator_and_trust_root` — protected independent verifier
    identity, pinned keys/implementation, witnesses and assurance ceiling.
11. `operator_approved_release_and_remedy_reentry` — separate approval,
    staged migration, qualified rollback, repair/reentry and exact release gate.

All 11 are mandatory. A nonapplicable feature must be explicitly excluded
from the **independently verified scope inventory**, not silently skipped.
A missing/unknown/blocked gate cannot be counted as a pass. If the system
changes, all dependent evidence and affected edge proofs are reopened.

## Evidence protocol

Provide the existing GTS five host-witness files in `--witness-dir`,
a separately controlled raw 32-byte Ed25519 trust anchor with
`--trust-anchor`, and the 11 new witnessed domains under
`--witness-dir/system/`.

The dependency graph evidence file is an object with a `graph` and
`attestation`. The graph has a pinned root `revision`, nonempty `nodes`
and nonempty `edges`. Each node binds its source/deployed commit and
authority domain; each edge declares caller, callee, authorization point,
actual effect point and observer point. Dangling edges, duplicate identities,
empty graphs, missing fields and mismatched revisions fail closed.

Every domain has one signed GTS witness envelope and exact raw evidence
bytes. The evidence binds the same source/deployed revision, graph scope
digest, live environment, run identity, distinct producer/verifier identities,
and **every edge ID**. Each domain has content-addressed JSON artifacts
for each graph edge and **the actual raw bytes** of positive, denied and
observed-effect receipts. Hash-only claims without their corresponding
raw evidence bytes are BLOCKED. Host witness signatures are verified using
the independently administered public trust root, not a key supplied by
the tested workload.

For a production `full_sweep` call, the public trust anchor must be an
absolute, regular 32-byte file whose file and ancestor directories are
not writable/owned by the evaluated account. This is only a necessary
custody check: even a correctly signed witness statement is not guaranteed
factually independent or true. External assessor admission, hardware trust,
scope verification and process ownership still require evidence beyond
the gate's local filesystem.

### Command

```bash
python3 -m assurance.full_sweep \
  --witness-dir /approved/external-evidence-set \
  --trust-anchor /independently-owned/evaluator-public-key.raw \
  --report /protected/evidence/gts-full-sweep.json
```

Exit 0: all defined gates verified under the configured evidence/identity
contracts and exact commit. Exit 2: HOLD/BLOCKED. No witness files or trust
root = fail closed, even with 100% local tests.

## Reporting and decision rules

- `PASS` requires an actually exercised and corroborated boundary.
- `FAIL` means exercised, contradicted or violated.
- `BLOCKED` means cannot execute or lack authority/infrastructure/witness.
- `NOT_TESTED` means no attempt; never silently convert to PASS.
- `IN_DOUBT` means an ambiguous effect; never auto-retry.
- `SHIPPED / ADAPTER / NONE` describe *implementation existence*, not
  acceptance or release status. A draft PR is not deployed or shipped.

Reports include required system evidence, dependency closure result, missing
domain identifiers and the old required host witnesses. Unit test PASS never
overrides any BLOCKED release requirement. Source review, staging and rootless
synthetic IPC do not qualify live independent authority.

## Limitations and independent duty

The gate cannot prove an inventory truly contains every possible component;
the independent scope assessor must justify completeness against real control
plane, services, dependencies and deployment targets. Signed in-band
descriptions or mock tests are not proof of a live effect. A successful
defined release gate never establishes absence of unknown vulnerabilities
or future authorization. Independently governed production cutover remains
necessary.
