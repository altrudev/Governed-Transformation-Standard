# Full sweep — enforceable minimum, not an assurance certificate

Run `python3 -m assurance.full_sweep --report /tmp/gts-sweep.json`. A nonzero exit indicates release blockers. This initial checker intentionally catches disconnected controls and missing service integration. Its static reference checks are **insufficient** for release approval: a named call may be unreachable, stubbed, monkey-patched, or invoked too late.

A production full DDC/Frequency sweep must also provide independently witnessed results for: requirements-to-execution traceability; reachable enforcement; alternate-path bypasses; actual separate-account execution; malicious inputs; mutation/control-removal testing; concurrent state transitions; crash/restart and replay; durable observer evidence; pinned key and signer custody; build and installed artifact equivalence; dependency provenance; protocol semantics; truthful claims and third-party reproducibility.

Statuses are PASS (observed proof), FAIL (demonstrated defect), BLOCKED (not executed), and NOT_APPLICABLE (justified scope exclusion). No pass-through green when mandatory evidence is absent.

Current run is a **subset** of the full standard. GTS must remain draft until the full set is implemented and executable evidence is available.
