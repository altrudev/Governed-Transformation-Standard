# GTS protected cross-account acceptance — operator runbook

Status: development candidate, NOT independently qualified or deployed.
These are explicit steps for an authorized administrator to review; no
AI-controlled application or broker may carry out privilege provisioning.

## Identity and trust domains

- gts-observer: locked account; owns signing key and fsync-backed journal.
- gts-broker: separate locked account; durable IN_DOUBT reservation and delivery.
- gts-evaluator: required third locked UID; currently absent from Prometheus.
- Independent assessor: controls evaluation/public-key trust and release decision.
- External witness: retains separately anchored, revision-bound checkpoints.

## Required sequence

1. Independently review and pin the source revision and provisioner digest.
   Install reviewed, root-owned, non-writable code under /opt/gts.
2. Only after independent administrator approval, execute --apply from the
   reviewed /opt/gts/deployment/provision-evaluator.sh file. Do not execute
   its development-checkout copy with root privileges. Verify distinct UIDs.
3. Provision deployment/gts-sockets.tmpfiles.conf: owner:group and modes
   must match observer:evaluator 0710, observer:broker 0710 and
   broker:evaluator 0710. Protected state directories are owner-only 0700.
4. Under independent credential custody, provision an observer-owned Ed25519
   private key at /var/lib/gts-observer/observer_ed25519.pem mode 0600.
   Separately enroll the raw public key with the independent evaluator.
   Never export private key bytes to chat or source.
5. Review and stage deployment/gts-observer.service and gts-broker.service.
   Verify actual service UIDs, protected source read-only access, socket
   groups, syscalls, network denial and credential access. Do not start
   two observer units simultaneously. Installation requires approval.
6. As the actual gts-evaluator UID, run the synthetic-only client:
   python3 -m evaluator.synthetic_acceptance --case-id CASE_ID
   Confirm exact peer credentials, one broker reservation, one signed
   checkpoint and no duplicate. This is NOT proof of an external effect.
7. As unrelated UIDs, broker and observer, attempt unauthorized issuance
   and delivery; all must fail. Test stale sockets, symlinks, permissions,
   wrong key, corrupted checkpoint, repeated case, crash/ambiguous outcomes,
   and restricted file/network access. Preserve original host test evidence.
8. Test restart after successful fsync and unresolved IN_DOUBT outcomes.
   Never delete broker state to force a retry. Authorize reconciliation
   through a separate human-controlled decision and actual observation.
9. Independently anchor the journal checkpoint and exact source SHA on
   a separately administered witness, using independently pinned keys.
   The currently available VPS has not qualified this trust requirement.
10. Perform actual physical power-cut validation if physical durability
    is claimed; a software crash simulator is insufficient.
11. Only an independent assessor with approved authority may sign a
    complete report and admit a release through EDRG.

## Interpretation

Observer-signed journal state is not external effect observation.
A Linux UID is not itself independent governance authority.
A hash chain under single-host control is not rollback-resistant without
externally protected checkpoint history. Test signatures are not production
signing authority. No arbitrary shell, financial payment, or browser file
operations are authorized through these synthetic-only interfaces.

All account, signing, observer and witness gates currently HOLD.
Preserve separate VPS administrator recovery access during later DSR migration.
