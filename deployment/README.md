# Dedicated-host-principal observer: reviewed deployment blueprint

This is a proposed service unit, **not a deployed service**. It presupposes a separately created locked system account `gts-observer`, a reviewed observer implementation at `/opt/gts-observer`, proper socket access via a narrowly controlled broker and no shared credentials with the test subject.

**Not runnable yet:** `observer.service` does not exist. The supplied unit is an auditable profile only and MUST NOT be enabled. It intentionally exposes neither a privileged socket nor any signing key. The deployment must be completed and tested before use.

A privileged administrator must separately review and provision an observer OS principal with no login, an isolated working directory, restrict readable keys to that principal, and record file ownership. Do not mount host `/var/lib/gts-observer` into an untrusted test sandbox. The observer process must not accept commands that cause arbitrary filesystem writes or sign caller-controlled arbitrary data. Access to evidence should be through a narrowly scoped broker with peer credentials, a challenge protocol and audit records.

Deployment gates:
1. Implement authenticated observer executable and a bounded protocol, first.
2. Verify the systemd sandbox directives with `systemd-analyze security` and a local non-production host.
3. Provision the service account and key using explicit operator approval and a rollback plan.
4. Test from the untrusted adapter identity: key read denied; observer journal mutation denied; unrelated socket access denied; permitted effect receipt still observable.
5. Add key registration/revocation and external observer-held signatures, plus restart/crash tests.
6. Independently reproduce results before claiming external verification.

Rollback: disable/stop the newly introduced unit, restore the prior service configuration, and leave evidence journals retained for review. Account deletion or key destruction is a separate approval-controlled action.

This blueprint is not an authorization to modify the host's users or run an unfinished service.
