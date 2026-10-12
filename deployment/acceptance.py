"""Fail-closed acceptance gate for installing the privileged observer."""
import json
from deployment.readiness import inspect

REQUIRED = (
    "actual_host_uid_socket_test",
    "dedicated_evaluator_uid_and_socket_access",
    "broker_delivery_path_and_anti_impersonation",
    "broker_challenge_issuance",
    "observer_key_custody",
    "durable_journal_recovery",
    "sandbox_cannot_impersonate_broker",
)
def evaluate(evidence=None):
    host = inspect()
    evidence = evidence or {}
    # Never trust booleans supplied by the tested adapter as verification.
    checks = {key: False for key in REQUIRED}
    return {
        "install_authorized": False,
        "host_readiness": host["checks"],
        "integration_checks": checks,
        "reason": "Required independently witnessed host tests and trusted broker challenge protocol not implemented",
        "requested_evidence_ignored": bool(evidence),
    }
if __name__ == "__main__":
    print(json.dumps(evaluate(),indent=2,sort_keys=True))
