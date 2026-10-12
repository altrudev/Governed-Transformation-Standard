"""Read-only deployment readiness gate; no privileged changes."""
import json
import os
import pathlib
import pwd
import stat

def inspect():
    checks = {}
    try:
        observer = pwd.getpwnam("gts-observer")
        broker = pwd.getpwnam("gts-broker")
        evaluator = pwd.getpwnam("gts-evaluator")
        checks["distinct_accounts"] = len({observer.pw_uid, broker.pw_uid, evaluator.pw_uid}) == 3
    except KeyError:
        checks["distinct_accounts"] = False
        observer = None
    evidence = pathlib.Path("/var/lib/gts-observer")
    try:
        st = evidence.stat()
        checks["evidence_owner_only"] = bool(observer and st.st_uid == observer.pw_uid
            and stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700)
    except OSError:
        checks["evidence_owner_only"] = False
    app = pathlib.Path("/opt/gts-observer/observer/service.py")
    checks["installed_observer_code"] = app.is_file()
    credential = pathlib.Path("/etc/gts-observer/observer_challenge")
    # Never read, log or export the credential; its existence alone is not proof of quality.
    checks["credential_file_present"] = credential.is_file()
    checks["unit_installed"] = pathlib.Path("/etc/systemd/system/gts-observer.service").is_file()
    return {"ready_for_operator_deployment_review": all(checks.values()),
            "checks":checks, "credential_contents_accessed":False, "changes_made":False}

if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2, sort_keys=True))
