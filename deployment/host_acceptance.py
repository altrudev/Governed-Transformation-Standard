"""Operator-run real-UID synthetic GTS acceptance; never authorizes release.

Requires privileged host access, root-pinned /opt/gts, three service accounts
and active broker/observer systemd units. Exercises real Unix IPC, wrong UID
denial, durable broker reservation, and observer-signed local journal state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import secrets
import socket
import sqlite3
import stat
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from observer.signed_state import verify_checkpoint
from observer.durable_events import canonical

ROOT = Path("/opt/gts")


def _call(*args, account=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"}
    argv = ["/usr/bin/python3", "-m", *args]
    if account is not None:
        argv = ["/usr/sbin/runuser", "--user", account, "--", *argv]
    return subprocess.run(argv, capture_output=True, text=True, timeout=12,
                          cwd=ROOT, env=env)


def _service(name, property):
    result = subprocess.run(["/usr/bin/systemctl", "show", name, "-p", property,
                             "--no-pager"], capture_output=True, text=True,
                            timeout=10, check=True)
    return result.stdout.strip().partition("=")[2]


def _socket(path, user, group):
    st = Path(path).lstat()
    return (stat.S_ISSOCK(st.st_mode) and
            st.st_uid == pwd.getpwnam(user).pw_uid and
            st.st_gid == grp.getgrnam(group).gr_gid and
            stat.S_IMODE(st.st_mode) == 0o660)


def run():
    if os.geteuid() != 0 or ROOT.is_symlink() or not ROOT.is_dir():
        raise PermissionError("root-installed pinned runtime required")
    installed = json.loads((ROOT / "SOURCE-MANIFEST.json").read_text())
    if installed.get("qualification") != "UNSIGNED_SOURCE_INTAKE":
        raise PermissionError("unexpected source qualification schema")
    from deployment.bootstrap_host import verify_installed_source
    verify_installed_source()
    accounts = [pwd.getpwnam(n).pw_uid for n in
                ("gts-observer", "gts-broker", "gts-evaluator")]
    if len(set(accounts)) != 3:
        raise PermissionError("service identities are not separate")
    for n in ("gts-observer", "gts-broker"):
        if _service(n + ".service", "ActiveState") != "active" or (
                _service(n + ".service", "User") != n):
            raise RuntimeError("service not active under expected identity")
    sockets = {
        "issuer": _socket("/run/gts-issuer/issue.sock", "gts-observer", "gts-evaluator"),
        "delivery": _socket("/run/gts-broker-delivery/deliver.sock", "gts-broker", "gts-evaluator"),
        "observer": _socket("/run/gts-observer/observer.sock", "gts-observer", "gts-broker")
    }
    if not all(sockets.values()):
        raise PermissionError("runtime socket ownership not independently verified")

    case = "host-" + secrets.token_hex(12)
    ok = _call("evaluator.synthetic_acceptance", "--case-id", case,
               account="gts-evaluator")
    if ok.returncode != 0:
        raise RuntimeError("actual UID evaluator delivery failed")
    report = json.loads(ok.stdout)
    if (report.get("case_id") != case or
            report.get("delivery_acknowledged") is not True or
            report.get("release_authority") != "NONE"):
        raise RuntimeError("synthetic evaluator receipt invalid")
    duplicate = _call("evaluator.synthetic_acceptance", "--case-id", case,
                      account="gts-evaluator")
    if duplicate.returncode == 0:
        raise RuntimeError("duplicate case was admitted")

    # A broker-identity request must fail at the issuance boundary.
    # Invoke an actual broker-UID process against evaluator-only issuance.
    attacker = subprocess.run([
        "/usr/sbin/runuser", "--user", "gts-broker", "--",
        "/usr/bin/python3", "-c",
        "from observer.issuance import request_challenge;"
        "request_challenge('/run/gts-issuer/issue.sock','denied-uid')"
    ], cwd=ROOT, env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent"},
        text=True, capture_output=True, timeout=8)
    if attacker.returncode == 0:
        raise RuntimeError("broker impersonated evaluator at issuer")

    database = Path("/var/lib/gts-broker/attempts.db")
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2) as db:
        row = db.execute("SELECT status FROM reservations WHERE case_id=?",
                         (case,)).fetchone()
    if row != ("ACKNOWLEDGED",):
        raise RuntimeError("broker acknowledged effect without durable reservation")

    event_file = Path("/var/lib/gts-observer/events.jsonl")
    data = event_file.read_bytes().splitlines()
    matching = [json.loads(line) for line in data if
                json.loads(line).get("case_id") == case]
    if len(matching) != 1:
        raise RuntimeError("observer did not record synthetic event exactly once")
    previous = "0"*64
    for index, line in enumerate(data):
        e = json.loads(line)
        block = {k:e[k] for k in ("index","previous","case_id","operation")}
        if (e["index"] != index or e["previous"] != previous or
                hashlib.sha256(canonical(block)).hexdigest() != e["sha256"]):
            raise RuntimeError("observer journal hash chain invalid")
        previous = e["sha256"]
    state = {"entry_count":len(data), "last_sha256":previous}
    signature = json.loads(Path("/var/lib/gts-observer/events.checkpoint.json").read_bytes())
    public = Path("/var/lib/gts-observer/observer_ed25519.pub").read_bytes()
    if len(public) != 32 or not verify_checkpoint(
            signature, Ed25519PublicKey.from_public_bytes(public), state):
        raise RuntimeError("observer signed checkpoint not valid under pinned local key")

    return {"schema":"gts.host-synthetic-acceptance.v1",
            "git_commit":installed["source_revision"],
            "case_id":case, "actual_evaluator_uid":accounts[2],
            "three_distinct_linux_uids":True,
            "socket_custody":sockets,
            "duplicate_case_denied":True,
            "broker_as_evaluator_denied":True,
            "broker_durable_reservation":"ACKNOWLEDGED",
            "observer_event_recorded_once":True,
            "observer_local_signature_valid":True,
            "independent_external_effect_proven":False,
            "independent_witness_enrolled":False,
            "release_authorized":False}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    args = ap.parse_args()
    if not args.run:
        print("DRY RUN. Use --run under independently authorized host administrator.")
        return
    print(json.dumps(run(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
