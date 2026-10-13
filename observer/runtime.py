"""Restricted observer runtime: synthetic evidence only. No release authority.

Requires independently provisioned service UIDs, private journal/signing key,
and restricted socket directories. Does not establish external witnessing.
"""
import os
from pathlib import Path
import pwd
import grp
import signal
import stat
import threading

from observer.challenge_authority import ChallengeAuthority
from observer.durable_events import DurableEvents
from observer.issuance import IssuanceServer
from observer.key_custody import load_observer_signer
from observer.service import Receiver
from observer.signed_state import SignedDurableEvents
from deployment.socket_lifecycle import SingleInstanceLease, guarded_stale_cleanup, cleanup_own_socket

ISSUER_DIR = Path("/run/gts-issuer")
OBSERVER_DIR = Path("/run/gts-observer")
STATE_DIR = Path("/var/lib/gts-observer")


def _account_uid(name):
    return pwd.getpwnam(name).pw_uid


def _account_gid(name):
    return grp.getgrnam(name).gr_gid


def _require_dir(path, *, uid, gid, mode):
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("required protected runtime directory missing")
    st = path.lstat()
    if (st.st_uid != uid or st.st_gid != gid
            or stat.S_IMODE(st.st_mode) != mode):
        raise PermissionError("runtime directory custody mismatch")


def preflight(*, issuer_dir=ISSUER_DIR, observer_dir=OBSERVER_DIR,
              state_dir=STATE_DIR):
    user = _account_uid("gts-observer")
    broker_uid = _account_uid("gts-broker")
    evaluator_uid = _account_uid("gts-evaluator")
    evaluator_gid = _account_gid("gts-evaluator")
    broker_gid = _account_gid("gts-broker")
    observer_gid = _account_gid("gts-observer")
    if (len({user, broker_uid, evaluator_uid}) != 3
            or os.geteuid() != user
            or evaluator_gid not in os.getgroups()
            or broker_gid not in os.getgroups()):
        raise PermissionError("observer identity/groups do not meet trust boundary")
    _require_dir(issuer_dir, uid=user, gid=evaluator_gid, mode=0o710)
    _require_dir(observer_dir, uid=user, gid=broker_gid, mode=0o710)
    _require_dir(state_dir, uid=user, gid=observer_gid, mode=0o700)
    if (issuer_dir / "issue.sock").exists() or (observer_dir / "observer.sock").exists():
        raise PermissionError("existing sockets require independent cleanup review")
    return {"observer_uid": user, "broker_uid": broker_uid,
            "broker_gid": broker_gid, "evaluator_uid": evaluator_uid,
            "evaluator_gid": evaluator_gid}


def build(*, issuer_dir=ISSUER_DIR, observer_dir=OBSERVER_DIR, state_dir=STATE_DIR):
    identities = preflight(issuer_dir=issuer_dir, observer_dir=observer_dir,
                           state_dir=state_dir)
    # No implicit/generated signing identity; absence must block startup.
    signer = load_observer_signer(state_dir / "observer_ed25519.pem")
    journal = SignedDurableEvents(state_dir / "events.jsonl",
                                  state_dir / "events.checkpoint.json", signer)
    authority = ChallengeAuthority()
    receiver = Receiver(observer_dir / "observer.sock", None,
                        {identities["broker_uid"]},
                        authority=authority, durable_events=journal, strict=True)
    try:
        socket_path = observer_dir / "observer.sock"
        os.chown(socket_path, -1, identities["broker_gid"])
        os.chmod(socket_path, 0o660)
        issuer = IssuanceServer(issuer_dir / "issue.sock", authority,
                                identities["evaluator_uid"],
                                observer_uid=identities["observer_uid"],
                                evaluator_gid=identities["evaluator_gid"])
        return receiver, issuer
    except BaseException:
        receiver.server_close()
        raise


def main():
    lease = SingleInstanceLease(STATE_DIR)
    receiver = issuer = None
    try:
        identities = {"observer_uid": _account_uid("gts-observer"),
                      "evaluator_gid": _account_gid("gts-evaluator"),
                      "broker_gid": _account_gid("gts-broker")}
        guarded_stale_cleanup(ISSUER_DIR / "issue.sock",
                              expected_uid=identities["observer_uid"],
                              expected_gid=identities["evaluator_gid"])
        guarded_stale_cleanup(OBSERVER_DIR / "observer.sock",
                              expected_uid=identities["observer_uid"],
                              expected_gid=identities["broker_gid"])
        receiver, issuer = build()
        paths = [(OBSERVER_DIR / "observer.sock", identities["broker_gid"]),
                 (ISSUER_DIR / "issue.sock", identities["evaluator_gid"])]
        owned = [(p, gid, p.lstat().st_ino) for p, gid in paths]
        jobs = [threading.Thread(target=x.serve_forever, daemon=True)
                for x in (receiver, issuer)]
        for job in jobs:
            job.start()
        finished = threading.Event()
        def stop(_signum, _frame):
            finished.set()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        finished.wait()
    finally:
        for server in (receiver, issuer):
            if server is not None:
                server.shutdown()
                server.server_close()
        for p, gid, inode in locals().get("owned", []):
            cleanup_own_socket(p, expected_uid=os.geteuid(),
                               expected_gid=gid, original_inode=inode)
        lease.close()


if __name__ == "__main__":
    main()
