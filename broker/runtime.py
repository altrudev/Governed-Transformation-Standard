"""Restricted GTS synthetic delivery broker. No authority issuance/release."""
import grp
import os
from pathlib import Path
import pwd
import signal
import stat
import threading

from broker.delivery import DeliveryServer
from broker.durable_attempts import DurableAttempts
from deployment.socket_lifecycle import SingleInstanceLease, guarded_stale_cleanup, cleanup_own_socket

DELIVERY_DIR = Path("/run/gts-broker-delivery")
STATE_DIR = Path("/var/lib/gts-broker")
OBSERVER_SOCKET = "/run/gts-observer/observer.sock"


def preflight(*, delivery_dir=DELIVERY_DIR, state_dir=STATE_DIR):
    broker_uid = pwd.getpwnam("gts-broker").pw_uid
    evaluator_uid = pwd.getpwnam("gts-evaluator").pw_uid
    observer_uid = pwd.getpwnam("gts-observer").pw_uid
    evaluator_gid = grp.getgrnam("gts-evaluator").gr_gid
    broker_gid = grp.getgrnam("gts-broker").gr_gid
    if (len({broker_uid, evaluator_uid, observer_uid}) != 3
            or os.geteuid() != broker_uid
            or evaluator_gid not in os.getgroups()):
        raise PermissionError("broker identity violates trust boundary")
    for path, gid, mode in ((delivery_dir, evaluator_gid, 0o710),
                            (state_dir, broker_gid, 0o700)):
        if path.is_symlink() or not path.is_dir():
            raise PermissionError("broker protected directory unavailable")
        meta = path.lstat()
        if (meta.st_uid != broker_uid or meta.st_gid != gid
                or stat.S_IMODE(meta.st_mode) != mode):
            raise PermissionError("broker directory custody mismatch")
    if (delivery_dir / "deliver.sock").exists():
        raise PermissionError("existing delivery socket requires review")
    return {"broker_uid": broker_uid, "evaluator_uid": evaluator_uid,
            "evaluator_gid": evaluator_gid}


def build(*, delivery_dir=DELIVERY_DIR, state_dir=STATE_DIR,
          observer_socket=OBSERVER_SOCKET):
    identities = preflight(delivery_dir=delivery_dir, state_dir=state_dir)
    state = DurableAttempts(state_dir / "attempts.db")
    try:
        server = DeliveryServer(delivery_dir / "deliver.sock", observer_socket,
                                evaluator_uid=identities["evaluator_uid"],
                                broker_uid=identities["broker_uid"],
                                evaluator_gid=identities["evaluator_gid"],
                                durable_attempts=state)
        return server, state
    except BaseException:
        state.close()
        raise


def main():
    lease = SingleInstanceLease(STATE_DIR)
    guarded_stale_cleanup(DELIVERY_DIR / "deliver.sock",
                          expected_uid=pwd.getpwnam("gts-broker").pw_uid,
                          expected_gid=grp.getgrnam("gts-evaluator").gr_gid)
    server, state = build()
    original_inode = (DELIVERY_DIR / "deliver.sock").lstat().st_ino
    stopped = threading.Event()
    def stop(_signum, _frame):
        stopped.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        stopped.wait()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        cleanup_own_socket(DELIVERY_DIR / "deliver.sock",
                           expected_uid=os.geteuid(),
                           expected_gid=grp.getgrnam("gts-evaluator").gr_gid,
                           original_inode=original_inode)
        state.close()
        lease.close()


if __name__ == "__main__":
    main()
