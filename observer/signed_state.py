"""Observer-owned Ed25519 checkpoints of fsync-backed synthetic event journal.

These are signed CLAIMS OF A LOCAL JOURNAL, not independent effect evidence.
The external verifier must pre-enroll the public key and independently anchor
monotonic checkpoints. A crash between journal and checkpoint blocks startup.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
from cryptography.exceptions import InvalidSignature
from observer.durable_events import DurableEvents, canonical

SCHEMA = "gts.synthetic-signed-journal-checkpoint.v1"


def _strict_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise PermissionError("checkpoint not a trusted regular file")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 8192):
        raise PermissionError("insecure signed checkpoint custody")
    return path.read_bytes()


def verify_checkpoint(packet, public_key, expected_state):
    """Local consistency, NOT independent signer enrollment/rollback protection."""
    try:
        if (not isinstance(packet, dict) or set(packet) != {"statement", "signature"}
                or not isinstance(packet["statement"], dict)
                or set(packet["statement"]) != {"schema", "entry_count", "last_sha256"}
                or packet["statement"]["schema"] != SCHEMA
                or packet["statement"]["entry_count"] != expected_state["entry_count"]
                or packet["statement"]["last_sha256"] != expected_state["last_sha256"]):
            return False
        raw = canonical(packet["statement"])
        signature = base64.b64decode(packet["signature"], validate=True)
        if len(signature) != 64:
            return False
        public_key.verify(signature, raw)
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature, UnicodeError):
        return False


class SignedDurableEvents:
    def __init__(self, journal_path, checkpoint_path, signer):
        self.checkpoint_path = Path(checkpoint_path)
        if Path(journal_path).parent != self.checkpoint_path.parent:
            raise PermissionError("signed journal and checkpoint must share protected custody")
        parent = self.checkpoint_path.parent
        directory = parent.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
                or stat.S_IMODE(directory.st_mode) != 0o700
                or self.checkpoint_path.is_symlink()):
            raise PermissionError("checkpoint directory must be observer-owned and private")
        self.journal = DurableEvents(journal_path)
        self.signer = signer
        self._failed = False
        if self.checkpoint_path.exists():
            raw = _strict_file(self.checkpoint_path)
            packet = json.loads(raw)
            state = self.journal.checkpoint()
            if not verify_checkpoint(packet, self.signer.public_key(), state):
                raise ValueError("journal and protected signature checkpoint diverged")
        elif self.journal.count:
            raise ValueError("non-empty journal has no signed checkpoint; reconciliation required")
        else:
            self._publish()

    def _publish(self):
        state = self.journal.checkpoint()
        statement = {"schema": SCHEMA, "entry_count": state["entry_count"],
                     "last_sha256": state["last_sha256"]}
        packet = {"statement": statement,
                  "signature": base64.b64encode(self.signer.sign(canonical(statement))).decode("ascii")}
        payload = canonical(packet) + b"\n"
        # Never use a caller-provided temporary filename or external location.
        tmp_name = self.checkpoint_path.with_name(
            "." + self.checkpoint_path.name + "." + os.urandom(16).hex() + ".pending")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp_name, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if self.checkpoint_path.exists():
                _strict_file(self.checkpoint_path)
            os.replace(tmp_name, self.checkpoint_path)
            dirfd = os.open(self.checkpoint_path.parent,
                            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if tmp_name.exists():
                tmp_name.unlink()

    def append(self, case_id, operation):
        if self._failed:
            raise RuntimeError("signed journal requires independent reconciliation")
        # Lock serializes event append and checkpoint creation. An observer ACK
        # must not be sent until both data and the signed checkpoint are fsynced.
        with self.journal.lock:
            appended = False
            try:
                digest = self.journal.append(case_id, operation)
                appended = True
                self._publish()
                return digest
            except ValueError:
                if appended:
                    self._failed = True
                raise
            except BaseException:
                self._failed = True
                raise

    @property
    def count(self):
        return self.journal.count
