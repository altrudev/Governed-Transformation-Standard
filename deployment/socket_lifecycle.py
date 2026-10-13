"""Service-owned AF_UNIX path cleanup guarded by a private singleton lease.

Prevents routine crash leftovers from causing restart storms. Never removes a
symlink, foreign-owned socket, non-socket path, or connected live server.
A protected service state directory and independently installed systemd
sandbox are prerequisites. This is operational availability, not authority.
"""
import errno
import fcntl
import os
from pathlib import Path
import socket
import stat


class SingleInstanceLease:
    def __init__(self, state_dir, name="runtime.lock"):
        self.path = Path(state_dir) / name
        parent = self.path.parent
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise PermissionError("runtime lock directory not private to service")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise PermissionError("insecure service lease")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def guarded_stale_cleanup(path, *, expected_uid, expected_gid):
    """Return True only when an inaccessible dead socket was removed."""
    p = Path(path)
    try:
        info = p.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != expected_uid
        or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) != 0o660):
        raise PermissionError("socket custody mismatch; refusing unlink")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.4)
            probe.connect(str(p))
    except ConnectionRefusedError:
        # The lease must be held by the caller. Recheck inode before unlink.
        current = p.lstat()
        if (current.st_dev != info.st_dev or current.st_ino != info.st_ino):
            raise PermissionError("socket changed while checking stale state")
        p.unlink()
        return True
    except OSError as error:
        raise PermissionError("socket state cannot be safely proven stale") from error
    raise PermissionError("another active process owns the socket")


def cleanup_own_socket(path, *, expected_uid, expected_gid, original_inode):
    p = Path(path)
    try:
        info = p.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != expected_uid
        or info.st_gid != expected_gid or info.st_ino != original_inode):
        raise PermissionError("refusing to unlink replaced service socket")
    p.unlink()
