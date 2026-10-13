"""Owner-only Ed25519 key loader; no generation, exporting or signing endpoint."""
import os
import pathlib
import stat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def load_observer_signer(path):
    location = pathlib.Path(path)
    fd = os.open(location, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
            or meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o600
            or meta.st_size > 4096):
            raise PermissionError("insecure signer custody")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(4097)
        if len(data) > 4096:
            raise ValueError("invalid signer size")
        signer = load_pem_private_key(data, password=None)
        if not isinstance(signer, Ed25519PrivateKey):
            raise ValueError("unsupported signer type")
        return signer
    finally:
        os.close(fd)
