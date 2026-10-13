"""Explicit one-time GTS synthetic runtime bootstrap for a trusted operator.

Never executed by an evaluator, broker, agent or Conduit. Root-only actions
require a reviewed, immutable /opt/gts installation and affirmative --apply.
No live authority or release conformance is asserted by this installer.
"""
import argparse
import hashlib
import os
from pathlib import Path
import pwd
import grp
import shutil
import stat
import subprocess
import sys

INSTALL = Path("/opt/gts")
UNITS = ("gts-observer.service", "gts-broker.service")
TMPFILES = "gts-sockets.tmpfiles.conf"


def _call(*argv):
    subprocess.run(list(argv), check=True, timeout=35)


def protected(path, expected_uid=0):
    """Check all path ancestors including the file, without following symlinks."""
    item = Path(path)
    for child in (item, *item.parents):
        meta = child.lstat()
        if (stat.S_ISLNK(meta.st_mode) or meta.st_uid != expected_uid
                or stat.S_IMODE(meta.st_mode) & 0o022):
            raise PermissionError(f"untrusted install path: {child}")


def verify_installed_source():
    manifest_path = INSTALL / "SOURCE-MANIFEST.json"
    protected(manifest_path)
    import json
    manifest = json.loads(manifest_path.read_text())
    revision = manifest.get("source_revision")
    if (manifest.get("schema") != "gts.operator-source-bundle.v1"
            or not isinstance(revision, str) or len(revision) != 40
            or any(c not in "0123456789abcdef" for c in revision)):
        raise PermissionError("missing or invalid reviewed source revision")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > 256:
        raise PermissionError("invalid runtime file manifest")
    actual = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise PermissionError("invalid source manifest entry")
        relative = entry["path"]
        if (not isinstance(relative, str) or relative.startswith("/")
                or ".." in Path(relative).parts or relative in actual):
            raise PermissionError("source path not allowed or duplicated")
        path = INSTALL / relative
        protected(path)
        contents = path.read_bytes()
        if (len(contents) != entry["size"] or
                hashlib.sha256(contents).hexdigest() != entry["sha256"]):
            raise PermissionError("installed source digest differs from reviewed bundle")
        actual.add(relative)
    for package in ("observer", "broker", "evaluator", "deployment"):
        for module in (INSTALL / package).glob("*.py"):
            if str(module.relative_to(INSTALL)) not in actual:
                raise PermissionError("unmanifested Python module in runtime")
    return revision


def _require_root_copy():
    if os.geteuid() != 0:
        raise PermissionError("trusted administrator is required")
    if Path(__file__).resolve() != INSTALL / "deployment/bootstrap_host.py":
        raise PermissionError("bootstrap can only execute from protected installation")
    protected(INSTALL / "deployment/bootstrap_host.py")
    # Do not trust a writable imported module, even when installer is protected.
    for part in ("observer", "broker", "evaluator", "deployment"):
        directory = INSTALL / part
        protected(directory)
        for file in directory.glob("*.py"):
            protected(file)
    for name in UNITS + (TMPFILES,):
        protected(INSTALL / "deployment" / name)
    verify_installed_source()


def _current_accounts():
    a = {name: pwd.getpwnam(name) for name in ("gts-observer", "gts-broker")}
    if a["gts-observer"].pw_uid == a["gts-broker"].pw_uid:
        raise PermissionError("observer and broker identities must be distinct")
    for name in a:
        if not a[name].pw_shell.endswith("/nologin"):
            raise PermissionError(f"{name} is not a locked service account")
    return a


def _get_or_create_evaluator():
    try:
        account = pwd.getpwnam("gts-evaluator")
    except KeyError:
        _call("/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
              "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
              "gts-evaluator")
        account = pwd.getpwnam("gts-evaluator")
    if (not account.pw_shell.endswith("/nologin")
            or any(account.pw_uid == pwd.getpwnam(n).pw_uid
                   for n in ("gts-observer", "gts-broker"))):
        raise PermissionError("evaluator account is unsafe or not distinct")
    return account


def _private_state(path, owner, group):
    path = Path(path)
    if not path.exists():
        os.mkdir(path, mode=0o700)
        os.chown(path, owner, group)
    meta = path.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != owner
            or meta.st_gid != group or stat.S_IMODE(meta.st_mode) != 0o700):
        raise PermissionError(f"unsafe existing state directory: {path}")


def _write_root_file(source, target):
    target = Path(target)
    if target.exists() or target.is_symlink():
        meta = target.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0
                or meta.st_gid != 0 or stat.S_IMODE(meta.st_mode) != 0o644
                or target.read_bytes() != Path(source).read_bytes()):
            raise PermissionError(f"unreviewed existing system file: {target}")
        return
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    content = Path(source).read_bytes()
    fd = os.open(target, flags, 0o644)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def _provision_signer(observer):
    """Operator host custodian creates signer only if absent; never rotate here."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    keyfile = Path("/var/lib/gts-observer/observer_ed25519.pem")
    public = Path("/var/lib/gts-observer/observer_ed25519.pub")
    if keyfile.exists() or keyfile.is_symlink():
        raise PermissionError("key already exists; human-led custody review required")
    if public.exists() or public.is_symlink():
        raise PermissionError("public key already exists; refusing ambiguous enrollment")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    raw_public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for path, content in ((keyfile, pem), (public, raw_public)):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchown(fd, observer.pw_uid, observer.pw_gid)
            with os.fdopen(fd, "wb") as dest:
                dest.write(content)
                dest.flush()
                os.fsync(dest.fileno())
        except BaseException:
            raise
    fd = os.open(keyfile.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return hashlib.sha256(raw_public).hexdigest()


def prepare(*, create_key=False):
    _require_root_copy()
    a = _current_accounts()
    evaluator = _get_or_create_evaluator()
    _private_state("/var/lib/gts-observer",
                   a["gts-observer"].pw_uid, a["gts-observer"].pw_gid)
    _private_state("/var/lib/gts-broker",
                   a["gts-broker"].pw_uid, a["gts-broker"].pw_gid)

    for name in UNITS:
        _write_root_file(INSTALL / "deployment" / name,
                         Path("/etc/systemd/system") / name)
    config = Path("/etc/tmpfiles.d/gts-sockets.conf")
    _write_root_file(INSTALL / "deployment" / TMPFILES, config)
    _call("/usr/bin/systemd-tmpfiles", "--create", str(config))
    _call("/usr/bin/systemctl", "daemon-reload")
    fingerprint = None
    if create_key:
        fingerprint = _provision_signer(a["gts-observer"])
    return {"evaluator_uid": evaluator.pw_uid,
            "observer_uid": a["gts-observer"].pw_uid,
            "broker_uid": a["gts-broker"].pw_uid,
            "key_fingerprint_sha256": fingerprint,
            "services_started": False,
            "release_authorized": False}


def start_synthetic():
    """Run under explicit operator action; do not enable at boot or qualify."""
    _require_root_copy()
    # Readiness of signer/directory/access must be established first.
    for name in UNITS:
        _call("/usr/bin/systemctl", "start", name)
    return {"services_started": True, "services_enabled": False,
            "independent_observation": False, "release_authorized": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true",
                        help="prepare identities, state and service units; no start")
    parser.add_argument("--create-key", action="store_true",
                        help="explicit one-time host-operator signer generation")
    parser.add_argument("--start-synthetic", action="store_true",
                        help="start synthetic services, not enable or release")
    args = parser.parse_args()
    if args.create_key and not args.apply:
        raise ValueError("--create-key requires explicit --apply")
    if not args.apply and not args.start_synthetic:
        print("DRY RUN ONLY. Requires reviewed root-owned /opt/gts. "
              "Use --apply --create-key after operator review.")
        return
    if args.start_synthetic and args.apply:
        raise ValueError("prepare and start are separate approved operations")
    result = prepare(create_key=args.create_key) if args.apply else start_synthetic()
    import json
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
