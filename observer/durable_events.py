"""Prototype observer-owned, fsync-backed hash-chain for synthetic events.

This detects accidental/unauthorized modifications relative to the stored
chain, but does not resist an attacker able to rewrite the whole file.
It is NOT independent observation or externally anchored custody.
"""
import hashlib
import json
import os
import pathlib
import stat
import threading

def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

class DurableEvents:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.lock = threading.RLock()
        self._cases = set()
        self._previous = "0" * 64
        self._count = 0
        self._failed = False
        if not self.path.parent.is_dir():
            raise RuntimeError("journal parent missing")
        if self.path.exists():
            meta = self.path.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) & 0o077:
                raise PermissionError("insecure journal file")
            self._load()
        else:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.path, flags, 0o600)
            os.fsync(fd)
            os.close(fd)
            parent = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(parent)
            finally: os.close(parent)

    def _load(self):
        previous = "0" * 64
        cases = set()
        count = 0
        with self.path.open("rb") as file:
            for line in file:
                if len(line) > 4096 or not line.endswith(b"\n"):
                    raise ValueError("invalid journal framing")
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeError) as exc:
                    raise ValueError("invalid journal JSON") from exc
                if not isinstance(record, dict) or set(record) != {"index", "previous", "case_id", "operation", "sha256"}:
                    raise ValueError("invalid journal schema")
                digest = record["sha256"]
                signed_part = {k: record[k] for k in ("index", "previous", "case_id", "operation")}
                expected = hashlib.sha256(canonical(signed_part)).hexdigest()
                if (record["index"] != count or record["previous"] != previous
                    or digest != expected or not isinstance(record["case_id"], str)
                    or record["operation"] != "synthetic-effect"
                    or record["case_id"] in cases):
                    raise ValueError("journal integrity failure")
                cases.add(record["case_id"])
                previous = digest
                count += 1
        self._previous, self._cases, self._count = previous, cases, count

    def append(self, case_id, operation):
        if not isinstance(case_id, str) or not 1 <= len(case_id) <= 128 or operation != "synthetic-effect":
            raise ValueError("invalid event")
        with self.lock:
            if self._failed:
                raise RuntimeError("journal requires recovery after write failure")
            if case_id in self._cases:
                raise ValueError("duplicate committed case")
            record = {"index": self._count, "previous": self._previous,
                      "case_id": case_id, "operation": operation}
            digest = hashlib.sha256(canonical(record)).hexdigest()
            record["sha256"] = digest
            payload = canonical(record) + b"\n"
            flags = os.O_WRONLY | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
            try:
                fd = os.open(self.path, flags)
                try:
                    if os.write(fd, payload) != len(payload):
                        raise OSError("short journal write; recovery required")
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                self._failed = True
                raise
            self._count += 1
            self._previous = digest
            self._cases.add(case_id)
            return digest

    def checkpoint(self):
        """Observed synthetic journal state, NOT a physical-effect claim."""
        with self.lock:
            return {"schema": "gts.synthetic-durable-journal-state.v1",
                    "entry_count": self._count, "last_sha256": self._previous}

    @property
    def count(self):
        return self._count
