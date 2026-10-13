"""Fail-closed, fsync-backed single-use delivery reservations.

A reservation is committed before any outward effect. On an ambiguous result,
the case is deliberately not released for retry. Does not confer authority,
prove actual observer effect or provide rollback-resistant external anchoring.
"""
import os
from pathlib import Path
import sqlite3
import stat
import threading


class DurableAttempts:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        parent = self.path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError("trusted delivery state directory required")
        directory = parent.stat()
        if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) & 0o077:
            raise PermissionError("delivery state directory must be owner-private")
        if self.path.is_symlink():
            raise PermissionError("symlinked delivery state prohibited")
        created = False
        if not self.path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.path, flags, 0o600)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            created = True
        metadata = self.path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise PermissionError("insecure broker delivery state")
        # WAL generates mutable sidecars; DELETE+FULL requires only the existing
        # protected database file and a protected directory.
        self.connection = sqlite3.connect(
            f"file:{self.path}?mode=rw", uri=True, isolation_level=None,
            check_same_thread=False, timeout=2.0
        )
        try:
            self.connection.execute("PRAGMA journal_mode=DELETE")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS reservations "
                "(case_id TEXT PRIMARY KEY NOT NULL, status TEXT NOT NULL "
                "CHECK (status IN ('IN_DOUBT', 'ACKNOWLEDGED')))"
            )
            if created:
                fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except BaseException:
            self.connection.close()
            raise

    def reserve(self, case_id):
        if (not isinstance(case_id, str) or not 1 <= len(case_id) <= 128):
            raise ValueError("invalid reservation case")
        with self.lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute(
                    "INSERT INTO reservations(case_id,status) VALUES (?, 'IN_DOUBT')",
                    (case_id,)
                )
                self.connection.execute("COMMIT")
                return True
            except (sqlite3.IntegrityError, sqlite3.DatabaseError):
                if self.connection.in_transaction:
                    self.connection.execute("ROLLBACK")
                # An existing reservation or disk failure must not dispatch.
                return False

    def acknowledge(self, case_id):
        with self.lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                row = self.connection.execute(
                    "UPDATE reservations SET status='ACKNOWLEDGED' "
                    "WHERE case_id=? AND status='IN_DOUBT'", (case_id,)
                )
                if row.rowcount != 1:
                    self.connection.execute("ROLLBACK")
                    return False
                self.connection.execute("COMMIT")
                return True
            except sqlite3.DatabaseError:
                if self.connection.in_transaction:
                    self.connection.execute("ROLLBACK")
                return False

    def status(self, case_id):
        with self.lock:
            row = self.connection.execute(
                "SELECT status FROM reservations WHERE case_id=?", (case_id,)
            ).fetchone()
            return row[0] if row else None

    def close(self):
        with self.lock:
            self.connection.close()
