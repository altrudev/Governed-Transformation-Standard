"""Local AF_UNIX socket cleanup tests; no independent host acceptance."""
import os
from pathlib import Path
import socket
import tempfile
import unittest

from deployment.socket_lifecycle import SingleInstanceLease, guarded_stale_cleanup, cleanup_own_socket


class SocketLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.root.chmod(0o700)
        self.path=self.root/"unit.sock"

    def tearDown(self):
        self.temp.cleanup()

    def bind(self):
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(str(self.path))
        self.path.chmod(0o660)
        return server

    def args(self):
        return {"expected_uid":os.geteuid(),"expected_gid":self.path.lstat().st_gid}

    def test_single_instance_lock_refuses_concurrent_owner(self):
        lease=SingleInstanceLease(self.root)
        try:
            with self.assertRaises(BlockingIOError):
                SingleInstanceLease(self.root)
        finally:
            lease.close()
        second=SingleInstanceLease(self.root)
        second.close()

    def test_dead_socket_only_removed_under_protected_lease(self):
        with self.bind() as server:
            server.close()
        lease=SingleInstanceLease(self.root)
        try:
            self.assertTrue(guarded_stale_cleanup(self.path,**self.args()))
            self.assertFalse(self.path.exists())
        finally:
            lease.close()

    def test_live_socket_never_removed(self):
        server=self.bind()
        server.listen(2)
        try:
            with self.assertRaises(PermissionError):
                guarded_stale_cleanup(self.path,**self.args())
            self.assertTrue(self.path.exists())
        finally:
            server.close()

    def test_symlink_or_regular_file_not_removed(self):
        other=self.root/"regular"
        other.write_text("do not delete")
        self.path.symlink_to(other)
        with self.assertRaises(PermissionError):
            guarded_stale_cleanup(self.path,expected_uid=os.geteuid(),expected_gid=os.getegid())
        self.assertTrue(other.exists())

    def test_wrong_group_denied(self):
        server=self.bind()
        server.close()
        with self.assertRaises(PermissionError):
            guarded_stale_cleanup(self.path,expected_uid=os.geteuid(),expected_gid=999999)
        self.assertTrue(self.path.exists())

    def test_clean_shutdown_only_removes_original_inode(self):
        server=self.bind()
        inode=self.path.lstat().st_ino
        server.close()
        cleanup_own_socket(self.path,expected_uid=os.geteuid(),
                           expected_gid=self.path.lstat().st_gid,original_inode=inode)
        self.assertFalse(self.path.exists())

    def test_wrong_inode_denied(self):
        server=self.bind()
        server.close()
        with self.assertRaises(PermissionError):
            cleanup_own_socket(self.path,expected_uid=os.geteuid(),
                               expected_gid=self.path.lstat().st_gid,original_inode=0)
        self.assertTrue(self.path.exists())

if __name__=="__main__": unittest.main()
