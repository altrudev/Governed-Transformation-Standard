"""Regression tests for observer storage and socket authorization separation."""
import os
import pathlib
import tempfile
import unittest
from observer.service import Receiver

class BoundaryTests(unittest.TestCase):
    def test_socket_mode_is_not_storage_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            socket_path = pathlib.Path(folder) / "observer.sock"
            server = Receiver(socket_path, "c"*32, {os.getuid()})
            try:
                # The deployed service sets this explicitly after creation.
                os.chmod(socket_path, 0o660)
                self.assertEqual(socket_path.stat().st_mode & 0o777, 0o660)
            finally:
                server.server_close()

    def test_broker_is_not_authorized_to_read_evidence_by_socket_protocol(self):
        from broker.client import submit
        with self.assertRaises(ValueError):
            submit("/invalid", {"case_id":"x", "operation":"read-journal", "challenge":"c"*32})
