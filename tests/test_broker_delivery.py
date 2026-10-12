"""Protocol tests, NOT separate-Linux-UID acceptance tests."""
import os
from pathlib import Path
import tempfile
import threading
import unittest

from broker.delivery import DeliveryServer, deliver
from observer.challenge_authority import ChallengeAuthority
from observer.durable_events import DurableEvents
from observer.issuance import IssuanceServer, request_challenge
from observer.service import Receiver


class BrokerDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.authority = ChallengeAuthority()
        self.issuer_dir = self.home / "issuer"
        self.issuer_dir.mkdir(mode=0o710)
        self.issuer_dir.chmod(0o710)
        self.issuer = IssuanceServer(
            self.issuer_dir / "issue.sock", self.authority,
            evaluator_uid=os.getuid(), observer_uid=os.getuid() + 100,
            evaluator_gid=os.getegid()
        )
        self.journal = DurableEvents(self.home / "events.jsonl")
        self.receiver = Receiver(
            self.home / "observer.sock", None, {os.getuid()},
            authority=self.authority, durable_events=self.journal
        )
        self.broker_dir = self.home / "broker"
        self.broker_dir.mkdir(mode=0o710)
        self.broker_dir.chmod(0o710)
        # This explicit same-UID exception is used ONLY in isolated unit tests.
        self.broker = DeliveryServer(
            self.broker_dir / "deliver.sock", self.receiver.server_address,
            evaluator_uid=os.getuid(), broker_uid=os.getuid(),
            evaluator_gid=os.getegid(), require_distinct=False
        )
        self.servers = (self.issuer, self.receiver, self.broker)
        self.threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in self.servers
        ]
        for thread in self.threads:
            thread.start()

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
        self.temp.cleanup()

    def test_end_to_end_observed_durable_once(self):
        token = request_challenge(self.issuer.server_address, "case-1")
        event = {"case_id": "case-1", "operation": "synthetic-effect",
                 "challenge": token}
        self.assertTrue(deliver(self.broker.server_address, event))
        self.assertEqual(DurableEvents(self.home / "events.jsonl").count, 1)
        with self.assertRaises(PermissionError):
            deliver(self.broker.server_address, event)
        self.assertEqual(self.journal.count, 1)

    def test_impersonation_wrong_kernel_peer_uid_denied(self):
        self.broker.evaluator_uid = os.getuid() + 100000
        token = request_challenge(self.issuer.server_address, "not-authorized")
        with self.assertRaises(PermissionError):
            deliver(self.broker.server_address,
                    {"case_id": "not-authorized", "operation": "synthetic-effect",
                     "challenge": token})
        self.assertEqual(self.journal.count, 0)

    def test_broker_cannot_solicit_challenge_as_other_uid(self):
        self.issuer.evaluator_uid = os.getuid() + 100000
        with self.assertRaises((ValueError, OSError)):
            request_challenge(self.issuer.server_address, "forbidden")

    def test_malformed_challenge_rejected_before_observer(self):
        with self.assertRaises(ValueError):
            deliver(self.broker.server_address,
                    {"case_id": "bad", "operation": "synthetic-effect",
                     "challenge": "../arbitrary-code"})
        self.assertEqual(self.journal.count, 0)

    def test_broader_shared_socket_parent_denied(self):
        other = self.home / "exposed"
        other.mkdir()
        other.chmod(0o770)
        with self.assertRaises(PermissionError):
            DeliveryServer(other / "deliver.sock", self.receiver.server_address,
                           evaluator_uid=os.getuid(), broker_uid=os.getuid(),
                           evaluator_gid=os.getegid(), require_distinct=False)

    def test_production_identity_separation_mandatory(self):
        path = self.broker_dir / "production.sock"
        with self.assertRaises(ValueError):
            DeliveryServer(path, self.receiver.server_address,
                           evaluator_uid=os.getuid(), broker_uid=os.getuid())

    def test_issuance_broad_permissions_denied(self):
        other = self.home / "publicissuer"
        other.mkdir()
        other.chmod(0o750)
        with self.assertRaises(PermissionError):
            IssuanceServer(other / "issuer.sock", self.authority, os.getuid(),
                           observer_uid=os.getuid() + 100, evaluator_gid=os.getegid())


if __name__ == "__main__":
    unittest.main()
