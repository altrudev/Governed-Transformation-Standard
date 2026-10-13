"""Broker crash/replay protocol tests, no independent host trust claims."""
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from broker.durable_attempts import DurableAttempts
from broker.delivery import DeliveryServer, deliver
from observer.challenge_authority import ChallengeAuthority
from observer.durable_events import DurableEvents
from observer.service import Receiver


class DurableBrokerAttemptsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.home.chmod(0o700)
        self.db_path = self.home / "delivery.db"

    def tearDown(self):
        self.temp.cleanup()

    def test_reserved_case_survives_restart_and_is_not_replayable(self):
        first = DurableAttempts(self.db_path)
        self.assertTrue(first.reserve("r1"))
        self.assertEqual(first.status("r1"), "IN_DOUBT")
        first.close()
        second = DurableAttempts(self.db_path)
        try:
            self.assertEqual(second.status("r1"), "IN_DOUBT")
            self.assertFalse(second.reserve("r1"))
            self.assertTrue(second.acknowledge("r1"))
            self.assertEqual(second.status("r1"), "ACKNOWLEDGED")
            self.assertFalse(second.reserve("r1"))
        finally:
            second.close()
        final = DurableAttempts(self.db_path)
        try:
            self.assertEqual(final.status("r1"), "ACKNOWLEDGED")
            self.assertFalse(final.reserve("r1"))
        finally:
            final.close()

    def test_production_broker_refuses_without_durable_state(self):
        with self.assertRaisesRegex(ValueError, "requires durable"):
            DeliveryServer(self.home / "missing.sock", self.home / "observer.sock",
                           evaluator_uid=os.getuid()+1, broker_uid=os.geteuid())

    def test_insecure_storage_is_denied(self):
        self.home.chmod(0o770)
        with self.assertRaises(PermissionError):
            DurableAttempts(self.db_path)
        self.home.chmod(0o700)
        self.db_path.write_text("not a database")
        self.db_path.chmod(0o666)
        with self.assertRaises(PermissionError):
            DurableAttempts(self.db_path)

    def test_symlinked_state_is_denied(self):
        target = self.home / "target.db"
        target.write_bytes(b"")
        self.db_path.symlink_to(target)
        with self.assertRaises(PermissionError):
            DurableAttempts(self.db_path)

    def test_indeterminate_observer_delivery_never_retries_after_restart(self):
        ledger = DurableAttempts(self.db_path)
        authority = ChallengeAuthority()
        observer = Receiver(self.home / "observed.sock", None, {os.getuid()},
                            authority=authority, durable_events=DurableEvents(self.home / "observed.jsonl"))
        broker_dir = self.home / "broker"
        broker_dir.mkdir(mode=0o700)
        broker = DeliveryServer(broker_dir / "deliver.sock", observer.server_address,
                                evaluator_uid=os.getuid(), broker_uid=os.getuid(),
                                require_distinct=False, durable_attempts=ledger)
        worker = threading.Thread(target=broker.serve_forever, daemon=True)
        worker.start()
        event = {"case_id":"uncertain", "operation":"synthetic-effect",
                 "challenge":authority.issue(case_id="uncertain")}
        try:
            with patch("broker.delivery.submit", side_effect=TimeoutError("ambiguous result")):
                with self.assertRaises(PermissionError):
                    deliver(broker.server_address, event)
            self.assertEqual(ledger.status("uncertain"), "IN_DOUBT")
        finally:
            broker.shutdown()
            broker.server_close()
            worker.join(timeout=3)
            observer.server_close()
            ledger.close()
        restarted = DurableAttempts(self.db_path)
        try:
            self.assertEqual(restarted.status("uncertain"), "IN_DOUBT")
            self.assertFalse(restarted.reserve("uncertain"))
        finally:
            restarted.close()

    def test_durable_broker_acknowledges_only_observer_success(self):
        ledger = DurableAttempts(self.db_path)
        authority = ChallengeAuthority()
        observer = Receiver(self.home / "observed.sock", None, {os.getuid()},
                            authority=authority, durable_events=DurableEvents(self.home / "observed.jsonl"))
        observer_thread = threading.Thread(target=observer.serve_forever, daemon=True)
        observer_thread.start()
        broker_dir = self.home / "broker"
        broker_dir.mkdir(mode=0o700)
        broker = DeliveryServer(broker_dir / "deliver.sock", observer.server_address,
                                evaluator_uid=os.getuid(), broker_uid=os.getuid(),
                                require_distinct=False, durable_attempts=ledger)
        worker = threading.Thread(target=broker.serve_forever, daemon=True)
        worker.start()
        event = {"case_id":"case-verified","operation":"synthetic-effect",
                 "challenge":authority.issue(case_id="case-verified")}
        try:
            self.assertTrue(deliver(broker.server_address, event))
            self.assertEqual(ledger.status("case-verified"), "ACKNOWLEDGED")
            with self.assertRaises(PermissionError):
                deliver(broker.server_address, event)
        finally:
            broker.shutdown()
            observer.shutdown()
            broker.server_close()
            observer.server_close()
            worker.join(timeout=3)
            observer_thread.join(timeout=3)
            ledger.close()


if __name__ == "__main__":
    unittest.main()
