import concurrent.futures
import tempfile
from unittest.mock import patch
import unittest
from pathlib import Path
from observer.durable_events import DurableEvents

class DurableEventsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/"observer.jsonl"
    def tearDown(self):
        self.tmp.cleanup()
    def test_restart_and_duplicate_rejection(self):
        store=DurableEvents(self.path)
        store.append("a","synthetic-effect")
        reopened=DurableEvents(self.path)
        self.assertEqual(reopened.count,1)
        with self.assertRaises(ValueError):reopened.append("a","synthetic-effect")
    def test_tampered_file_fails_closed(self):
        store=DurableEvents(self.path)
        store.append("a","synthetic-effect")
        raw=self.path.read_bytes().replace(b'"case_id":"a"',b'"case_id":"b"')
        self.path.write_bytes(raw)
        with self.assertRaises(ValueError):DurableEvents(self.path)
    def test_truncated_tail_fails_closed(self):
        DurableEvents(self.path).append("a","synthetic-effect")
        self.path.write_bytes(self.path.read_bytes()[:-3])
        with self.assertRaises(ValueError):DurableEvents(self.path)
    def test_concurrent_duplicate_only_one(self):
        store=DurableEvents(self.path)
        def write(_):
            try:store.append("same","synthetic-effect");return True
            except ValueError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(write,range(16)))
        self.assertEqual(results.count(True),1)
        self.assertEqual(DurableEvents(self.path).count,1)
    def test_bad_event_rejected(self):
        store=DurableEvents(self.path)
        with self.assertRaises(ValueError):store.append("x","arbitrary-sign")

    def test_write_failure_poisoned_until_recovery(self):
        store=DurableEvents(self.path)
        with patch("observer.durable_events.os.fsync", side_effect=OSError("injected fsync failure")):
            with self.assertRaises(OSError):
                store.append("a","synthetic-effect")
        with self.assertRaises(RuntimeError):
            store.append("b","synthetic-effect")
        # The fsync failure may have written an entire record; restart
        # reconstructs it, rather than replaying the original case.
        fresh=DurableEvents(self.path)
        self.assertEqual(fresh.count,1)
        with self.assertRaises(ValueError):
            fresh.append("a","synthetic-effect")
