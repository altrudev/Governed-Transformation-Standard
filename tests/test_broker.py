import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from broker.client import submit
from observer.service import Receiver

class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=str(Path(self.tmp.name)/"observer.sock")
        self.challenge="c"*32
        self.server=Receiver(self.path,self.challenge,{os.getuid()})
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()
    def event(self):
        return {"case_id":"case-1","operation":"synthetic-effect","challenge":self.challenge}
    def test_allowed_broker_submission(self):
        self.assertTrue(submit(self.path,self.event()))
        self.assertEqual(len(self.server.events),1)
    def test_non_allowlisted_identity_rejected(self):
        self.server.allowed_uids=frozenset({os.getuid()+100000})
        with self.assertRaises((PermissionError,ConnectionResetError,BrokenPipeError)):
            submit(self.path,self.event())
        self.assertEqual(self.server.events,[])
    def test_no_arbitrary_commands(self):
        e=self.event();e["operation"]="read-private-key"
        with self.assertRaises(ValueError):
            submit(self.path,e)
    def test_no_extra_fields(self):
        e=self.event();e["file"]="/var/lib/gts-observer/key"
        with self.assertRaises(ValueError):
            submit(self.path,e)
    def test_replay_rejected(self):
        self.assertTrue(submit(self.path,self.event()))
        with self.assertRaises((PermissionError,ConnectionResetError,BrokenPipeError)):
            submit(self.path,self.event())
        self.assertEqual(len(self.server.events),1)
