import shutil
import unittest
from observer.custody_probe import assess
@unittest.skipUnless(shutil.which("bwrap"),"bubblewrap unavailable")
class CustodyTests(unittest.TestCase):
    def test_unprivileged_user_namespace_and_hidden_secrets(self):
        result=assess()
        self.assertEqual(result["uid"],65534)
        self.assertEqual(result["gid"],65534)
        self.assertFalse(any(result["visible"].values()))
        self.assertTrue(result["tmp_writable"])
