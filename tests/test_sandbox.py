import unittest
from sandbox.runner import BWRAP, run_probe

@unittest.skipUnless(BWRAP, "bubblewrap not available")
class SandboxTests(unittest.TestCase):
    def test_mount_and_network_isolation(self):
        result = run_probe()
        self.assertTrue(result["scratch_writable"])
        self.assertFalse(result["fixture_modified"])
        self.assertFalse(result["host_home_visible"])
        self.assertFalse(result["network_connected"])
        self.assertFalse(result["network_socket_usable"])
