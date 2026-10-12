import os
import grp
from pathlib import Path
import pwd
import socket
import tempfile
import unittest

from deployment.socket_custody import inspect


class SocketCustodyTests(unittest.TestCase):
    def test_missing_paths_never_qualify(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "missing"
            result=inspect([(p, pwd.getpwuid(os.getuid()).pw_name,
                             grp.getgrgid(os.getgid()).gr_name, 0o660, "socket")])
            self.assertFalse(result["all_socket_custody_prerequisites"])
            self.assertFalse(result["cross_account_protocol_qualified"])
            self.assertFalse(result["credential_contents_accessed"])

    def test_metadata_check_and_broader_mode_denial(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "case.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                path.chmod(0o660)
                args=[(path, pwd.getpwuid(os.getuid()).pw_name,
                       grp.getgrgid(os.getgid()).gr_name, 0o660, "socket")]
                self.assertTrue(inspect(args)["all_socket_custody_prerequisites"])
                path.chmod(0o666)
                self.assertFalse(inspect(args)["all_socket_custody_prerequisites"])
                path.chmod(0o660)
                self.assertFalse(inspect([(path, args[0][1],args[0][2],0o710,"directory")])["all_socket_custody_prerequisites"])

    def test_symlink_is_not_socket(self):
        with tempfile.TemporaryDirectory() as root:
            link=Path(root)/"alias";real=Path(root)/"underlying"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.bind(str(real));real.chmod(0o660);link.symlink_to(real)
                self.assertFalse(inspect([(link,pwd.getpwuid(os.getuid()).pw_name,
                    grp.getgrgid(os.getgid()).gr_name,0o660,"socket")])["all_socket_custody_prerequisites"])


if __name__ == "__main__":
    unittest.main()
