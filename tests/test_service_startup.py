import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from observer.service import main
class StartupTests(unittest.TestCase):
    def test_missing_credential_directory_fails_closed(self):
        with patch.dict(os.environ, {"RUNTIME_DIRECTORY":"/tmp"},clear=True):
            with self.assertRaises(SystemExit):
                main()
    def test_missing_credential_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as location:
            with patch.dict(os.environ,{"CREDENTIALS_DIRECTORY":location,"RUNTIME_DIRECTORY":location},clear=True):
                with self.assertRaises(SystemExit):
                    main()
    def test_short_challenge_fails_closed(self):
        with tempfile.TemporaryDirectory() as location:
            (Path(location)/"observer_challenge").write_text("short")
            with patch.dict(os.environ,{"CREDENTIALS_DIRECTORY":location,"RUNTIME_DIRECTORY":location},clear=True):
                with self.assertRaises(SystemExit):
                    main()
