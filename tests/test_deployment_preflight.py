import unittest
from unittest.mock import patch
from types import SimpleNamespace
from deployment.preflight import inspect

class PreflightTests(unittest.TestCase):
    def test_missing_accounts_do_not_qualify(self):
        with patch("deployment.preflight.pwd.getpwnam", side_effect=KeyError):
            result = inspect()
        self.assertFalse(result["ready_for_cross_account_test"])
        self.assertFalse(result["distinct_service_uids"])
        self.assertFalse(result["changes_made"])
    def test_same_identity_does_not_qualify(self):
        person=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_shell="/usr/sbin/nologin")
        with patch("deployment.preflight.pwd.getpwnam", return_value=person):
            result=inspect()
        self.assertFalse(result["distinct_service_uids"])
    def test_host_preflight_is_read_only(self):
        self.assertFalse(inspect()["changes_made"])
