import configparser
import pathlib
import unittest
UNIT = pathlib.Path(__file__).resolve().parents[1] / "deployment" / "gts-observer.service"

class UnitBlueprintTests(unittest.TestCase):
    def test_restricted_service_profile(self):
        cfg=configparser.ConfigParser(interpolation=None)
        cfg.read(UNIT)
        service=cfg["Service"]
        self.assertEqual(service["User"],"gts-observer")
        self.assertEqual(service["ExecStart"],"/usr/bin/python3 -m observer.runtime")
        self.assertEqual(service["Group"],"gts-observer")
        self.assertEqual(service["SupplementaryGroups"],"gts-broker gts-evaluator")
        self.assertEqual(service["ReadWritePaths"],"/run/gts-issuer /run/gts-observer /var/lib/gts-observer")
        self.assertEqual(service["StateDirectoryMode"],"0700")
        self.assertEqual(service["NoNewPrivileges"],"yes")
        self.assertEqual(service["ProtectSystem"],"strict")
        self.assertEqual(service["ProtectHome"],"yes")
        self.assertEqual(service["IPAddressDeny"],"any")
        self.assertEqual(service["RestrictAddressFamilies"],"AF_UNIX")
        self.assertEqual(service["MemoryMax"],"256M")
        self.assertEqual(service["TasksMax"],"32")
        self.assertEqual(service["UMask"],"0077")
