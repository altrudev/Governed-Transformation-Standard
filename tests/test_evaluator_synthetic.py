import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from evaluator.synthetic_acceptance import perform


class SyntheticEvaluatorTests(unittest.TestCase):
    def test_development_user_cannot_announce_evaluator(self):
        with self.assertRaises((PermissionError,KeyError)):
            perform("case-1")

    def test_invalid_case_rejected_before_identity_or_effect(self):
        for value in ("", "../etc", "x"*90, "case with spaces"):
            with self.assertRaises(ValueError):
                perform(value)

    def test_fixture_mock_admitted_without_ever_claiming_independent_result(self):
        uid=os.geteuid()
        mapping={"gts-evaluator": SimpleNamespace(pw_uid=uid),
                 "gts-observer": SimpleNamespace(pw_uid=uid+100),
                 "gts-broker": SimpleNamespace(pw_uid=uid+101)}
        with patch("evaluator.synthetic_acceptance.pwd.getpwnam",side_effect=lambda n:mapping[n]), patch(
            "evaluator.synthetic_acceptance.request_challenge",return_value="a"*64
        ) as issued, patch("evaluator.synthetic_acceptance.deliver",return_value=True) as received:
            result=perform("case-123")
        issued.assert_called_once()
        received.assert_called_once()
        self.assertTrue(result["delivery_acknowledged"])
        self.assertFalse(result["independent_observation_verified"])
        self.assertEqual(result["release_authority"],"NONE")

if __name__=="__main__":
    unittest.main()
