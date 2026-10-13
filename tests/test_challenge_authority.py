import concurrent.futures
import unittest
from observer.challenge_authority import ChallengeAuthority

class ChallengeSecurityTests(unittest.TestCase):
    def setUp(self):
        self.now = [100.0]
        self.authority = ChallengeAuthority(lambda: self.now[0])
        self.token = self.authority.issue(case_id="case-1", ttl_seconds=5)
    def consume(self, **kwargs):
        return self.authority.consume(case_id=kwargs.get("case_id", "case-1"),
            purpose=kwargs.get("purpose", "synthetic-effect"),
            token=kwargs.get("token", self.token))
    def test_issued_single_use(self):
        self.assertTrue(self.consume())
        self.assertFalse(self.consume())
    def test_unissued_case_rejected(self):
        self.assertFalse(self.consume(case_id="invented"))
    def test_cross_case_token_rejected(self):
        self.authority.issue(case_id="case-2")
        self.assertFalse(self.consume(case_id="case-2"))
    def test_bad_token_rejected(self):
        self.assertFalse(self.consume(token="00" * 32))
    def test_expired_rejected(self):
        self.now[0] += 5
        self.assertFalse(self.consume())
    def test_purpose_substitution_rejected(self):
        self.assertFalse(self.consume(purpose="read-journal"))
    def test_failed_attempt_does_not_consume(self):
        self.assertFalse(self.consume(token="bad"))
        self.assertTrue(self.consume())
    def test_duplicate_issuance_rejected(self):
        with self.assertRaises(ValueError):
            self.authority.issue(case_id="case-1")
    def test_concurrent_replay_exactly_one_accepted_in_memory(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:self.consume(), range(16)))
        self.assertEqual(results.count(True),1)
    def test_bad_ttl_rejected(self):
        for ttl in [-1,0,301,True]:
            with self.assertRaises(ValueError):
                self.authority.issue(case_id="other",ttl_seconds=ttl)
