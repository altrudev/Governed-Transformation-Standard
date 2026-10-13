"""Verifier-owned, purpose-bound synthetic challenge state.

Issuance is only an in-process API invoked by trusted evaluator code; it is
NOT exposed through the untrusted effect socket. Not a production authority.
"""
import hmac
import secrets
import threading
import time

class ChallengeAuthority:
    def __init__(self, clock=None):
        self._clock = clock or time.monotonic
        self._pending = {}
        self._lock = threading.Lock()

    def issue(self, *, case_id, purpose="synthetic-effect", ttl_seconds=30):
        if (not isinstance(case_id, str) or not 1 <= len(case_id) <= 128
            or purpose != "synthetic-effect"
            or not isinstance(ttl_seconds, (int, float))
            or isinstance(ttl_seconds, bool)
            or not 0 < ttl_seconds <= 300):
            raise ValueError("invalid scope")
        token = secrets.token_hex(32)
        with self._lock:
            if case_id in self._pending:
                raise ValueError("case already issued or consumed")
            self._pending[case_id] = {
                "token": token, "purpose": purpose,
                "deadline": self._clock() + ttl_seconds, "consumed": False
            }
        return token

    def consume(self, *, case_id, purpose, token):
        if not isinstance(case_id, str) or not isinstance(token, str):
            return False
        with self._lock:
            item = self._pending.get(case_id)
            if (item is None or item["consumed"]
                or self._clock() >= item["deadline"]
                or purpose != item["purpose"]
                or not hmac.compare_digest(token, item["token"])):
                return False
            item["consumed"] = True
            return True
