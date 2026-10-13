"""Pre-pinned Ed25519 verifier: embedded packet keys are never trust anchors."""
import base64
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from observer.evidence import canonical

def verify(packet, expected_public_key, expected_subject_digest, expected_challenge):
    """Returns False closed on malformed or unsupported evidence.

    expected_public_key must be separately provisioned by the evaluator.
    expected_subject_digest is hex SHA-256; challenge is evaluator-generated.
    """
    try:
        if not isinstance(packet, dict) or packet.get("alg") != "Ed25519":
            return False
        if not isinstance(expected_public_key, bytes) or len(expected_public_key) != 32:
            return False
        report = packet["report"]
        if not isinstance(report, dict):
            return False
        if report.get("subject_sha256") != expected_subject_digest:
            return False
        if report.get("challenge") != expected_challenge:
            return False
        raw = canonical(report)
        if packet.get("sha256") != hashlib.sha256(raw).hexdigest():
            return False
        signature = base64.b64decode(packet["signature"], validate=True)
        if len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(expected_public_key).verify(signature, raw)
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature, UnicodeError):
        return False
