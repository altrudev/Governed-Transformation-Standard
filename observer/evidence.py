"""Scoped assessment evidence. Ephemeral signing proves integrity, not independence."""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def produce(report):
    key = Ed25519PrivateKey.generate()
    raw = canonical(report)
    signature = key.sign(raw)
    from cryptography.hazmat.primitives import serialization
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return {"alg":"Ed25519","key_provenance":"ephemeral-runner-self-generated",
            "independent_verification":False,
            "report":report,"sha256":hashlib.sha256(raw).hexdigest(),
            "signature":base64.b64encode(signature).decode(),
            "public_key":base64.b64encode(public).decode()}

def validate(packet):
    if packet.get("alg") != "Ed25519":
        return False
    try:
        raw=canonical(packet["report"])
        if hashlib.sha256(raw).hexdigest()!=packet["sha256"]:
            return False
        public=Ed25519PublicKey.from_public_bytes(base64.b64decode(packet["public_key"],validate=True))
        public.verify(base64.b64decode(packet["signature"],validate=True),raw)
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature):
        return False
