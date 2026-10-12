"""External host witness verifier. Does not generate keys or trust in-band claims."""
import base64
import hashlib
import json
import pathlib
import re
from datetime import datetime, timezone
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "gts.host-witness.v1"
REQUIRED = {"schema", "requirement", "revision", "observed_at", "outcome",
            "evidence_sha256", "environment", "witness_id"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

def verify_witness(packet, *, requirement, revision, public_key, evidence_bytes, now=None, max_age_seconds=86400):
    """Verify one independently supplied signed evidence envelope; return False closed."""
    try:
        if not isinstance(packet, dict) or set(packet) != {"statement", "signature"}:
            return False
        statement = packet["statement"]
        if not isinstance(statement, dict) or set(statement) != REQUIRED:
            return False
        if (statement["schema"] != SCHEMA or statement["requirement"] != requirement
            or statement["revision"] != revision or statement["outcome"] != "PASS"
            or not isinstance(statement["environment"], str) or not statement["environment"]
            or not isinstance(statement["witness_id"], str) or not statement["witness_id"]
            or not isinstance(statement["evidence_sha256"], str)
            or not HEX64.fullmatch(statement["evidence_sha256"])
            or not isinstance(revision, str) or not HEX40.fullmatch(revision)):
            return False
        if (not isinstance(public_key, bytes) or len(public_key) != 32
            or not isinstance(evidence_bytes, bytes)):
            return False
        stamp = datetime.fromisoformat(statement["observed_at"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return False
        current = now if now is not None else datetime.now(timezone.utc)
        age = (current - stamp).total_seconds()
        if age < -300 or age > max_age_seconds:
            return False
        if hashlib.sha256(evidence_bytes).hexdigest() != statement["evidence_sha256"]:
            return False
        signature = base64.b64decode(packet["signature"], validate=True)
        if len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical(statement))
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature, UnicodeError, OverflowError):
        return False

def check_external_witnesses(directory, anchor_path, requirements, revision):
    """Accept only an explicitly configured outside trust anchor and exact raw evidence bytes."""
    results = {r: {"status": "BLOCKED", "reason": "Independent signed witness not verified"} for r in requirements}
    if not directory or not anchor_path or not revision:
        return results
    directory = pathlib.Path(directory)
    anchor_path = pathlib.Path(anchor_path)
    try:
        anchor = anchor_path.read_bytes()
        if len(anchor) != 32:
            return results
        for requirement in requirements:
            packet = json.loads((directory / (requirement + ".json")).read_text())
            evidence = (directory / (requirement + ".evidence")).read_bytes()
            if len(evidence) > 2_000_000:
                continue
            if verify_witness(packet, requirement=requirement, revision=revision,
                              public_key=anchor, evidence_bytes=evidence):
                results[requirement] = {"status": "PASS",
                                        "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                                        "verified_anchor_sha256": hashlib.sha256(anchor).hexdigest()}
    except (OSError, ValueError, UnicodeError):
        pass
    return results
