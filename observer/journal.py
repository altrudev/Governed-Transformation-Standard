"""Signed, hash-linked synthetic event journal; evaluator supplies public trust anchor."""
import base64
import hashlib
from observer.evidence import canonical
from observer.trusted_evidence import verify

def chain_events(events):
    previous = "0" * 64
    result = []
    for index, event in enumerate(events):
        entry = {"sequence": index, "previous_sha256": previous, "event": event}
        previous = hashlib.sha256(canonical(entry)).hexdigest()
        result.append(entry)
    return result, previous

def sign_journal(events, private_key, subject_sha256, challenge):
    entries, root = chain_events(events)
    report = {"format": "gts.synthetic-journal.v0.1",
              "subject_sha256": subject_sha256, "challenge": challenge,
              "entries": entries, "entry_count": len(entries), "chain_root": root}
    raw = canonical(report)
    return {"alg": "Ed25519", "report": report,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "signature": base64.b64encode(private_key.sign(raw)).decode()}

def verify_journal(packet, expected_public_key, subject_sha256, challenge):
    if not verify(packet, expected_public_key, subject_sha256, challenge):
        return False
    report = packet["report"]
    if report.get("format") != "gts.synthetic-journal.v0.1":
        return False
    entries = report.get("entries")
    if not isinstance(entries, list) or len(entries) > 10000:
        return False
    previous = "0" * 64
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"sequence", "previous_sha256", "event"}:
            return False
        if entry["sequence"] != index or entry["previous_sha256"] != previous:
            return False
        previous = hashlib.sha256(canonical(entry)).hexdigest()
    return report.get("entry_count") == len(entries) and report.get("chain_root") == previous
