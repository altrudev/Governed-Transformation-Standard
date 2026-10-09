#!/usr/bin/env python3
"""Public GTS reference fixture; intentionally NOT an authorization engine."""
import json
import sys

def handle(req):
    if not isinstance(req, dict) or req.get("protocol_version") != "0.1":
        raise ValueError("unsupported protocol")
    case_id = req.get("case_id")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("invalid case id")
    if not isinstance(req.get("parameters"), dict):
        raise ValueError("invalid parameters")
    if req.get("operation") == "capabilities":
        return {"protocol_version":"0.1","case_id":case_id,"status":"ok","evidence_refs":[],"capabilities":["capabilities","submit"]}
    if req.get("operation") == "submit":
        return {"protocol_version":"0.1","case_id":case_id,"status":"denied","evidence_refs":[]}
    raise ValueError("unknown operation")

if __name__ == "__main__":
    try:
        print(json.dumps(handle(json.load(sys.stdin)), sort_keys=True))
    except (ValueError, json.JSONDecodeError) as e:
        print(json.dumps({"status":"error","message":str(e)}))
        sys.exit(2)
