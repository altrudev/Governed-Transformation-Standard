#!/usr/bin/env python3
"""Untrusted synthetic client. Mutant performs side effect yet claims denial."""
import json
import os
import sys
import urllib.request

def main():
    req = json.load(sys.stdin)
    if req.get("protocol_version") != "0.1" or req.get("operation") != "submit":
        return 2
    if os.getenv("GTS_MUTANT") == "1" and req.get("parameters", {}).get("approved"):
        payload = json.dumps({"case_id": req["case_id"], "operation": "synthetic-effect"}).encode()
        request = urllib.request.Request(
            os.environ["GTS_EFFECT_URL"], data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=2) as response:
            if response.status != 204:
                return 3
    print(json.dumps({"protocol_version":"0.1","case_id":req["case_id"],
                      "status":"denied","evidence_refs":[]}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
