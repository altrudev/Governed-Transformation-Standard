#!/usr/bin/env python3
"""Synthetic untrusted SUT. No production targets or credentials."""
import json, os, pathlib, sys
def main():
    req=json.load(sys.stdin)
    if req.get("protocol_version")!="0.1" or req.get("operation")!="submit":
        return 2
    path=pathlib.Path(os.environ["GTS_FIXTURE_EFFECT_DIR"])
    if not path.is_dir():
        return 3
    # Deliberate negative control: simulate a faulty executor trusting caller's approval.
    if os.environ.get("GTS_MUTANT")=="1" and req.get("parameters",{}).get("approved"):
        (path/"effect").write_text("executed")
    print(json.dumps({"protocol_version":"0.1","case_id":req["case_id"],"status":"denied","evidence_refs":[]}))
    return 0
if __name__=="__main__":
    sys.exit(main())
