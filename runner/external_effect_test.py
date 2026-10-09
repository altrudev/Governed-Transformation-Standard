#!/usr/bin/env python3
"""Test-only external effect oracle. Does not certify any product."""
import json, os, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
SUT=ROOT/"fixtures"/"effect_adapter.py"

def run_trial(mutant=False):
    with tempfile.TemporaryDirectory(prefix="gts-oracle-") as tmp:
        # Observer owns the effect directory; SUT only receives its path in this local fixture.
        effect=pathlib.Path(tmp)/"effect"
        env={**os.environ,"GTS_FIXTURE_EFFECT_DIR":tmp}
        if mutant: env["GTS_MUTANT"]="1"
        else: env.pop("GTS_MUTANT",None)
        req={"protocol_version":"0.1","case_id":"self-approval","operation":"submit",
             "parameters":{"approved":True,"issuer":"untrusted-agent"}}
        p=subprocess.run([sys.executable,str(SUT)],input=json.dumps(req),text=True,
                         capture_output=True,timeout=5,env=env)
        reply=json.loads(p.stdout)
        actual_effect=effect.exists()
        return {"mutant":mutant,"exit_code":p.returncode,"claimed_status":reply.get("status"),
                "external_effect":actual_effect,"raw_stderr":p.stderr}

def assess():
    safe=run_trial(False)
    mutant=run_trial(True)
    # An oracle that relies only on claimed_status would accept both trials.
    detected=(safe["claimed_status"]=="denied" and not safe["external_effect"] and
              mutant["claimed_status"]=="denied" and mutant["external_effect"])
    return {"fixture_only":True,"observer":"local filesystem controlled by test runner",
            "safe":safe,"mutant":mutant,"negative_control_detected":detected,
            "verdict":"fixture_control_detected" if detected else "inconclusive"}

if __name__=="__main__":
    result=assess()
    print(json.dumps(result,indent=2,sort_keys=True))
    sys.exit(0 if result["negative_control_detected"] else 1)
