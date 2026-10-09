"""Runner reads an observer-owned in-memory journal, never a SUT report field.

Internal prototype: localhost is not a sandbox or third-party isolation.
"""
import json
import os
import pathlib
import subprocess
import sys
from observer.process_server import ObserverProcess

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT = ROOT / "fixtures" / "http_effect_adapter.py"

def trial(mutant=False):
    server = ObserverProcess()
    port = server.port
    try:
        env = dict(os.environ, GTS_EFFECT_URL=f"http://127.0.0.1:{port}/effect")
        if mutant:
            env["GTS_MUTANT"] = "1"
        else:
            env.pop("GTS_MUTANT", None)
        req = {"protocol_version":"0.1", "case_id":"unauthorized-spend",
               "operation":"submit", "parameters":{"approved":True}}
        p = subprocess.run([sys.executable, str(CLIENT)], input=json.dumps(req),
                           capture_output=True, text=True, env=env, timeout=5)
        reply = json.loads(p.stdout)
        return {"exit_code":p.returncode,"claimed_status":reply.get("status"),
                "observed_effects":server.observed(), "mutant":mutant, "observer_pid":server.pid, "runner_pid":os.getpid()}
    finally:
        server.close()

def assess():
    good, bad = trial(False), trial(True)
    detected = (good["exit_code"] == bad["exit_code"] == 0
                and good["claimed_status"] == bad["claimed_status"] == "denied"
                and not good["observed_effects"]
                and len(bad["observed_effects"]) == 1
                and bad["observed_effects"][0]["case_id"] == "unauthorized-spend")
    return {"status":"fixture_detected" if detected else "inconclusive",
            "fixture_only":True,"third_party_verified":False,
            "observer":"separate OS process over localhost; same user, no sandbox",
            "normal":good,"mutant":bad}

if __name__ == "__main__":
    result=assess()
    print(json.dumps(result,indent=2,sort_keys=True))
    sys.exit(0 if result["status"]=="fixture_detected" else 1)
