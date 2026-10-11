"""GTS assurance sweep: machine-checkable wiring gates, not certification."""
import argparse
import ast
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
def source(relative, root=ROOT):
    return (root / relative).read_text(encoding="utf-8")

def references(relative, names, root=ROOT):
    """Look for executable references, excluding comments, strings and test files."""
    tree = ast.parse(source(relative, root))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                called.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                called.add(fn.attr)
    return all(name in called for name in names)

def run(root=ROOT):
    root = pathlib.Path(root)
    svc = "observer/service.py"
    checks = {
        "challenge_authority_enforced_in_receiver": references(svc, ["consume"], root)
            and "challenge_authority" in source(svc, root),
        "journal_write_on_observation": references(svc, ["sign_journal"], root),
        "durable_observer_custody": references(svc, ["fsync"], root),
        "independent_verifier_in_acceptance_path": references("deployment/acceptance.py", ["verify_journal"], root),
        "deployment_is_actually_gated": "ExecStartPre=" in source("deployment/gts-observer.service", root),
        "secret_delivery_to_broker_implemented": (root / "broker/authority.py").is_file(),
        "real_cross_account_test_implemented": (root / "tests/test_real_host_socket.py").is_file(),
        "production_credential_installation_implemented": (root / "deployment/install-observer.sh").is_file(),
    }
    findings = [{"id": key, "status": "STATIC_INDICATOR_ONLY" if ok else "BLOCKED",
                 "basis": "static call-site / artifact presence only; must also validate dynamically"}
                for key,ok in checks.items()]
    return {"schema": "gts.full-sweep.v1", "overall": "BLOCKED",
            "verified_gates": 0, "static_indicators_found": sum(checks.values()), "total_gates": len(checks),
            "findings": findings, "limitations": [
                "Static call-site checks can be gamed and do not establish run-time execution or production acceptance.",
                "No independently controlled host, secrets, hardware or external assessor is exercised.",
                "Full end-to-end, fault injection and mutation coverage remain mandatory release gates."
            ]}
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--report", type=pathlib.Path)
    args=parser.parse_args()
    result=run()
    report=json.dumps(result,indent=2,sort_keys=True)+"\n"
    print(report,end="")
    if args.report:
        args.report.write_text(report,encoding="utf-8")
    return 0 if result["overall"] == "PASS" else 2
if __name__ == "__main__":
    sys.exit(main())
