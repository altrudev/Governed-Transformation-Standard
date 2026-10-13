"""Evidence-driven GTS release gate. A missing witness is never a pass."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from assurance.witness import check_external_witnesses
from assurance.system_closure import check_system_closure, MANDATORY_SYSTEM

ROOT = Path(__file__).resolve().parents[1]
MANDATORY_HOST = (
    "real_cross_account_socket",
    "trusted_evaluator_to_broker_delivery",
    "observer_owned_signer_and_pinned_verifier",
    "crash_recovery_and_external_journal_anchor",
    "sandbox_broker_impersonation_denial",
)
TEST_GROUPS = {
    "regression": ["discover", "-s", "tests", "-q"],
    "adversarial_integration": ["tests.test_integrated_evidence_path",
        "tests.test_receiver_authority_wiring", "tests.test_issuance_socket",
        "tests.test_strict_observer", "tests.test_key_custody",
        "tests.test_durable_events", "tests.test_adversarial_static_challenge", "-q"],
}
def execute(root, args, timeout=90):
    try:
        proc = subprocess.run([sys.executable, "-m", "unittest", *args], cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        raw = proc.stdout
        return {"status": "PASS" if proc.returncode == 0 else "FAIL",
                "exit_code": proc.returncode, "output_sha256": hashlib.sha256(raw).hexdigest(),
                "output_bytes": len(raw), "output_tail": raw.decode("utf-8", "replace")[-1200:]}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "BLOCKED", "reason": type(exc).__name__}

def run(root=ROOT, execute_tests=True, witness_dir=None, trust_anchor=None):
    root = Path(root)
    tests = {name: execute(root, args) for name, args in TEST_GROUPS.items()} if execute_tests else {}
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    revision = commit.stdout.strip() if commit.returncode == 0 else None
    diff = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True)
    clean = diff.returncode == 0 and not diff.stdout.strip()
    host = check_external_witnesses(witness_dir, trust_anchor, MANDATORY_HOST, revision)
    system, closure = check_system_closure(
        Path(witness_dir) / "system" if witness_dir else None,
        trust_anchor, revision)
    accepted = (bool(tests) and clean
        and all(item["status"] == "PASS" for item in tests.values())
        and all(item["status"] == "PASS" for item in host.values())
        and all(item["status"] == "PASS" for item in system.values())
        and closure["status"] == "PASS")
    return {
        "schema": "gts.release-evidence.v2", "generated_utc": datetime.now(timezone.utc).isoformat(),
        "revision": revision, "working_tree_clean": clean,
        "test_execution": tests, "required_host_witnesses": host,
        "required_system_evidence": system,
        "dependency_closure": closure,
        "total_gates": len(tests)+len(host)+len(system),
        "verified_gates": (sum(item["status"]=="PASS" for item in tests.values())
            + sum(item["status"]=="PASS" for item in host.values())
            + sum(item["status"]=="PASS" for item in system.values())),
        "blocked_dependencies": (
            ["local_test_" + key for key, value in tests.items() if value["status"] != "PASS"]
            + ["host_witness_" + key for key, value in host.items() if value["status"] != "PASS"]
            + ["system_evidence_" + key for key, value in system.items() if value["status"] != "PASS"]
            + ([] if clean else ["source_tree_not_clean"])
            + ([] if closure["status"] == "PASS" else ["dependency_graph_not_closed"])
        ),
        "overall": "PASS" if accepted else "BLOCKED",
        "release_authorized": accepted,
        "limitations": [
            "Test process exit codes and output hashes are local evidence, not independent attestations.",
            "Host witnesses require a separate controlled evidence ingestion and verification workflow.",
            "An externally anchored observer journal and production release equivalence remain unverified.",
            "A release is never admitted from local PASS counts without independently witnessed system-wide scope and dependency closure.",
            "Validated signatures do not independently establish truth or completeness of evidence; external assessor must inspect measured effects and trust domains."
        ],
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    parser.add_argument("--witness-dir", type=Path)
    parser.add_argument("--trust-anchor", type=Path)
    args = parser.parse_args()
    result = run(witness_dir=args.witness_dir, trust_anchor=args.trust_anchor)
    payload = json.dumps(result, indent=2, sort_keys=True)+"\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(args.report, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    print(payload, end="")
    return 0 if result["release_authorized"] else 2

if __name__ == "__main__":
    sys.exit(main())
