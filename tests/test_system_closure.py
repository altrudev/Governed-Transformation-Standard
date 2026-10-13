"""Test that a green suite cannot replace end-to-end signed release proof.

All signing keys and 'live' fixtures in these tests are fabricated test
identities. Passing tests are NEVER independent production qualifications.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from assurance.system_closure import (
    SCHEMA, GRAPH_SCHEMA, GRAPH_DOMAIN, MANDATORY_SYSTEM,
    validate_graph, check_system_closure,
)
from assurance.witness import canonical, SCHEMA as WITNESS_SCHEMA
from assurance.full_sweep import run, TEST_GROUPS, MANDATORY_HOST


class SystemClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.outside_key = Ed25519PrivateKey.generate()
        self.pub = self.outside_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.anchor = self.root / "external-key"
        self.anchor.write_bytes(self.pub)
        self.rev = "a" * 40
        self.graph = {
            "schema": GRAPH_SCHEMA, "revision": self.rev,
            "nodes": [
                {"id": "user", "source_revision": self.rev,
                 "deployed_revision": self.rev, "authority_domain": "fixture-a"},
                {"id": "executor", "source_revision": "b" * 40,
                 "deployed_revision": "b" * 40, "authority_domain": "fixture-b"},
            ],
            "edges": [
                {"id": "submit", "caller": "user", "callee": "executor",
                 "authorization_point": "policy-v1",
                 "effect_point": "dispatcher-v1",
                 "observer_point": "witness-v1"},
            ]
        }
        self.edge_ids, self.scope = validate_graph(self.graph, self.rev)
        self.records = {}
        (self.root / "artifacts").mkdir()
        (self.root / "receipts").mkdir()
        for requirement in MANDATORY_SYSTEM:
            self.records[requirement] = {
                "schema": SCHEMA, "requirement": requirement,
                "revision": self.rev, "deployed_revision": self.rev,
                "scope_sha256": self.scope, "environment": "live",
                "run_id": "synthetic-test", "producer_domain": "test-host",
                "verifier_domain": "test-independent-fixture",
                "edge_ids": ["submit"], "artifact_sha256": [],
                "result": "PASS",
            }
            hashes = {}
            for kind in ("positive_receipt_sha256", "negative_receipt_sha256",
                         "observed_effect_sha256"):
                raw_receipt = canonical({
                    "fixture": "NOT_REAL_HOST_EVIDENCE", "kind": kind,
                    "requirement": requirement, "edge_id": "submit",
                })
                receipt_hash = hashlib.sha256(raw_receipt).hexdigest()
                (self.root / "receipts" / (receipt_hash + ".bin")).write_bytes(raw_receipt)
                hashes[kind] = receipt_hash
            artifact = {
                "schema": "gts.full-sweep-edge-artifact.v1",
                "requirement": requirement, "revision": self.rev,
                "edge_id": "submit", "source_identity": "test-fixture",
                **hashes,
                "observer_domain": "fixture-independent",
                "executor_domain": "fixture-executor",
            }
            raw = canonical(artifact)
            digest = hashlib.sha256(raw).hexdigest()
            (self.root / "artifacts" / (digest + ".json")).write_bytes(raw)
            self.records[requirement]["artifact_sha256"] = [digest]

    def tearDown(self):
        self.temp.cleanup()

    def sign_all(self):
        for name, record in self.records.items():
            evidence = ({"graph": self.graph, "attestation": record}
                        if name == GRAPH_DOMAIN else record)
            raw = canonical(evidence)
            statement = {
                "schema": WITNESS_SCHEMA, "requirement": name,
                "revision": self.rev,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "outcome": "PASS", "evidence_sha256": hashlib.sha256(raw).hexdigest(),
                "environment": "synthetic test fixture",
                "witness_id": "test-fixture-only",
            }
            sig = base64.b64encode(self.outside_key.sign(canonical(statement))).decode()
            (self.root / (name + ".evidence")).write_bytes(raw)
            (self.root / (name + ".json")).write_text(json.dumps(
                {"statement": statement, "signature": sig}))

    def verify(self):
        return check_system_closure(
            self.root, self.anchor, self.rev,
            test_only_allow_same_uid_anchor=True)

    def test_no_trust_anchor_is_never_a_pass(self):
        result, closure = check_system_closure(None, None, self.rev)
        self.assertEqual(closure["status"], "BLOCKED")
        self.assertEqual(len(result), len(MANDATORY_SYSTEM))
        self.assertTrue(all(x["status"] == "BLOCKED" for x in result.values()))

    def test_strict_complete_signed_fixture(self):
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(closure["status"], "PASS")
        self.assertEqual(closure["edges"], 1)
        self.assertTrue(all(x["status"] == "PASS" for x in result.values()))

    def test_normal_run_refuses_locally_owned_anchor(self):
        self.sign_all()
        _, result = check_system_closure(self.root, self.anchor, self.rev)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("trust-root", result["reason"])

    def test_missing_real_artifact_bytes_blocks_release(self):
        self.sign_all()
        digest = self.records["actual_runtime_wiring"]["artifact_sha256"][0]
        (self.root / "artifacts" / (digest + ".json")).unlink()
        entries, result = self.verify()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(entries["actual_runtime_wiring"]["status"], "BLOCKED")

    def test_missing_denial_receipt_bytes_blocks_release(self):
        self.sign_all()
        digest = self.records["authorization_and_credential_custody"]["artifact_sha256"][0]
        artifact = json.loads((self.root / "artifacts" / (digest + ".json")).read_bytes())
        name = artifact["negative_receipt_sha256"]
        (self.root / "receipts" / (name + ".bin")).unlink()
        entries, result = self.verify()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(entries["authorization_and_credential_custody"]["status"], "BLOCKED")

    def test_missing_one_dependency_domain_blocks_all_release(self):
        self.sign_all()
        (self.root / "actual_runtime_wiring.json").unlink()
        result, closure = self.verify()
        self.assertEqual(closure["status"], "BLOCKED")
        self.assertNotEqual(result["actual_runtime_wiring"]["status"], "PASS")

    def test_unknown_graph_edge_is_blocked(self):
        self.graph["edges"][0]["callee"] = "unaccounted-service"
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(closure["status"], "BLOCKED")
        self.assertEqual(result[GRAPH_DOMAIN]["status"], "BLOCKED")

    def test_uninstalled_node_cannot_pass(self):
        self.graph["nodes"][0]["deployed_revision"] = "c" * 40
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(closure["status"], "BLOCKED")

    def test_green_tests_do_not_override_missing_system_domains(self):
        good = {"status": "PASS", "exit_code": 0, "output_sha256": "e" * 64}
        signed_host = {
            x: {"status": "PASS", "evidence_sha256": "1" * 64}
            for x in MANDATORY_HOST
        }
        from subprocess import CompletedProcess
        def clean_git_command(args, **_kwargs):
            return CompletedProcess(args, 0,
                                    stdout=(self.rev + "\n") if "rev-parse" in args else "")
        with patch("assurance.full_sweep.execute", return_value=good), patch(
                "assurance.full_sweep.check_external_witnesses",
                return_value=signed_host), patch(
                "assurance.full_sweep.subprocess.run",
                side_effect=clean_git_command):
            result = run(witness_dir=None)
        self.assertTrue(result["working_tree_clean"])
        self.assertEqual(result["revision"], self.rev)
        self.assertFalse(result["release_authorized"])
        self.assertEqual(len(result["test_execution"]), len(TEST_GROUPS))
        self.assertEqual(len(result["required_system_evidence"]),
                         len(MANDATORY_SYSTEM))
        self.assertIn("dependency_graph_not_closed", result["blocked_dependencies"])

    def test_scope_digest_divergence_rejected(self):
        self.records["actual_runtime_wiring"]["scope_sha256"] = "0" * 64
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(result["actual_runtime_wiring"]["status"], "BLOCKED")
        self.assertEqual(closure["status"], "BLOCKED")

    def test_incomplete_edge_coverage_rejected(self):
        self.records["adversarial_mutation_and_bypass_denials"]["edge_ids"] = []
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(result["adversarial_mutation_and_bypass_denials"]["status"], "BLOCKED")
        self.assertEqual(closure["status"], "BLOCKED")

    def test_source_installed_mismatch_rejected(self):
        self.records["source_build_installed_equivalence"]["deployed_revision"] = "c" * 40
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(result["source_build_installed_equivalence"]["status"], "BLOCKED")
        self.assertEqual(closure["status"], "BLOCKED")

    def test_same_producer_and_verifier_denied(self):
        self.records["independent_evaluator_and_trust_root"]["verifier_domain"] = "test-host"
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(result["independent_evaluator_and_trust_root"]["status"], "BLOCKED")
        self.assertEqual(closure["status"], "BLOCKED")

    def test_rewritten_evidence_denied_by_signature(self):
        self.sign_all()
        target = self.root / "independent_effect_observation.evidence"
        target.write_bytes(target.read_bytes().replace(b'"PASS"', b'"FAIL"'))
        result, closure = self.verify()
        self.assertEqual(result["independent_effect_observation"]["status"], "BLOCKED")
        self.assertEqual(closure["status"], "BLOCKED")

    def test_forged_witness_with_untrusted_key_denied(self):
        self.sign_all()
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.anchor.write_bytes(other)
        result, closure = self.verify()
        self.assertEqual(closure["status"], "BLOCKED")

    def test_empty_external_artifacts_denied(self):
        self.records["restart_recovery_and_rollback"]["artifact_sha256"] = []
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(result["restart_recovery_and_rollback"]["status"], "BLOCKED")

    def test_forged_live_flag_not_enough_if_scope_has_no_edges(self):
        self.graph["edges"] = []
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(closure["status"], "BLOCKED")

    def test_extra_self_claim_fields_denied(self):
        self.records["operator_approved_release_and_remedy_reentry"]["self_certified"] = True
        self.sign_all()
        result, closure = self.verify()
        self.assertEqual(result["operator_approved_release_and_remedy_reentry"]["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
