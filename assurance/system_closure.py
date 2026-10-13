"""Universal full-sweep release rule: signed evidence must close the live graph.

A local PASS does not qualify deployment. The independently enrolled trust
anchor and independently witnessed source/effect evidence remain mandatory.
"""
import hashlib
import json
from pathlib import Path
import os
import re
import stat

from assurance.witness import canonical, check_external_witnesses

SCHEMA = "gts.full-sweep-domain.v1"
GRAPH_SCHEMA = "gts.full-sweep-dependency-graph.v1"
MANDATORY_SYSTEM = (
    "scope_inventory",
    "dependency_graph_and_adapter_closure",
    "source_build_installed_equivalence",
    "authorization_and_credential_custody",
    "actual_runtime_wiring",
    "independent_effect_observation",
    "adversarial_mutation_and_bypass_denials",
    "restart_recovery_and_rollback",
    "provenance_retention_and_data_boundary",
    "independent_evaluator_and_trust_root",
    "operator_approved_release_and_remedy_reentry",
)
GRAPH_DOMAIN = MANDATORY_SYSTEM[1]
REQUIRED = {
    "schema", "requirement", "revision", "deployed_revision",
    "scope_sha256", "environment", "run_id", "producer_domain",
    "verifier_domain", "edge_ids", "artifact_sha256", "result",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}$")


def _denied(reason):
    return {"status": "BLOCKED", "reason": reason}


def _independent_anchor_custody(path):
    # A proof whose public-trust root can be swapped by the evaluated account
    # is not independent of that account. Check every ancestor as well.
    if path is None:
        return False
    p = Path(path)
    if not p.is_absolute():
        return False
    try:
        for entry in (p, *p.parents):
            info = entry.lstat()
            if (stat.S_ISLNK(info.st_mode)
                    or info.st_uid == os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o022):
                return False
        info = p.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_size == 32)
    except OSError:
        return False


def _validate_artifacts(directory, record, *, requirement, revision, edge_ids):
    """Check the bytes behind every digest, not just hex-looking filenames."""
    covered = set()
    for digest in record["artifact_sha256"]:
        file = directory / "artifacts" / (digest + ".json")
        if file.is_symlink() or not file.is_file():
            raise ValueError("referenced evidence artifact not present")
        raw = file.read_bytes()
        if (len(raw) > 1_000_000 or not raw
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError("artifact hash mismatch")
        artifact = json.loads(raw)
        if not isinstance(artifact, dict) or set(artifact) != {
            "schema", "requirement", "revision", "edge_id", "source_identity",
            "positive_receipt_sha256", "negative_receipt_sha256",
            "observed_effect_sha256", "observer_domain", "executor_domain"
        }:
            raise ValueError("concrete positive/negative effect receipt required")
        if (artifact["schema"] != "gts.full-sweep-edge-artifact.v1"
                or artifact["requirement"] != requirement
                or artifact["revision"] != revision
                or artifact["edge_id"] not in edge_ids
                or artifact["edge_id"] in covered
                or not isinstance(artifact["source_identity"], str)
                or not NAME.fullmatch(artifact["source_identity"])
                or not isinstance(artifact["observer_domain"], str)
                or not NAME.fullmatch(artifact["observer_domain"])
                or not isinstance(artifact["executor_domain"], str)
                or not NAME.fullmatch(artifact["executor_domain"])
                or artifact["observer_domain"] == artifact["executor_domain"]
                or any(not isinstance(artifact[k], str) or not HEX64.fullmatch(artifact[k])
                       for k in ("positive_receipt_sha256",
                                 "negative_receipt_sha256", "observed_effect_sha256"))):
            raise ValueError("artifact does not independently bind tested edge")
        # A signed claim that embeds only hashes of nonexistent observations
        # is NOT measured evidence. Require corresponding bounded raw bytes.
        for kind in ("positive_receipt_sha256", "negative_receipt_sha256",
                     "observed_effect_sha256"):
            receipt_digest = artifact[kind]
            receipt = directory / "receipts" / (receipt_digest + ".bin")
            if receipt.is_symlink() or not receipt.is_file():
                raise ValueError("positive/negative/effect receipt bytes missing")
            if receipt.stat().st_size < 1 or receipt.stat().st_size > 1_000_000:
                raise ValueError("receipt size not bounded")
            if hashlib.sha256(receipt.read_bytes()).hexdigest() != receipt_digest:
                raise ValueError("receipt content does not match signed digest")
        covered.add(artifact["edge_id"])
    if covered != edge_ids:
        raise ValueError("at least one edge lacks concrete effect/denial evidence")


def validate_graph(graph, revision):
    """Require a closed, explicitly wired, nonempty scope/edge inventory."""
    if not isinstance(graph, dict) or set(graph) != {
        "schema", "revision", "nodes", "edges"
    }:
        raise ValueError("dependency graph missing mandatory fields")
    if graph["schema"] != GRAPH_SCHEMA or graph["revision"] != revision:
        raise ValueError("dependency graph version/revision mismatch")
    nodes = graph["nodes"]
    edges = graph["edges"]
    if (not isinstance(nodes, list) or not 1 <= len(nodes) <= 2048
            or not isinstance(edges, list) or not 1 <= len(edges) <= 8192):
        raise ValueError("empty, invalid or unbounded dependency inventory")
    node_ids = set()
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {
            "id", "source_revision", "deployed_revision", "authority_domain"
        }:
            raise ValueError("incomplete node source/deployment identity")
        if (not isinstance(node["id"], str) or not NAME.fullmatch(node["id"])
                or node["id"] in node_ids or
                not isinstance(node["source_revision"], str)
                or not HEX40.fullmatch(node["source_revision"])
                or node["source_revision"] != node["deployed_revision"]
                or not isinstance(node["authority_domain"], str)
                or not NAME.fullmatch(node["authority_domain"])):
            raise ValueError("node identity not verified as deployed")
        node_ids.add(node["id"])
    edge_ids = set()
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {
            "id", "caller", "callee", "authorization_point",
            "effect_point", "observer_point",
        }:
            raise ValueError("incomplete control-flow/effect edge")
        if (not isinstance(edge["id"], str) or not NAME.fullmatch(edge["id"])
                or edge["id"] in edge_ids or
                edge["caller"] not in node_ids or edge["callee"] not in node_ids
                or any(not isinstance(edge[field], str) or
                       not NAME.fullmatch(edge[field]) for field in (
                        "authorization_point", "effect_point", "observer_point"))):
            raise ValueError("unresolved/invalid graph edge")
        edge_ids.add(edge["id"])
    return edge_ids, hashlib.sha256(canonical(graph)).hexdigest()


def _read_json_exact(path):
    data = Path(path).read_bytes()
    if not 1 <= len(data) <= 2_000_000:
        raise ValueError("evidence missing or oversized")
    parsed = json.loads(data)
    if not isinstance(parsed, dict):
        raise ValueError("evidence must be an object")
    return parsed


def _validate_record(evidence, *, requirement, revision, scope_hash, edge_ids):
    if not isinstance(evidence, dict) or set(evidence) != REQUIRED:
        raise ValueError("missing/misleading full-sweep evidence fields")
    if (evidence["schema"] != SCHEMA or evidence["requirement"] != requirement
            or evidence["revision"] != revision
            or evidence["deployed_revision"] != revision
            or evidence["scope_sha256"] != scope_hash
            or evidence["environment"] != "live"
            or evidence["result"] != "PASS"):
        raise ValueError("source, deployment, scope or environment mismatch")
    for field in ("run_id", "producer_domain", "verifier_domain"):
        if not isinstance(evidence[field], str) or not NAME.fullmatch(evidence[field]):
            raise ValueError("invalid run/provenance identity")
    if evidence["producer_domain"] == evidence["verifier_domain"]:
        raise ValueError("self-certification not permitted")
    covered = evidence["edge_ids"]
    if (not isinstance(covered, list) or len(covered) != len(edge_ids)
            or len(set(covered)) != len(edge_ids)
            or set(covered) != edge_ids):
        raise ValueError("not every declared dependency edge was exercised")
    artifacts = evidence["artifact_sha256"]
    if (not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 1024
            or any(not isinstance(x, str) or not HEX64.fullmatch(x) for x in artifacts)
            or len(set(artifacts)) != len(artifacts)):
        raise ValueError("missing or invalid immutable observation artifacts")


def check_system_closure(directory, trust_anchor, revision, *, test_only_allow_same_uid_anchor=False):
    """Signed mandatory domains + closed live graph; fail-closed by default.

    The trust-anchor holder must be outside the evaluated system's authority.
    This function cannot independently establish the custodian's independence.
    """
    results = {r: _denied("Independent scoped live evidence missing")
               for r in MANDATORY_SYSTEM}
    if not directory or not trust_anchor or not isinstance(revision, str) or not HEX40.fullmatch(revision):
        return results, {"status": "BLOCKED", "reason": "No independent live sweep enrollment"}
    if not test_only_allow_same_uid_anchor and not _independent_anchor_custody(trust_anchor):
        return results, {"status": "BLOCKED",
                         "reason": "No independently administered trust-root custody"}
    directory = Path(directory)
    signed = check_external_witnesses(
        directory, trust_anchor, MANDATORY_SYSTEM, revision)
    # A signed inventory alone is not enough: inventory must contain a
    # closed nonempty dependency graph and must be bound across all domains.
    if signed[GRAPH_DOMAIN]["status"] != "PASS":
        results[GRAPH_DOMAIN] = _denied("Signed dependency graph witness missing or invalid")
        return results, {"status": "BLOCKED", "reason": "Dependency graph not independently witnessed"}
    try:
        source = _read_json_exact(directory / (GRAPH_DOMAIN + ".evidence"))
        if set(source) != {"graph", "attestation"}:
            raise ValueError("graph/attestation envelope required")
        graph_edges, scope_hash = validate_graph(source["graph"], revision)
        _validate_record(source["attestation"], requirement=GRAPH_DOMAIN,
                         revision=revision, scope_hash=scope_hash,
                         edge_ids=graph_edges)
        _validate_artifacts(directory, source["attestation"],
                            requirement=GRAPH_DOMAIN, revision=revision,
                            edge_ids=graph_edges)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        results[GRAPH_DOMAIN] = _denied("Invalid dependency closure: " + str(exc))
        return results, {"status": "BLOCKED", "reason": "Unverifiable dependency closure"}
    results[GRAPH_DOMAIN] = {
        "status": "PASS", "scope_sha256": scope_hash, "edges": len(graph_edges),
        "witness_evidence_sha256": signed[GRAPH_DOMAIN]["evidence_sha256"],
    }
    for requirement in MANDATORY_SYSTEM:
        if requirement == GRAPH_DOMAIN:
            continue
        if signed[requirement]["status"] != "PASS":
            continue
        try:
            record = _read_json_exact(directory / (requirement + ".evidence"))
            _validate_record(record, requirement=requirement, revision=revision,
                             scope_hash=scope_hash, edge_ids=graph_edges)
            _validate_artifacts(directory, record, requirement=requirement,
                                revision=revision, edge_ids=graph_edges)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            results[requirement] = _denied("Unverifiable domain evidence: " + str(exc))
            continue
        results[requirement] = {
            "status": "PASS", "scope_sha256": scope_hash,
            "edges": len(graph_edges),
            "witness_evidence_sha256": signed[requirement]["evidence_sha256"],
        }
    complete = all(x["status"] == "PASS" for x in results.values())
    return results, {
        "status": "PASS" if complete else "BLOCKED",
        "scope_sha256": scope_hash,
        "nodes": len(source["graph"]["nodes"]), "edges": len(graph_edges),
        "unverified_domains": [
            key for key, item in results.items() if item["status"] != "PASS"
        ],
        "limitations": [
            "An independently supplied verifier key and witnessed evidence do not prove absence of unknown bugs.",
            "Production scope completeness and verifier independence require external operator validation.",
        ],
    }
