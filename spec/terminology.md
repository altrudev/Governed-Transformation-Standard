# Technical terminology and naming policy — GTS draft 0.1

GTS implementation contracts MUST use established terms in software security, authorization, distributed systems and software testing whenever an equivalent term exists. The meaning of a term depends on demonstrable behavior, not a product name.

## Core terms (descriptive, unless tied to an explicit conformance requirement)

| Term | Technical meaning | Normative reference / orientation |
|---|---|---|
| Principal | Entity whose authorization is evaluated | NIST SP 800-162 (ABAC) |
| Policy decision point (PDP) | Evaluates authorization rules and returns a policy decision | OASIS XACML 3.0 / NIST SP 800-162 concepts |
| Policy enforcement point (PEP) | Enforces a decision at a real operation boundary | OASIS XACML 3.0 |
| Scope attenuation | Constraining delegated authority so it cannot exceed its source grant | Authorization/delegation model; formal semantics MUST be specified by profile |
| Cryptographic signature verification | Verifying a message and signature using the expected public key | RFC 8032 (EdDSA); algorithm/profile dependent |
| Issuer authentication | Establishing that an accepted statement came from an authorized issuer | Trust anchors and credential validation profile required |
| Provenance | Information about origin and derivation of an artifact | W3C PROV; SLSA/in-toto for software supply chain contexts |
| Integrity | Detection of unintended or unauthorized alteration | NIST glossary and applicable cryptographic primitives |
| Idempotency | Repeat application has the same defined effect, within stated scope | HTTP Semantics RFC 9110 section 9.2.2 |
| Replay protection | Preventing reuse of a previously valid authorization/message | Protocol-specific state, freshness and uniqueness rules |
| Test oracle | Mechanism determining expected behavior for a test | Software testing terminology (ISO/IEC/IEEE 29119 series) |
| Mutation testing | Introducing a controlled defect to assess test sensitivity | Software testing technique; not independent security proof |
| Independent observation | Outcome measurement from an observer outside the SUT-controlled claim channel | GTS-defined profile term, NOT a blanket industry certification |

References provide terminology context; they do not automatically establish that GTS implements the referenced standard. Exact versions and clauses should be recorded in a separately reviewed references registry before a requirement is called standards-conformant.

## Naming and claims
1. Public APIs MUST describe observable behavior (e.g. `verify_signature`, `check_policy`, `read_audit_log`) rather than unproved properties (e.g. `guarantee_trust`).
2. A check of schema shape, hash equality or a caller-supplied PASS is NOT authorization enforcement or independent verification.
3. Brand and research terms MAY appear in explanatory material, but MUST link to the project registry and clearly distinguish the term from its actual standardized technical counterpart.
4. When no established equivalent exists, mark the new term `GTS-defined`, state an operational definition and counterexample, and document its distinction from prior art.
5. Claims of standards compliance MUST identify a pinned standard, clause, test profile, and external evidence where applicable.
