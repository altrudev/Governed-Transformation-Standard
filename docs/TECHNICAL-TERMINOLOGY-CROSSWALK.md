# Altru / DDC / Frequency / GTS terminology crosswalk

**Purpose:** translate project-specific terminology into established technical language without renaming existing concepts or claiming equivalence where none is demonstrated.

**Interpretation:** “Comparable term” gives the closest conventional vocabulary, not certification, formal conformance, novelty, or proof of implementation. Composite Altru concepts can combine multiple standard primitives. Terms used across other repositories are included for interoperability; this file does **not** audit their implementation.

| Project term | Comparable standard technical terminology | Boundaries / explanation |
|---|---|---|
| DDC (project/program) | Software assurance and controlled execution framework | Project name, not an industry standard |
| Frequency / FDDCRF-EVO | Security assurance orchestration; continuous verification workflow | Project architecture, not a recognized protocol |
| GTS / Governed Transformation Standard | Policy-enforced transformation protocol and assurance specification | Proposed project standard, not standards-body endorsement |
| Full sweep | Multi-layer security architecture review, integration testing, adversarial assessment, and release assurance audit | Requires scoped evidence; never proves absence of bugs |
| Independent Assurance Fabric | Federated third-party attestation and evidence-verification architecture | Independence must be tested across administrative trust boundaries |
| Authority Envelope | Signed/bound authorization context; attenuated capability / authorization grant | Context alone is not enforceable without mandatory checks |
| Capability Lattice | Partial order of permissions and capability attenuation | Mathematical lattice properties require proof, not naming |
| Policy IR | Intermediate representation of authorization policy | Compare to policy-as-code, AST/IR, OPA/Rego evaluation |
| PolicyDecision | Authorization decision record | Permit/deny is not proof that action was gated |
| CounterexamplePath | Counterexample trace / policy violation witness | Must represent a reproducible execution path |
| Guardian | Reference monitor / policy enforcement point (PEP) | Requires complete mediation and tamper resistance |
| Action Gateway | Security enforcement proxy / PEP / execution mediation point | Must intercept all protected operations |
| Reasoning Gateway | Model input/output policy mediation / inference-time guardrail | Not a guarantee of model reasoning integrity |
| Credential Broker | Privileged secret broker / delegated credential service | Scope binding, isolation, and secret lifecycle matter |
| FlowAuthorityDecision | Information-flow authorization decision / data-use policy decision | Must bind data, purpose, recipient, and cumulative releases |
| Observed-flow enforcement | Runtime information-flow monitoring / provenance-aware disclosure control | Mechanism needs actual source-to-sink monitoring |
| Dual receipts | Independent attestations / two-party evidence records | Two receipts from same trust domain are not independent |
| Independent observation | Out-of-band measurement by independent observer | Merely repeating subject declarations is not independent |
| Evidence anchor | Cryptographic digest commitment / external transparency anchor | A hash by itself does not provide independent custody |
| Evidence custody | Chain of custody / tamper-evident append-only log | Hash chaining alone is rewriteable without an external anchor |
| Witness receipt | Attestation record / signed measurement statement | Trust depends on witness independence and key protection |
| Trusted evidence verifier | Signature verification against externally pinned trust anchor | Signature proves key use, not factual truth of measurement |
| Challenge authority | Nonce issuance and scope-bound authorization state | Issuer authentication and replay durability are separate controls |
| Per-case challenge | Purpose-bound one-time token / challenge-response nonce | A bearer token can be stolen; it is not identity verification |
| Broker-to-observer socket | AF_UNIX IPC with kernel peer-credential checks (SO_PEERCRED) | User IDs are host-scoped and do not establish request intent |
| Observer journal | Durable event log / hash-chained audit log | fsync does not ensure independent or immutable evidence |
| Signed raw journal | Digitally signed audit/event log | Ensure canonicalization, trust anchoring and truncation detection |
| Replay protection | Anti-replay nonce ledger / idempotency and consumed-token state | Restart and concurrent request behavior must be checked |
| Drift engine | Runtime configuration/policy drift detection | Predictive assertions require tested baseline models |
| Predictive Authority Simulation | Pre-execution policy evaluation / authorization what-if analysis | Simulation cannot replace runtime enforcement |
| Data provenance | Data lineage / source attribution / provenance metadata | Cryptographic provenance needs verifiable binding |
| Sting Protocol | Behavioral anomaly analysis with multi-event evidence | Internal name, not a public industry protocol |
| Radial lenses | Multi-perspective analysis / ensemble assurance checks | Labels do not imply independence of detectors |
| HIO | Human-computer interaction (HCI), accessibility and usability engineering | Project method; empirical validation required |
| Companion | Human-in-the-loop (HITL) agent assistance | Human approval must be appropriately authenticated and scoped |
| Frequency Conduit | Restricted remote execution/control-plane mediation | Subject to endpoint, credential and transport threats |
| DDCRE | Sandboxed execution environment / least-privilege runtime | Isolation strength depends on kernel and configuration |
| Federation edge pack | Interoperability adapter and conformance fixture bundle | Fixtures are not a live federation test |
| APS (agent passport) | Agent identity/credential assertions and attestations | Verify actual upstream semantics and signatures |
| PriorSeal | Evidence provenance / prior-commitment sealing | Project-specific mechanism; no assumed standardized equivalence |
| Agent execution assurance | Runtime action authorization and attestation | A record is not enforcement |
| TRACE integration | Agent execution trace / telemetry and conformance integration | External program semantics must be confirmed independently |
| Repo-Proof | Repository integrity and provenance verification | Commit integrity != shipped artifact integrity |
| AgentPay proof | Payment authorization/settlement receipt verification | Requires chain confirmation and purpose binding |
| x402 rail | HTTP payment-required protocol integration | Conformance depends on exact x402 version |
| SolSynth | Solution synthesis, design-space exploration and constraint optimization | Product name; not a standard algorithm |
| ACIR | Canonical intermediate representation for layout/capabilities | Custom IR; not interchange-conformant by naming |
| Test-first / Output QA | Test-driven development and validation of deliverables | Test design quality remains essential |
| Perun | Internal audit command/workflow name | Must document exactly what checks actually ran |

## Standards vocabulary and verification references

- NIST SP 800-53 (access control, audit, system integrity); NIST SP 800-207 (zero-trust architecture).
- NIST SP 800-218 SSDF (secure development); NIST SP 800-61 (incident handling).
- IETF RFC 8785 (JSON canonicalization scheme / JCS); RFC 8032 (EdDSA); RFC 7519 (JWT, only if JWT used).
- IETF RFC 6962 and successors (transparency-log principles); in-toto and SLSA (supply-chain attestations and provenance).
- OWASP ASVS and threat modeling; CWE/CAPEC for weakness/attack classification.
- Linux AF_UNIX / SO_PEERCRED, Unix discretionary access control, systemd credentials and sandboxing.
- W3C PROV (provenance model); Open Policy Agent (OPA) for policy evaluation comparisons.

References here are **orientation**, not claims that GTS implements or conforms to them. Specific normative mappings require clause-level, version-pinned conformance evidence.
