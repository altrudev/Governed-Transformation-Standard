# Governed Transformation Standard (GTS)

**A public specification for making consequential transformations inspectable, bounded, and independently verifiable.**

GTS defines a common evidence model for transformations carried out by people, software, automation, or AI-assisted systems. The standard separates what is wanted from what is authorized, what was proposed from what actually executed, and execution claims from independently observed outcomes.

Core lifecycle:

`need -> authority -> evidence -> proposed transformation -> admission -> execution -> observation -> verification -> receipt`

## Status

**Pre-release specification repository.** The standard is being developed alongside Frequency/DDC implementation work. This repository does not represent a production-certified standard and does not publish private Frequency or DDC reasoning, scoring, policy, or execution internals.

## Design invariants

- Need is not authority.
- A model or tool cannot grant itself permission.
- Consequential transitions bind to an exact predecessor state where applicable.
- Dispatch is not proof of execution.
- Execution is not proof of an acceptable outcome.
- Independent observation remains distinct from executor claims.
- Missing evidence remains missing; it is not silently converted into success.
- Later evidence may extend a record but must not rewrite what was knowable earlier.
- Public interoperability contracts are separated from proprietary implementation methods.

## Intended use

GTS is intended as a provider-neutral contract for systems that need portable evidence of governed transformations across software engineering, agent execution, infrastructure changes, documents, payments, physical actions, and other consequential workflows.

Created by **Valentyn Rukhaylo / Altru.dev**.

## External verification protocol (draft 0.1)
The [external verification protocol](docs/EXTERNAL-VERIFICATION.md) provides a public, provider-neutral testing contract. See the [adapter request schema](schemas/adapter-request.schema.json), [verification report schema](schemas/verification-report.schema.json), and [reference fixture adapter](adapters/reference/adapter.py).

The included fixture tests can be run with `python3 -m unittest discover -s tests -v`. They test the sample adapter, **not** third-party security assurance or Frequency itself.

## Technical language and project attribution
GTS uses [established technical terminology](spec/terminology.md) and a [mandatory project attribution policy](spec/project-attribution.md). A [public project registry](vocabulary/project-registry.json) identifies related Altru.dev projects without claiming they are certified or disclosing proprietary code. References to another project's specific behavior require a pinned revision and test evidence.

**Licensing note:** The repository's current licensing notice includes a CC BY-NC 4.0 restriction for specification materials; public availability is not equivalent to an OSI-approved open-source license. Review the [LICENSE](LICENSE) before reuse.

## Public examination and commercial rights
GTS is publicly inspectable; its current specification license remains CC BY-NC 4.0. This is **not** an OSI open-source claim or a general license for commercial implementations. See the [rights matrix](governance/RIGHTS-MATRIX.md) and [proposed research/testing permissions](governance/TESTING-PERMISSION.md). The latter is a draft for legal review, **not yet an operative additional license**. File-specific licenses for executable adapters must be decided separately.

## Conformance architecture
[Conformance profiles and independent assessment model](governance/CONFORMANCE-MODEL.md) distinguish syntax checks, actual conformance, adversarial assessment and genuinely external review. Current fixture tests do not certify any production system.
