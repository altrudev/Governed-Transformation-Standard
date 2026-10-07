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
