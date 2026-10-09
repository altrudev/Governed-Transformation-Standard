# Project references, attribution and provenance policy — GTS draft 0.1

## Applicability
These rules apply to GTS and SHOULD be reused by subsequent Altru.dev projects, repositories, public adapters, benchmark reports, standards crosswalks and technical documentation.

## Mandatory identification
When a project or artifact is named as an implementation, influence, adapter source, research origin or prior art, public material MUST:
1. Use its exact repository or publication title, canonical URL and owning organization/author if independently confirmed.
2. State the relationship precisely: `implementation`, `adapter`, `test subject`, `prior art`, `inspiration`, `research origin`, `external standard`, or `planned integration`.
3. Distinguish software implementation from a specification, prototype, conceptual architecture, or research hypothesis.
4. Pin a commit SHA, version, DOI or content digest for technical claims about specific behavior. Unpinned project links are navigation only.
5. Link a source-file path and test/receipt reference when asserting that an implementation satisfies a control.
6. Preserve author credits and correct licenses; do not imply permissive use because a repository is public.
7. Make clear that the GTS standard does not certify or endorse a named project unless a separate scoped independent review exists.
8. Never reveal private repository contents, secret endpoints, signing material or proprietary source solely to justify attribution.

## Ownership boundary
GTS and DDC/Frequency are related initiatives, not interchangeable modules. The open GTS protocol MUST remain independently implementable without private DDC/Frequency code. Project attribution does NOT transfer ownership, imply a patent license, or assign proprietary methods to the GTS public specification.

## Citation format
Use a stable entry ID from `vocabulary/project-registry.json` and include:

```yaml
project_ref: altrudev.frequency
relation: test_subject
revision: "<commit-sha-if-claim-is-version-specific>"
component: "<path-or-public-interface>"
claim: "<measurable statement>"
evidence: "<independent-result-reference-or-unverified>"
```

If the revision, code path or evidence is missing, state `unverified` rather than substituting a general project homepage.

## License caveat
The existing GTS repository licensing notice applies CC BY-NC 4.0 to specification material. Public visibility therefore does not, by itself, make all GTS materials open-source under OSI criteria. Licensing changes require a separate owner decision and review; adapter code must disclose its own license before redistribution.

## Outside contributors
Attribute external work to the original contributor and upstream project; identify derivative or independently created work; include applicable copyright/license notices and pinned upstream revisions. External vocabulary registries are mappings, not higher normative authority than recognized standards.
