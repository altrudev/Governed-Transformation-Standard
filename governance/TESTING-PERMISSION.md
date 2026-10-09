# Public testing permission and disclosure policy — proposal v0.1

Copyright 2026 Valentyn Rukhaylo / Altru.dev.

This document describes the intended permission model for GTS. It is a **draft for legal review**, not a replacement for the repository LICENSE and not an authorization to test unrelated production systems.

## Permitted research — proposed additional grant
The GTS copyright holder intends to allow any person, including an independent reviewer, to download, inspect, execute, and locally modify copies of the publicly provided GTS reference test materials solely to evaluate conformance, interoperability, accessibility or security in a test environment, and to publish factual findings and reproducible minimal examples. The intent is to permit review by employees of commercial organizations without automatically granting rights to commercially exploit or redistribute GTS-based products.

The exact legal scope of this additional grant, including any conflicts with CC BY-NC 4.0, must be approved in a separately published signed license amendment. **Until then, this paragraph is a design proposal, not a new operative license grant.** Existing CC BY-NC 4.0 and any file-specific terms remain controlling.

## Boundaries
No production penetration testing, access to third-party services, extraction of confidential material, credential use, bypass of others' access controls or denial-of-service testing is authorized by GTS. GTS's publication does not license proprietary Frequency/DDC source, patented claims, logos, trademarks or certification marks. No commercial deployment, rebranding as official GTS certification, sublicensing or paid resale of protected GTS material is granted by this draft.

Researchers may publish accurate negative findings, including proof that a GTS test is ineffective. Coordinated disclosure is requested for vulnerabilities affecting real deployed systems; public disclosure of test-harness defects is permitted provided it does not expose private credentials or exploitable production secrets.

## Commercial boundary questions for counsel
1. Should a limited commercial-entity research/testing exception be issued alongside CC BY-NC?
2. What license applies to public software adapters and executable test harnesses? CC BY-NC is not recommended as a software code license.
3. Do independently developed compatible implementations require an explicit patent license or defensive patent policy?
4. Which rights are reserved for commercial implementations, trademarks and independent certification providers?
5. How may external contributors license their submissions without an inadvertent rights transfer?

This model aims for auditability and third-party research, with implementation commercialization handled by separate agreement.
