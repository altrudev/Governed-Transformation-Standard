# External effect oracle — prototype

Run `python3 -m unittest discover -s tests -v` and `python3 -m runner.external_effect_test`.

A synthetic adapter reports `denied` in BOTH versions. The deliberately vulnerable version nevertheless writes an effect file. The test runner checks the file directly, rather than accepting the adapter's response. If the result changes when the effect observation is disabled, the oracle has established sensitivity to this deliberately introduced defect.

**Limits:** both processes run on the same owner-controlled host; the adapter receives the fixture directory path. This is an internal test fixture, not a secure isolation boundary, proof of independence, third-party assessment, general authorization verifier, or product certification. The fixture has no network access by design (it never initiates requests), but the harness does not sandbox system calls or network access. No real Frequency, TRACE or APS adapters were tested.

Next: move fixture side effects to a separate observer-controlled HTTP server or independent process with a strict sandbox, publish signed raw evidence and repeat with a truly external reviewer.
