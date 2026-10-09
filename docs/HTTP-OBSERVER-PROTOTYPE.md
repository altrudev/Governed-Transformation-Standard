# GTS loopback HTTP observer prototype

Run `python3 -m unittest discover -s tests -q` and `python3 -m observer.http_effect_oracle`.

The fixture service listens on an ephemeral 127.0.0.1 port. The untrusted subprocess receives the service URL, but not the observer's in-memory event journal. The safe adapter claims denial with no call. A deliberately vulnerable adapter also claims denial, but sends an unauthorized synthetic effect request; the observer records that independently of the response.

**Security scope:** the fixture uses a separate HTTP server in a background thread of the runner process, not a separate OS process or separate host. It is not sandboxed; malicious local code with the runner's OS privileges could attack observation integrity. It exercises a synthetic side effect only. It provides no proof of real authorization enforcement, network isolation, independent third-party evaluation, or runtime attestation. Those require stronger process/container/user isolation, externally controlled signing keys and independent reproductions. Do not run untrusted third-party adapters on the host.

No production credentials or outside API targets are involved.
