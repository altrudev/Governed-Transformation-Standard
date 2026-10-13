# Linux sandbox fixture profile

Run `python3 -m sandbox.runner` on Linux with Bubblewrap, then `python3 -m unittest discover -s tests -q`.

The fixture runs inside a Bubblewrap mount/user/network namespace with read-only system libraries, read-only probe, private temporary storage, no host home mount and a fully disconnected network namespace. Failure to launch does not fall back to host execution.

This **is not a production-ready untrusted code runner**. It is a test-specific restricted execution configuration that assumes a trusted Python interpreter and fixture file, and does not currently specify resource limits, kernel attack surface, supply-chain controls, distinct OS-user credential separation, syscall filters or a controlled IPC link to the independent HTTP observer. Bubblewrap support varies by host. The tests must be re-run on every deployment target and must not be interpreted as universal escape resistance.

The HTTP observer test remains separate and unisolated. Integration via a controlled Unix socket or restricted proxy is a follow-up; do not enable broad network access just to connect the fixture.
