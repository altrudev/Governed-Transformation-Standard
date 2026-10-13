# Broker challenge authority — unresolved integration contract

The current observer accepts kernel-verified broker UID and a configured challenge. The bearer challenge must not be exported to a sandboxed subject. However, there is **no implemented trusted mechanism** for a real broker process to obtain or mint challenge-scoped authority. Consequently the systemd unit must not be installed as an operational assurance service.

Required redesign:
- Observer or independently controlled evaluator creates unpredictable, single-use, purpose-bound challenge IDs; never accept SUT-generated challenges as authority.
- Broker is an independently deployed process with its own OS identity, not user-provided input or an untrusted adapter subprocess.
- Broker forwards only an allowlisted synthetic effect request bound to a previously issued challenge; kernel peer credentials authenticate the broker process but cannot prove user intent.
- Observer alone validates issuance, scope, deadline, nonce consumption and event observations; deny unknown, expired and duplicate challenges.
- Observer journal and signing identity are held by the observer principal and not accessible to broker or adapter.
- A real cross-account test must prove broker can connect and cannot read observer files, while adapter cannot access broker/observer sockets directly.

No current component implements this end-to-end issuance protocol. No third-party trust claims or production execution should depend on the demo receiver.
