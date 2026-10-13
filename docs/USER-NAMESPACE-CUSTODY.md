# User-namespace custody check — internal fixture
The Bubblewrap adapter now runs as UID/GID 65534 inside a user namespace with a constrained mount view and no general networking. A custody probe checks that sampled paths for an observer key, observer journal and host SSH data are not exposed in that view. The socket-based synthetic effect detector continues to function.

**Scope:** UID 65534 is a namespace identity, not proof of a separately administered host OS principal. No real production keys were read, opened or moved. Path-invisibility tests are not an exhaustive filesystem attack assessment. The observer and its signing material still require isolation under separate host credentials, securely provisioned key custody and external trust roots before any independent-assurance claim.
