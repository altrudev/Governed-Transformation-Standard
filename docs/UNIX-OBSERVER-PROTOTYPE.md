# Network-isolated adapter and Unix-socket effect observer

Run `python3 -m observer.unix_oracle` or `python3 -m unittest discover -s tests -v` on a compatible Linux host with Bubblewrap.

The adapter executes in a Bubblewrap sandbox with no network namespace connectivity, a read-only executable fixture and no host-home mount. Exactly one observer Unix-domain socket is bound into the sandbox at `/observer/effect.sock`. The host-side observer collects synthetic effects and ignores the adapter's self-reported denial. The faulty fixture claims `denied` while producing an observable effect; the normal fixture does not.

This proves that the controlled fixture can detect the deliberately inserted side effect over the permitted Unix socket. It does **not** prove that arbitrary untrusted code cannot escape Bubblewrap, that all file descriptors and process privileges are contained, or that the observer is controlled by an independent OS user. The observer currently executes as a thread inside the runner; same-user hostile code may compromise it. Socket protocol authentication, endpoint allowlisting, resource limits, independent observer custody, challenge nonces and independent assessor replication are not implemented. There are no production credentials or target endpoints.

No real Frequency, APS/PriorSeal or TRACE implementation is evaluated here. Third-party verification remains pending.
