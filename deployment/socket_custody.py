"""Read-only service identity and Unix socket filesystem custody preflight.

Checking metadata cannot establish authorization correctness: actual Linux
SO_PEERCRED access-denial tests must be performed independently.
"""
import json
import grp
from pathlib import Path
import pwd
import stat

PATHS = (
    ("/run/gts-issuer", "gts-observer", "gts-evaluator", 0o710, "directory"),
    ("/run/gts-issuer/issue.sock", "gts-observer", "gts-evaluator", 0o660, "socket"),
    ("/run/gts-broker-delivery", "gts-broker", "gts-evaluator", 0o710, "directory"),
    ("/run/gts-broker-delivery/deliver.sock", "gts-broker", "gts-evaluator", 0o660, "socket"),
    ("/run/gts-observer", "gts-observer", "gts-broker", 0o710, "directory"),
    ("/run/gts-observer/observer.sock", "gts-observer", "gts-broker", 0o660, "socket"),
)


def inspect(paths=PATHS):
    checked = []
    for path, owner_name, group_name, expected_mode, kind in paths:
        record = {"path":str(path), "expected_owner":owner_name,
                  "expected_group":group_name, "expected_mode":oct(expected_mode),
                  "expected_kind":kind, "qualified":False}
        try:
            owner = pwd.getpwnam(owner_name).pw_uid
            group = grp.getgrnam(group_name).gr_gid
            st = Path(path).lstat()
            record["exists"] = True
            record["owner_match"] = st.st_uid == owner
            record["group_match"] = st.st_gid == group
            record["mode_match"] = stat.S_IMODE(st.st_mode) == expected_mode
            record["kind_match"] = (
                stat.S_ISDIR(st.st_mode) if kind == "directory"
                else stat.S_ISSOCK(st.st_mode) if kind == "socket"
                else False
            )
            record["qualified"] = all(record[x] for x in
                                      ("owner_match","group_match","mode_match","kind_match"))
        except (OSError, KeyError, ValueError):
            record["exists"] = False
        checked.append(record)
    return {"all_socket_custody_prerequisites":all(x["qualified"] for x in checked),
            "checks":checked, "credential_contents_accessed":False,
            "mutated_host_state":False, "cross_account_protocol_qualified":False}


if __name__ == "__main__":
    print(json.dumps(inspect(), sort_keys=True, indent=2))
