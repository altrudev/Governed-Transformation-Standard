"""Read-only host custody preflight; never creates accounts or starts services."""
import json
import os
import pwd
import grp
import pathlib
import shutil
import stat

def inspect():
    names = ("gts-observer", "gts-broker")
    identities = {}
    for name in names:
        try:
            record = pwd.getpwnam(name)
            identities[name] = {"present": True, "uid": record.pw_uid,
                                "gid": record.pw_gid, "shell": record.pw_shell}
        except KeyError:
            identities[name] = {"present": False}
    distinct = (all(x["present"] for x in identities.values())
                and identities[names[0]]["uid"] != identities[names[1]]["uid"]
                and os.getuid() not in (identities[names[0]]["uid"], identities[names[1]]["uid"]))
    directories = {}
    for path in ("/run/gts-observer", "/var/lib/gts-observer"):
        p = pathlib.Path(path)
        if p.exists():
            st = p.stat()
            directories[path] = {"exists":True,"uid":st.st_uid,"gid":st.st_gid,
                                 "mode":oct(stat.S_IMODE(st.st_mode))}
        else:
            directories[path] = {"exists":False}
    return {"identities":identities,"distinct_service_uids":bool(distinct),
            "paths":directories,"systemd_available":bool(shutil.which("systemctl")),
            "ready_for_cross_account_test":bool(distinct and all(v["exists"] for v in directories.values())),
            "changes_made":False}

if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2, sort_keys=True))
