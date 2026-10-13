"""Bounded negative test for user-namespace and mount separation."""
import json
import pathlib
import subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
PROBE=ROOT/"fixtures"/"custody_probe.py"
def assess():
    cmd=["bwrap","--die-with-parent","--unshare-all","--uid","65534","--gid","65534",
         "--ro-bind","/usr","/usr","--ro-bind","/lib","/lib",
         "--ro-bind","/lib64","/lib64","--proc","/proc","--dev","/dev",
         "--tmpfs","/tmp","--tmpfs","/home",
         "--ro-bind",str(PROBE),"/probe.py","/usr/bin/python3","/probe.py"]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=8)
    if p.returncode:
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout)
if __name__=="__main__":
    print(json.dumps(assess(),sort_keys=True))
