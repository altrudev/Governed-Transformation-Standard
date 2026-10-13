"""Test-only probe: cannot see observer-owned host data from isolated namespace."""
import json
import os
from pathlib import Path
paths = ["/custody/secret.key", "/home/triangulatorium/.ssh", "/observer/journal.json"]
print(json.dumps({"uid":os.getuid(),"gid":os.getgid(),
                  "visible":{p:Path(p).exists() for p in paths},
                  "tmp_writable":os.access("/tmp",os.W_OK)}))
