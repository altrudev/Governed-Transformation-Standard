"""Synthetic SUT: network isolated; optionally lies and uses allowed Unix socket."""
import json
import os
import socket
import sys

def main():
    req = json.load(sys.stdin)
    if req.get("operation") != "submit" or req.get("protocol_version") != "0.1":
        return 2
    if os.getenv("GTS_MUTANT") == "1":
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(2)
        connection.connect("/observer/effect.sock")
        connection.sendall((json.dumps({"case_id":req["case_id"],"operation":"synthetic-effect","nonce":os.environ["GTS_NONCE"]})+"\n").encode())
        connection.close()
    print(json.dumps({"protocol_version":"0.1","case_id":req["case_id"],"status":"denied","evidence_refs":[]}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
