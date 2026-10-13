"""Only synthetic event delivery via provisioned evaluator identity.

This records a local synthetic receipt; it is NOT independent effect or
release acceptance evidence. Neither credentials nor tokens are printed.
"""
import argparse
import json
import os
import pwd
import re

from observer.issuance import request_challenge
from broker.delivery import deliver

ISSUER = "/run/gts-issuer/issue.sock"
BROKER = "/run/gts-broker-delivery/deliver.sock"
CASE_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def perform(case_id, *, issuer_socket=ISSUER, delivery_socket=BROKER):
    if not isinstance(case_id, str) or not CASE_RE.fullmatch(case_id):
        raise ValueError("invalid synthetic case ID")
    evaluator = pwd.getpwnam("gts-evaluator").pw_uid
    if (evaluator != os.geteuid()
            or len({evaluator, pwd.getpwnam("gts-observer").pw_uid,
                    pwd.getpwnam("gts-broker").pw_uid}) != 3):
        raise PermissionError("dedicated evaluator process identity required")
    challenge = request_challenge(issuer_socket, case_id)
    deliver(delivery_socket, {"case_id": case_id, "operation": "synthetic-effect",
                              "challenge": challenge})
    return {"schema": "gts.synthetic-delivery-ack.v1", "case_id": case_id,
            "delivery_acknowledged": True,
            "independent_observation_verified": False,
            "release_authority": "NONE"}


def main():
    parser = argparse.ArgumentParser(description="GTS controlled synthetic delivery")
    parser.add_argument("--case-id", required=True)
    case_id = parser.parse_args().case_id
    print(json.dumps(perform(case_id), sort_keys=True))


if __name__ == "__main__":
    main()
