#!/bin/sh
# Privileged, explicit, one-time operator decision. Dry-run by default.
# It does NOT provision keys, release authority, or enable services.
set -eu
if [ "${1:-}" != "--apply" ]; then
  echo "DRY RUN: verify observer/broker UIDs and create a locked, dedicated gts-evaluator OS account."
  echo "No keys, services, privileges, groups, or socket ACLs are installed by this script."
  echo "Apply only after review: sudo sh deployment/provision-evaluator.sh --apply"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: administrator identity is required" >&2
  exit 1
fi
for name in gts-observer gts-broker; do
  if ! getent passwd "$name" >/dev/null; then
    echo "ERROR: required account $name is missing; review existing host first" >&2
    exit 1
  fi
done
if getent passwd gts-evaluator >/dev/null || getent group gts-evaluator >/dev/null; then
  echo "ERROR: evaluator identity already exists; review manually rather than changing it" >&2
  exit 1
fi
observer_uid=$(id -u gts-observer)
broker_uid=$(id -u gts-broker)
if [ "$observer_uid" -eq "$broker_uid" ]; then
  echo "ERROR: broker and observer must have different OS identities" >&2
  exit 1
fi
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gts-evaluator
evaluator_uid=$(id -u gts-evaluator)
if [ "$evaluator_uid" -eq "$observer_uid" ] || [ "$evaluator_uid" -eq "$broker_uid" ]; then
  echo "ERROR: non-distinct account allocated; stop and manually investigate" >&2
  exit 1
fi
echo "Evaluator account created with distinct UID. No socket, token, key or service enabled."
echo "Operator must separately provision observer-owned issuer directory grouped to gts-evaluator,"
echo "broker-owned delivery directory grouped to gts-evaluator, and protect all key material."
echo "Do not delete the identity automatically during rollback: retained evidence may reference its UID."
