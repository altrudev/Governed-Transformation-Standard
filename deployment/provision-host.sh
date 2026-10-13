#!/bin/sh
# Explicit administrator-only step. Never run automatically from tests.
set -eu
if [ "${1:-}" != "--apply" ]; then
  echo "DRY RUN: would create locked gts-observer and gts-broker system identities and protected directories."
  echo "To apply after admin review: sudo sh deployment/provision-host.sh --apply"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then echo "ERROR: requires administrator" >&2; exit 1; fi
for name in gts-observer gts-broker; do
  if getent passwd "$name" >/dev/null; then
    echo "EXISTING: $name; refusing to alter an existing account; review it manually" >&2
    exit 1
  fi
done
if [ -e /var/lib/gts-observer ] || [ -e /run/gts-observer ]; then
  echo "ERROR: existing observer paths need manual ownership review" >&2
  exit 1
fi
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gts-observer
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gts-broker
install -d -m 0700 -o gts-observer -g gts-observer /var/lib/gts-observer
echo "ACCOUNTS PROVISIONED; no keys, systemd services, or socket exposure created."
echo "Review: getent passwd gts-observer gts-broker; stat /var/lib/gts-observer"
echo "Do not automatically delete users in rollback: ownership/evidence review is mandatory."
