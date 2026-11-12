#!/bin/bash
# Refresh the rules (exit code 1 means "no update available"), start Unbound, then spamd in the foreground.
set -u
sa-update -v; rc=$?
if [ "$rc" -gt 1 ]; then echo "sa-update failed (code $rc), keeping the rules of the image" >&2; fi
unbound -d -c /etc/unbound/unbound.conf &
for i in $(seq 1 20); do
  if timeout 2 bash -c '</dev/udp/127.0.0.1/53' 2>/dev/null; then break; fi
  sleep 0.5
done
exec spamd --listen=0.0.0.0:783 --allowed-ips="${SPAMD_ALLOWED_IPS}" \
  --max-children="${SPAMD_MAX_CHILDREN}" --nouser-config --username=debian-spamd \
  --syslog=stderr --pidfile=/run/spamd.pid "$@"
