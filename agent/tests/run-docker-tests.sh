#!/bin/sh
# Docker matrix for flush-caches.sh. Never touches the host: containers are
# unprivileged, so /proc/sys stays read-only and drop_caches is never written.
# usage: run-docker-tests.sh [image...]    (default: the full list)
HERE=$(cd "$(dirname "$0")" && pwd)
AGENT=$(dirname "$HERE")
OUT=${TMPDIR:-/tmp}/check-agent-tests
mkdir -p "$OUT"
[ $# -gt 0 ] || set -- debian:12 ubuntu:24.04 ubuntu:20.04 fedora:41 rockylinux:9 almalinux:8 alpine:3.20 archlinux opensuse/leap busybox
FAIL=0

for img in "$@"; do
    safe=$(echo "$img" | tr '/:' '__')
    docker run --rm -v "$AGENT:/agent:ro" -v "$HERE:/tests:ro" "$img" \
        sh /tests/in-container.sh > "$OUT/$safe.txt" 2>"$OUT/$safe.err"
    python3 -I "$HERE/check_results.py" "$img" "$OUT/$safe.txt" || FAIL=1
    # Non-root: dry-run allowed, real run refused with exit 3.
    docker run --rm --user 65534 -v "$AGENT:/agent:ro" "$img" sh -c '
        sh /agent/flush-caches.sh --json --dry-run >/dev/null 2>&1 || echo "FAIL nonroot dry-run rc=$?"
        sh /agent/flush-caches.sh --json >/dev/null 2>&1; rc=$?
        [ $rc = 3 ] || echo "FAIL nonroot real rc=$rc (want 3)"' | tee "$OUT/$safe.nonroot" | grep -q FAIL && { echo "FAIL $img: non-root behaviour"; FAIL=1; }
done
exit $FAIL
