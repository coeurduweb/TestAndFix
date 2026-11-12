#!/bin/sh
# Full install/uninstall cycle inside unprivileged containers (never on the host).
HERE=$(cd "$(dirname "$0")" && pwd)
AGENT=$(dirname "$HERE")
FAIL=0
[ $# -gt 0 ] || set -- debian:12 alpine:3.20 rockylinux:9
for img in "$@"; do
    echo "### $img"
    docker run --rm -v "$AGENT:/agent:ro" -v "$HERE:/tests:ro" "$img" sh /tests/in-container-install.sh > "${TMPDIR:-/tmp}/install-test.out" 2>&1
    cat "${TMPDIR:-/tmp}/install-test.out"
    grep -q '^RESULT PASS' "${TMPDIR:-/tmp}/install-test.out" || FAIL=1
done
exit $FAIL
