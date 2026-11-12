#!/bin/sh
# Runs INSIDE a test container (mounted read-only at /agent).
# Installs DNS daemons when a package manager exists, starts them, then runs
# flush-caches.sh in dry-run and real mode under every available shell.
# Output is a stream of "@@ ..." marker lines parsed by check_results.py.

S=/agent/flush-caches.sh
echo "@@ INFO image $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-none}")"

# ---- package installation (best effort, one package at a time) ----------
if command -v apt-get >/dev/null 2>&1; then
    PM=apt
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    PKGS="dnsmasq unbound nscd bind9 pdns-recursor knot-resolver systemd-resolved socat"
    inst() { apt-get install -y -qq --no-install-recommends "$1" >/dev/null 2>&1; }
elif command -v dnf >/dev/null 2>&1; then
    PM=dnf
    PKGS="dnsmasq unbound nscd bind bind-utils pdns-recursor knot-resolver socat"
    inst() { dnf install -y -q "$1" >/dev/null 2>&1; }
elif command -v apk >/dev/null 2>&1; then
    PM=apk
    PKGS="dnsmasq unbound bind bind-tools unscd pdns-recursor knot-resolver socat"
    inst() { apk add -q "$1" >/dev/null 2>&1; }
elif command -v pacman >/dev/null 2>&1; then
    PM=pacman
    pacman -Sy --noconfirm >/dev/null 2>&1
    PKGS="dnsmasq unbound bind pdns-recursor knot-resolver socat"
    inst() { pacman -S --noconfirm --needed "$1" >/dev/null 2>&1; }
elif command -v zypper >/dev/null 2>&1; then
    PM=zypper
    zypper -q --non-interactive refresh >/dev/null 2>&1
    PKGS="dnsmasq unbound nscd bind bind-utils pdns-recursor knot-resolver socat"
    inst() { zypper -q --non-interactive install --no-recommends "$1" >/dev/null 2>&1; }
else
    PM=none
    PKGS=""
fi
echo "@@ INFO pkgmgr $PM"
OKPKGS=""
for p in $PKGS; do
    if inst "$p"; then OKPKGS="$OKPKGS $p"; else echo "@@ INFO pkg-unavailable $p"; fi
done
echo "@@ INFO pkgs$OKPKGS"

# ---- start daemons -------------------------------------------------------
alive() {
    for d in /proc/[0-9]*; do
        read -r c < "$d/comm" 2>/dev/null || continue
        [ "$c" = "$1" ] && return 0
    done
    return 1
}
expect() { echo "@@ EXPECT $1"; }

if command -v dnsmasq >/dev/null 2>&1; then
    mkdir -p /var/lib/NetworkManager /var/lib/libvirt/dnsmasq
    printf 'port=5354\nbind-interfaces\nlisten-address=127.0.0.1\nno-resolv\nno-hosts\n' > /tmp/dnsmasq-std.conf
    printf 'port=5355\nbind-interfaces\nlisten-address=127.0.0.1\nno-resolv\nno-hosts\n' > /var/lib/NetworkManager/dnsmasq-test.conf
    printf 'port=5356\nbind-interfaces\nlisten-address=127.0.0.1\nno-resolv\nno-hosts\n' > /var/lib/libvirt/dnsmasq/default.conf
    dnsmasq --user=root --conf-file=/tmp/dnsmasq-std.conf --pid-file=/tmp/dnsmasq-std.pid >/dev/null 2>&1
    dnsmasq --user=root --conf-file=/var/lib/NetworkManager/dnsmasq-test.conf --pid-file=/tmp/dnsmasq-nm.pid >/dev/null 2>&1
    dnsmasq --user=root --conf-file=/var/lib/libvirt/dnsmasq/default.conf --pid-file=/tmp/dnsmasq-lv.pid >/dev/null 2>&1
fi

if command -v unbound >/dev/null 2>&1 && command -v unbound-control >/dev/null 2>&1; then
    cat > /tmp/unbound.conf <<'CONF'
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5353
    username: ""
    chroot: ""
    directory: "/tmp"
    pidfile: "/tmp/unbound.pid"
    use-syslog: no
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    control-use-cert: no
CONF
    unbound -c /tmp/unbound.conf >/tmp/unbound.log 2>&1
    # The script calls unbound-control without -c: point the default config at ours.
    for f in /etc/unbound/unbound.conf /usr/local/etc/unbound/unbound.conf; do
        [ -d "$(dirname "$f")" ] && cp /tmp/unbound.conf "$f"
    done
fi

if command -v named >/dev/null 2>&1 && command -v rndc >/dev/null 2>&1; then
    rndc-confgen -a >/dev/null 2>&1
    KEY=""
    for k in /etc/bind/rndc.key /etc/rndc.key /etc/named/rndc.key /etc/bind/rndc.key; do
        [ -f "$k" ] && KEY=$k && break
    done
    cat > /tmp/named.conf <<CONF
options { directory "/tmp"; listen-on port 5357 { 127.0.0.1; }; listen-on-v6 { none; }; recursion yes; pid-file "/tmp/named.pid"; };
include "$KEY";
controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; }; };
CONF
    chmod 644 "$KEY"
    named -u root -c /tmp/named.conf >/tmp/named.log 2>&1
fi

if command -v nscd >/dev/null 2>&1; then
    mkdir -p /var/run/nscd /run/nscd
    nscd >/tmp/nscd.log 2>&1
fi

if command -v pdns_recursor >/dev/null 2>&1; then
    mkdir -p /var/run/pdns-recursor /run/pdns-recursor
    pdns_recursor --daemon=no --local-port=5359 --local-address=127.0.0.1 >/tmp/pdns.log 2>&1 &
fi

if command -v kresd >/dev/null 2>&1; then
    mkdir -p /run/knot-resolver
    printf "net.listen('127.0.0.1', 5360)\n" > /tmp/kresd.conf
    kresd -n -c /tmp/kresd.conf /run/knot-resolver >/tmp/kresd.log 2>&1 &
fi

if [ -x /lib/systemd/systemd-resolved ] || [ -x /usr/lib/systemd/systemd-resolved ]; then
    mkdir -p /run/systemd/resolve
    R=/lib/systemd/systemd-resolved; [ -x "$R" ] || R=/usr/lib/systemd/systemd-resolved
    "$R" >/tmp/resolved.log 2>&1 &
fi

sleep 3
alive dnsmasq && {
    n=0; for d in /proc/[0-9]*; do read -r c < "$d/comm" 2>/dev/null; [ "$c" = dnsmasq ] && n=$((n+1)); done
    [ "$n" -ge 3 ] && { expect dnsmasq; expect dnsmasq-networkmanager; expect dnsmasq-libvirt; }
}
alive unbound && expect unbound
alive named && expect bind-named
alive nscd && expect nscd
alive pdns_recursor && expect pdns-recursor
alive kresd && expect knot-resolver
alive systemd-resolve && expect systemd-resolved

# ---- run the script ------------------------------------------------------
run() { # label shell args...
    label=$1; sh_=$2; shift 2
    echo "@@ RUN $label"
    out=$($sh_ "$S" "$@" 2>/tmp/stderr.txt); rc=$?
    echo "$out" | tail -n 1
    echo "@@ RC $rc"
}

SHELLS="sh"
command -v bash >/dev/null 2>&1 && SHELLS="$SHELLS bash"
command -v dash >/dev/null 2>&1 && SHELLS="$SHELLS dash"
command -v busybox >/dev/null 2>&1 && SHELLS="$SHELLS busybox-sh"
for sh_ in $SHELLS; do
    cmd=$sh_; [ "$sh_" = busybox-sh ] && cmd="busybox sh"
    run "dry:$sh_" "$cmd" --json --dry-run
done
run "dns-dry" sh --json --dry-run --dns-only
run "pc-dry" sh --json --dry-run --page-cache-only
run "bad-option" sh --json --bogus
run "exclusive" sh --dns-only --page-cache-only

# real run (first shell), then a second real run under another shell to show
# that already-flushed daemons are still handled.
run "real:sh" sh --json
if command -v bash >/dev/null 2>&1; then run "real:bash" bash --json; fi
run "real-dns" sh --json --dns-only
run "real-pc" sh --json --page-cache-only
echo "@@ END"
