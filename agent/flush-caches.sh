#!/bin/sh
# flush-caches.sh - flush every local DNS cache and the kernel page cache.
#
# POSIX sh only (tested with dash, busybox ash, bash). Run as root.
#
# Usage: flush-caches.sh [--dns-only | --page-cache-only] [--dry-run] [--json]
#
# Exit codes:
#   0  success (daemons that are absent or skipped do not count as failures)
#   1  at least one detected cache could not be flushed
#   2  invalid usage
#   3  not running as root (and not --dry-run)
#
# Safety: this script only clears caches. It never edits configuration,
# never stops a service for good, and only restarts a daemon as a last
# resort when the daemon is running and has no flush command.

VERSION=1

DRY=0
JSON=0
DO_DNS=1
DO_PC=1

usage() {
    cat <<USAGE
Usage: $0 [--dns-only | --page-cache-only] [--dry-run] [--json]

  --dns-only         flush DNS caches only
  --page-cache-only  drop the kernel page cache only
  --dry-run          detect and report, change nothing
  --json             print human log on stderr and one final JSON line on stdout
  -h, --help         this help

Exit codes: 0 ok, 1 a flush failed, 2 usage error, 3 not root.
USAGE
}

for _a in "$@"; do
    case "$_a" in
        --dns-only) DO_PC=0 ;;
        --page-cache-only) DO_DNS=0 ;;
        --dry-run) DRY=1 ;;
        --json) JSON=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $_a" >&2; usage >&2; exit 2 ;;
    esac
done
if [ "$DO_DNS" = 0 ] && [ "$DO_PC" = 0 ]; then
    echo "--dns-only and --page-cache-only are mutually exclusive" >&2
    exit 2
fi

if [ "$DRY" = 0 ] && [ "$(id -u 2>/dev/null)" != 0 ]; then
    echo "must run as root (use sudo), or pass --dry-run" >&2
    exit 3
fi

# Do not inherit a user locale: we parse tool output only loosely, but keep
# it predictable anyway.
LC_ALL=C
export LC_ALL
PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

# ---------------------------------------------------------------- helpers

ACTIONS=""
FAILED=0

log() {
    if [ "$JSON" = 1 ]; then echo "$*" >&2; else echo "$*"; fi
}

# JSON string escape (backslash, quote, drop control chars).
jesc() {
    printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# rec TARGET STATUS DETAIL
# NS_NOTE (set by scan) is appended once, to the next record, then cleared.
rec() {
    _dt="$3${NS_NOTE:+; $NS_NOTE}"
    NS_NOTE=""
    log "[$2] $1: $_dt"
    _j="{\"target\":\"$(jesc "$1")\",\"status\":\"$2\",\"detail\":\"$(jesc "$_dt")\"}"
    if [ -z "$ACTIONS" ]; then ACTIONS=$_j; else ACTIONS="$ACTIONS,$_j"; fi
    [ "$2" = failed ] && FAILED=$((FAILED + 1))
    return 0
}

have() { command -v "$1" >/dev/null 2>&1; }

# Per-command timeout when a timeout binary exists.
TMO=""
if have timeout; then TMO="timeout 25"; fi

STEP_DESC=""
STEP_ERR=""

# step DESCRIPTION CMD [ARGS...]
# Runs CMD (or only records it in --dry-run). Returns 0 on success.
step() {
    STEP_DESC=$1
    shift
    if [ "$DRY" = 1 ]; then return 0; fi
    case "$1" in
        kill) _o=$("$@" 2>&1); _rc=$? ;;
        *) _o=$($TMO "$@" 2>&1); _rc=$? ;;
    esac
    if [ "$_rc" -ne 0 ]; then
        STEP_ERR="$STEP_DESC failed (rc=$_rc): $(printf '%s' "$_o" | head -n 1 | cut -c1-160)"
        return 1
    fi
    return 0
}

# finish TARGET DESC : report success (or the dry-run plan).
finish() {
    if [ "$DRY" = 1 ]; then
        rec "$1" skipped "dry-run, would: $2"
    else
        rec "$1" flushed "$2"
    fi
}

# fail TARGET [EXTRA] : report failure with the last step error.
fail() {
    rec "$1" failed "${STEP_ERR:-flush failed}${2:+ ($2)}"
    STEP_ERR=""
}

# Our PID namespace. The production server is shared with other applications:
# a daemon living in another PID namespace (another container) must never be
# signalled or flushed, so only processes of this namespace are acted upon.
#
# Primary test: the NSpid line of /proc/PID/status (Linux 4.1+) lists one pid
# per namespace level from ours down to the process's own. /proc only shows
# our namespace and its descendants, so same entry count = same namespace.
# status is world-readable, unlike /proc/PID/ns/pid whose readlink is refused
# for non-dumpable daemons (dnsmasq) when CAP_SYS_PTRACE is missing, as in an
# unprivileged container. Fallback: compare readlink of /proc/PID/ns/pid.
# Both unknown for ourselves (very old kernel): no filtering.

# ns_depth FILE : sets _depth to the number of NSpid entries in FILE, or "".
ns_depth() {
    _depth=""
    [ -r "$1" ] || return 0
    while read -r _k _v; do
        if [ "$_k" = NSpid: ]; then
            set -- $_v
            _depth=$#
            return 0
        fi
    done < "$1"
    return 0
}
ns_depth /proc/self/status
SELF_DEPTH=$_depth
SELF_NS=$(readlink /proc/self/ns/pid 2>/dev/null)

# same_ns DIR : 0 same namespace, 1 other namespace, 2 cannot tell.
same_ns() {
    if [ -n "$SELF_DEPTH" ]; then
        ns_depth "$1/status"
        if [ -n "$_depth" ]; then
            [ "$_depth" = "$SELF_DEPTH" ] && return 0
            return 1
        fi
    fi
    if [ -n "$SELF_NS" ]; then
        _ns=$(readlink "$1/ns/pid" 2>/dev/null)
        [ -z "$_ns" ] && return 2
        [ "$_ns" = "$SELF_NS" ] && return 0
        return 1
    fi
    [ -z "$SELF_DEPTH" ] && return 0     # nothing to compare with: no filtering
    return 2
}

# scan COMM... : sets _p to the pids, in our PID namespace, whose kernel
# process name (comm, 15 chars max) is one of COMM; _other and _unread count
# the matching processes left alone (other namespace, unreadable namespace);
# NS_NOTE describes them for the next rec.
scan() {
    _p=""; _other=0; _unread=0; NS_NOTE=""
    if [ -d /proc/self ]; then
        for _d in /proc/[0-9]*; do
            [ -r "$_d/comm" ] || continue
            _c=""
            read -r _c < "$_d/comm" 2>/dev/null || continue
            _hit=0
            for _want in "$@"; do [ "$_c" = "$_want" ] && _hit=1; done
            [ "$_hit" = 1 ] || continue
            same_ns "$_d"
            case $? in
                1) _other=$((_other + 1)); continue ;;
                2) _unread=$((_unread + 1)); continue ;;
            esac
            _p="${_p:+$_p }${_d#/proc/}"
        done
    elif have pidof; then
        for _want in "$@"; do _p="${_p:+$_p }$(pidof "$_want" 2>/dev/null)"; done
        _p=$(one_line $_p)
    fi
    if [ "$_other" -gt 0 ]; then
        NS_NOTE="$_other processus dans un autre espace de noms PID (un autre conteneur) : non touché"
    fi
    if [ "$_unread" -gt 0 ]; then
        NS_NOTE="${NS_NOTE:+$NS_NOTE, }$_unread processus dont l'espace de noms PID est illisible : non touché"
    fi
    return 0
}

# pids_of COMM : the pids of scan, one per line (used for detection only).
pids_of() {
    scan "$1"
    for _x in $_p; do echo "$_x"; done
    return 0
}

# gone TARGET : nothing to flush here. Absent, or skipped when the only
# matching processes belong to another PID namespace (never a failure).
gone() {
    if [ -n "$NS_NOTE" ]; then
        rec "$1" skipped "ne tourne pas ici"
    else
        rec "$1" absent "not running"
    fi
}

one_line() { echo $1; }   # word-split on purpose: join pids with spaces

# ------------------------------------------------------------ init system

HAVE_SYSTEMD=0
INIT=unknown
if [ -d /run/systemd/system ] && have systemctl; then
    HAVE_SYSTEMD=1
    INIT=systemd
elif have rc-service && { [ -d /run/openrc ] || [ -d /var/run/openrc ] || have rc-status; }; then
    INIT=openrc
elif have sv && { [ -d /etc/service ] || [ -d /var/service ] || [ -d /run/runit ]; }; then
    INIT=runit
elif have s6-svc && { [ -d /run/service ] || [ -d /service ] || [ -d /etc/s6 ]; }; then
    INIT=s6
elif [ -d /etc/init.d ]; then
    INIT=sysv
fi

sv_dir() {
    for _b in "${SVDIR:-}" /run/service /service /etc/service /var/service /run/runit/service; do
        [ -n "$_b" ] && [ -d "$_b/$1" ] && { echo "$_b/$1"; return 0; }
    done
    return 1
}

# svc_do ACTION NAME... : restart/reload a service under any supported init.
# Tries each candidate name; sets STEP_DESC on success.
svc_do() {
    _act=$1
    shift
    for _n in "$@"; do
        if [ "$HAVE_SYSTEMD" = 1 ] && systemctl is-active "$_n" >/dev/null 2>&1; then
            step "systemctl $_act $_n" systemctl "$_act" "$_n" && return 0
        fi
        if have rc-service && [ -x "/etc/init.d/$_n" ] && [ "$INIT" = openrc ]; then
            step "rc-service $_n $_act" rc-service "$_n" "$_act" && return 0
        fi
        if have sv && _dir=$(sv_dir "$_n"); then
            case "$_act" in reload) _sa=hup ;; *) _sa=restart ;; esac
            step "sv $_sa $_n" sv "$_sa" "$_dir" && return 0
        fi
        if have s6-svc && _dir=$(sv_dir "$_n"); then
            case "$_act" in reload) _sa=-h ;; *) _sa=-t ;; esac
            step "s6-svc $_sa $_n" s6-svc "$_sa" "$_dir" && return 0
        fi
        if [ -x "/etc/init.d/$_n" ] && [ "$INIT" != openrc ]; then
            if have service; then
                step "service $_n $_act" service "$_n" "$_act" && return 0
            else
                step "/etc/init.d/$_n $_act" "/etc/init.d/$_n" "$_act" && return 0
            fi
        fi
    done
    return 1
}

# ------------------------------------------------------------- DNS targets

flush_systemd_resolved() {
    scan systemd-resolve   # comm is truncated to 15 chars
    if [ -z "$_p" ]; then
        gone systemd-resolved
        return
    fi
    if have resolvectl && step "resolvectl flush-caches" resolvectl flush-caches; then
        finish systemd-resolved "$STEP_DESC"
    elif have systemd-resolve && step "systemd-resolve --flush-caches" systemd-resolve --flush-caches; then
        finish systemd-resolved "$STEP_DESC"
    elif step "kill -USR2 $(one_line $_p)" kill -USR2 $_p; then
        finish systemd-resolved "$STEP_DESC"
    else
        fail systemd-resolved
    fi
}

flush_nscd() {
    scan nscd
    if [ -z "$_p" ]; then
        gone nscd
        return
    fi
    if have nscd && step "nscd -i hosts" nscd -i hosts; then
        finish nscd "$STEP_DESC"
    elif svc_do restart nscd; then
        finish nscd "$STEP_DESC"
    else
        fail nscd
    fi
}

flush_unscd() {
    scan unscd
    if [ -z "$_p" ]; then
        gone unscd
        return
    fi
    if have nscd && step "nscd -i hosts" nscd -i hosts; then
        finish unscd "$STEP_DESC"
    elif svc_do restart unscd nscd; then
        finish unscd "$STEP_DESC"
    else
        fail unscd
    fi
}

# dnsmasq: standalone, NetworkManager-spawned, libvirt-spawned. SIGHUP clears
# its cache (and re-reads /etc/hosts and resolv files, which is harmless).
flush_dnsmasq() {
    scan dnsmasq
    _std=""; _nm=""; _lv=""
    for _pid in $_p; do
        _cmd=$(tr '\000' ' ' < "/proc/$_pid/cmdline" 2>/dev/null)
        case "$_cmd" in
            *NetworkManager*) _nm="$_nm $_pid" ;;
            *libvirt*|*virbr*) _lv="$_lv $_pid" ;;
            *) _std="$_std $_pid" ;;
        esac
    done
    for _kind in dnsmasq dnsmasq-networkmanager dnsmasq-libvirt; do
        case "$_kind" in
            dnsmasq) _list=$_std ;;
            dnsmasq-networkmanager) _list=$_nm ;;
            *) _list=$_lv ;;
        esac
        if [ -z "$_list" ] && [ "$_kind" = dnsmasq ]; then
            gone dnsmasq          # other-namespace dnsmasq are reported here
        elif [ -z "$_list" ]; then
            rec "$_kind" absent "not running"
        elif step "kill -HUP$_list" kill -HUP $_list; then
            finish "$_kind" "$STEP_DESC"
        else
            fail "$_kind"
        fi
    done
}

flush_unbound() {
    scan unbound
    if [ -z "$_p" ]; then
        gone unbound
        return
    fi
    if have unbound-control && step "unbound-control flush_zone ." unbound-control flush_zone .; then
        _d="unbound-control flush_zone ."
        # Best effort extras: infra (RTT) cache and bogus markers.
        if step "unbound-control flush_infra all" unbound-control flush_infra all; then
            _d="$_d, flush_infra all"
        fi
        if step "unbound-control flush_bogus" unbound-control flush_bogus; then
            _d="$_d, flush_bogus"
        fi
        finish unbound "$_d"
    elif have unbound-control && step "unbound-control reload" unbound-control reload; then
        finish unbound "$STEP_DESC"
    elif svc_do reload unbound; then
        finish unbound "$STEP_DESC"
    elif svc_do restart unbound; then
        finish unbound "$STEP_DESC"
    elif step "kill -HUP $(one_line $_p)" kill -HUP $_p; then
        finish unbound "$STEP_DESC"
    else
        fail unbound
    fi
}

flush_named() {
    scan named named-pkcs11
    if [ -z "$_p" ]; then
        gone bind-named
        return
    fi
    if have rndc && step "rndc flush" rndc flush; then
        finish bind-named "$STEP_DESC"
    elif svc_do restart named bind9 bind named-chroot; then
        finish bind-named "$STEP_DESC"
    else
        fail bind-named
    fi
}

flush_pdns_recursor() {
    scan pdns_recursor
    if [ -z "$_p" ]; then
        gone pdns-recursor
        return
    fi
    if have rec_control && step "rec_control wipe-cache '\$'" rec_control wipe-cache '$'; then
        finish pdns-recursor "$STEP_DESC"
    elif svc_do restart pdns-recursor pdns_recursor; then
        finish pdns-recursor "$STEP_DESC"
    else
        fail pdns-recursor
    fi
}

# Send "cache.clear()" to a kresd control socket.
kresd_send() {
    if have socat; then
        step "socat cache.clear() on $1" sh -c 'printf "cache.clear()\n" | socat -t1 -T3 - "UNIX-CONNECT:$1"' sh "$1"
    elif have python3; then
        step "python3 cache.clear() on $1" python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1])
s.sendall(b"cache.clear()\n"); s.recv(4096)' "$1"
    elif have nc; then
        step "nc -U cache.clear() on $1" sh -c 'printf "cache.clear()\n" | nc -U -w1 "$1"' sh "$1"
    else
        STEP_ERR="no socat, python3 or nc to talk to $1"
        return 1
    fi
}

flush_kresd() {
    scan kresd
    if [ -z "$_p" ]; then
        gone knot-resolver
        return
    fi
    # Knot Resolver 6 manager, then Knot Resolver 5 control sockets.
    if have kresctl && step "kresctl cache clear" kresctl cache clear; then
        finish knot-resolver "$STEP_DESC"
        return
    fi
    _done=0; _n=0
    for _s in /run/knot-resolver/control/* /var/run/knot-resolver/control/* \
              /run/kresd/control/* /run/knot-resolver/control* /tmp/knot-resolver/control/*; do
        [ -S "$_s" ] || continue
        # /var/run is usually a symlink to /run: do not clear the same socket twice
        case "$_s" in /var/run/*) [ -S "/run${_s#/var/run}" ] && continue ;; esac
        _n=$((_n + 1))
        if kresd_send "$_s"; then _done=$((_done + 1)); _desc="${_desc:+$_desc; }$STEP_DESC"; fi
    done
    if [ "$_done" -gt 0 ]; then
        finish knot-resolver "$_desc"
    elif [ "$HAVE_SYSTEMD" = 1 ] && systemctl is-active 'kresd@*' >/dev/null 2>&1 \
         && step "systemctl restart kresd@*" systemctl restart 'kresd@*'; then
        finish knot-resolver "$STEP_DESC"
    elif svc_do restart knot-resolver kresd; then
        finish knot-resolver "$STEP_DESC"
    else
        fail knot-resolver "no usable control socket ($_n found)"
    fi
}

flush_dnscrypt() {
    scan dnscrypt-proxy
    if [ -z "$_p" ]; then
        gone dnscrypt-proxy
        return
    fi
    # No flush command: a restart is the only way to empty its cache.
    if svc_do restart dnscrypt-proxy; then
        finish dnscrypt-proxy "$STEP_DESC"
    else
        fail dnscrypt-proxy "no service manager entry found"
    fi
}

flush_stubby() {
    scan stubby
    if [ -z "$_p" ]; then
        gone stubby
        return
    fi
    if svc_do restart stubby; then
        finish stubby "$STEP_DESC"
    else
        fail stubby "no service manager entry found"
    fi
}

flush_sssd() {
    if ! have sss_cache; then
        rec sssd absent "sss_cache not installed"
    elif [ -z "$(pids_of sssd)" ] && [ ! -d /var/lib/sss/db ]; then
        rec sssd absent "not running, no cache directory"
    elif step "sss_cache -E" sss_cache -E; then
        finish sssd "$STEP_DESC"
    else
        fail sssd
    fi
}

flush_coredns() {
    scan coredns
    if [ -z "$_p" ]; then
        gone coredns
        return
    fi
    # SIGUSR1 makes CoreDNS reload its Corefile, which rebuilds the cache.
    if step "kill -USR1 $(one_line $_p)" kill -USR1 $_p; then
        finish coredns "$STEP_DESC"
    elif svc_do restart coredns; then
        finish coredns "$STEP_DESC"
    else
        fail coredns
    fi
}

flush_pdnsd() {
    scan pdnsd
    if [ -z "$_p" ]; then
        gone pdnsd
        return
    fi
    if have pdnsd-ctl && step "pdnsd-ctl empty-cache" pdnsd-ctl empty-cache; then
        finish pdnsd "$STEP_DESC"
    elif svc_do restart pdnsd; then
        finish pdnsd "$STEP_DESC"
    else
        fail pdnsd
    fi
}

# ------------------------------------------------------------- page cache

cached_kb() {
    [ -r /proc/meminfo ] || return 0
    while read -r _k _v _rest; do
        if [ "$_k" = "Cached:" ]; then echo "$_v"; break; fi
    done < /proc/meminfo
}

in_container() {
    [ -f /.dockerenv ] || [ -f /run/.containerenv ] && return 0
    grep -qaE 'docker|containerd|kubepods|lxc|libpod' /proc/1/cgroup 2>/dev/null && return 0
    return 1
}

PC_STATUS="skipped"
PC_DETAIL="not requested"
PC_BEFORE=""
PC_AFTER=""

flush_page_cache() {
    PC_BEFORE=$(cached_kb)
    if [ "$DRY" = 1 ]; then
        PC_STATUS=skipped
        PC_DETAIL="dry-run, would: sync; echo 3 > /proc/sys/vm/drop_caches"
        PC_AFTER=$PC_BEFORE
        log "[skipped] page-cache: $PC_DETAIL"
        return
    fi
    if have timeout; then timeout 120 sync 2>/dev/null; else sync 2>/dev/null; fi
    if [ ! -e /proc/sys/vm/drop_caches ]; then
        PC_STATUS=skipped
        PC_DETAIL="/proc/sys/vm/drop_caches does not exist"
    elif ( echo 3 > /proc/sys/vm/drop_caches ) 2>/dev/null; then
        PC_STATUS=flushed
        PC_DETAIL="sync; echo 3 > /proc/sys/vm/drop_caches"
    elif in_container; then
        PC_STATUS=skipped
        PC_DETAIL="/proc/sys/vm/drop_caches is not writable (container without privileges)"
    else
        PC_STATUS=failed
        PC_DETAIL="/proc/sys/vm/drop_caches is not writable"
        FAILED=$((FAILED + 1))
    fi
    PC_AFTER=$(cached_kb)
    log "[$PC_STATUS] page-cache: $PC_DETAIL"
}

# ------------------------------------------------------------------- main

if [ "$DO_DNS" = 1 ]; then
    flush_systemd_resolved
    flush_nscd
    flush_unscd
    flush_dnsmasq
    flush_unbound
    flush_named
    flush_pdns_recursor
    flush_kresd
    flush_dnscrypt
    flush_stubby
    flush_sssd
    flush_coredns
    flush_pdnsd
fi
if [ "$DO_PC" = 1 ]; then
    flush_page_cache
fi

HOST=$(hostname 2>/dev/null || uname -n 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)
KERNEL=$(uname -r 2>/dev/null)
DISTRO=""
if [ -r /etc/os-release ]; then
    DISTRO=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$NAME}" )
fi
if [ -z "$DISTRO" ]; then
    for _f in /etc/alpine-release /etc/redhat-release /etc/SuSE-release /etc/debian_version; do
        if [ -r "$_f" ]; then DISTRO="$(basename "$_f") $(head -n 1 "$_f")"; break; fi
    done
fi
[ -z "$DISTRO" ] && DISTRO=unknown

OK=true
[ "$FAILED" -gt 0 ] && OK=false

num_or_null() { if [ -n "$1" ]; then echo "$1"; else echo null; fi; }
DRYJ=false
[ "$DRY" = 1 ] && DRYJ=true

if [ "$JSON" = 1 ]; then
    printf '{"host":"%s","distro":"%s","kernel":"%s","init":"%s","dry_run":%s,"actions":[%s],"page_cache":{"before_kb":%s,"after_kb":%s,"status":"%s","detail":"%s"},"ok":%s}\n' \
        "$(jesc "$HOST")" "$(jesc "$DISTRO")" "$(jesc "$KERNEL")" "$INIT" "$DRYJ" "$ACTIONS" \
        "$(num_or_null "$PC_BEFORE")" "$(num_or_null "$PC_AFTER")" "$PC_STATUS" "$(jesc "$PC_DETAIL")" "$OK"
else
    log "host=$HOST distro=$DISTRO kernel=$KERNEL init=$INIT ok=$OK"
fi

[ "$FAILED" -gt 0 ] && exit 1
exit 0
