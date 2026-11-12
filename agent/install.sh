#!/bin/sh
# install.sh - install (or remove) the check-agent on this Linux machine.
#
# Usage: sudo ./install.sh [--origin URL[,URL]] [--bind ADDR] [--port N]
#                          [--root] [--no-start]
#        sudo ./install.sh --uninstall
#
#   --origin   web origin(s) allowed by CORS, e.g. https://check.example.com
#   --bind     listen address (default 127.0.0.1; use the docker bridge IP or
#              0.0.0.0 on a server whose app runs in Docker, firewall it!)
#   --port     listen port (default 47625)
#   --root     run the agent itself as root instead of a dedicated user plus
#              sudoers rule (for minimal systems without sudo)
#   --no-start install but do not start the service
#
# POSIX sh. Exit codes: 0 ok, 1 error, 2 usage.

LIB=/usr/local/lib/check-agent
CONF=/etc/check-agent
USER_NAME=check-agent
SUDOERS=/etc/sudoers.d/check-agent
SRC=$(cd "$(dirname "$0")" && pwd)

UNINSTALL=0; ORIGIN=""; BIND=127.0.0.1; PORT=47625; RUNROOT=0; START=1; DNSONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) UNINSTALL=1 ;;
        --origin) ORIGIN=$2; shift ;;
        --bind) BIND=$2; shift ;;
        --dns-only) DNSONLY=1 ;;
        --port) PORT=$2; shift ;;
        --root) RUNROOT=1 ;;
        --no-start) START=0 ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo ./install.sh)"

# Values end up in a shell-sourced file and a systemd EnvironmentFile: keep
# them to a boring character set.
case "$ORIGIN$BIND$PORT" in
    *[!A-Za-z0-9:/.,_*-]*) die "--origin/--bind/--port contain unsupported characters" ;;
esac
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac

# ---------------------------------------------------------- init detection
if [ -d /run/systemd/system ] && have systemctl; then INIT=systemd
elif have rc-service && [ -x /sbin/openrc-run ]; then INIT=openrc
elif [ -d /etc/init.d ]; then INIT=sysv
else INIT=none; fi

# --------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
    say "stopping and removing the service (init: $INIT)"
    case "$INIT" in
        systemd)
            systemctl disable --now check-agent.service >/dev/null 2>&1
            rm -f /etc/systemd/system/check-agent.service
            systemctl daemon-reload >/dev/null 2>&1 ;;
        openrc)
            rc-service check-agent stop >/dev/null 2>&1
            rc-update del check-agent >/dev/null 2>&1
            rm -f /etc/init.d/check-agent ;;
        sysv)
            /etc/init.d/check-agent stop >/dev/null 2>&1
            if have update-rc.d; then update-rc.d -f check-agent remove >/dev/null 2>&1
            elif have chkconfig; then chkconfig --del check-agent >/dev/null 2>&1; fi
            rm -f /etc/init.d/check-agent ;;
    esac
    rm -f "$SUDOERS"
    rm -rf "$LIB" "$CONF"
    rm -f /var/run/check-agent.pid /run/check-agent.pid
    if id "$USER_NAME" >/dev/null 2>&1; then
        if have userdel; then userdel "$USER_NAME" >/dev/null 2>&1; else deluser "$USER_NAME" >/dev/null 2>&1; fi
        have groupdel && groupdel "$USER_NAME" >/dev/null 2>&1
    fi
    say "check-agent removed"
    exit 0
fi

# ----------------------------------------------------------------- install
PY=$(command -v python3) || die "python3 is required (3.6 or newer)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' || die "Python 3.6+ is required"
[ -f "$SRC/flush-caches.sh" ] && [ -f "$SRC/check-agent.py" ] || die "run install.sh from the agent/ directory"

if [ "$RUNROOT" = 0 ]; then
    have sudo && have visudo || die "sudo and visudo are required (install sudo, or use --root)"
fi

say "installing files in $LIB (root-owned, not writable by the agent user)"
mkdir -p "$LIB" || die "cannot create $LIB"
cp "$SRC/flush-caches.sh" "$SRC/check-agent.py" "$LIB/" || die "copy failed"
chown root:root "$LIB" "$LIB/flush-caches.sh" "$LIB/check-agent.py" 2>/dev/null || chown 0:0 "$LIB" "$LIB"/*
chmod 755 "$LIB" "$LIB/flush-caches.sh" "$LIB/check-agent.py"

if [ "$RUNROOT" = 1 ]; then
    RUN_USER=root; RUN_GROUP=root
else
    RUN_USER=$USER_NAME; RUN_GROUP=$USER_NAME
    if ! id "$USER_NAME" >/dev/null 2>&1; then
        say "creating system user $USER_NAME"
        NOLOGIN=$(command -v nologin || echo /sbin/nologin)
        if have useradd; then
            useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" "$USER_NAME" \
                || die "useradd failed"
        else
            addgroup -S "$USER_NAME" 2>/dev/null
            adduser -S -D -H -h /nonexistent -s "$NOLOGIN" -G "$USER_NAME" "$USER_NAME" || die "adduser failed"
        fi
    fi
fi

say "configuration in $CONF"
mkdir -p "$CONF"
chown root:"$RUN_GROUP" "$CONF"; chmod 750 "$CONF"
if [ ! -s "$CONF/token" ]; then
    TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    [ "${#TOKEN}" -ge 32 ] || die "could not generate a token"
    ( umask 077; printf '%s\n' "$TOKEN" > "$CONF/token" )
    NEWTOKEN=1
else
    NEWTOKEN=0
fi
chown root:"$RUN_GROUP" "$CONF/token"; chmod 640 "$CONF/token"
cat > "$CONF/env" <<ENV
CHECK_AGENT_ORIGIN=$ORIGIN
CHECK_AGENT_BIND=$BIND
CHECK_AGENT_PORT=$PORT
CHECK_AGENT_DNS_ONLY=$DNSONLY
ENV
chown root:"$RUN_GROUP" "$CONF/env"; chmod 640 "$CONF/env"

if [ "$RUNROOT" = 0 ]; then
    say "sudoers rule (only $LIB/flush-caches.sh)"
    TMP=$(mktemp) || die "mktemp failed"
    if [ "$DNSONLY" = 1 ]; then
        # shared server: sudo allows the DNS-only invocation and nothing else
        printf '%s ALL=(root) NOPASSWD: %s --json --dns-only\n' "$USER_NAME" "$LIB/flush-caches.sh" > "$TMP"
    else
        printf '%s ALL=(root) NOPASSWD: %s\n' "$USER_NAME" "$LIB/flush-caches.sh" > "$TMP"
    fi
    if ! visudo -c -f "$TMP" >/dev/null 2>&1; then
        rm -f "$TMP"; die "generated sudoers rule rejected by visudo -c"
    fi
    mkdir -p /etc/sudoers.d
    install -m 0440 -o root -g root "$TMP" "$SUDOERS" 2>/dev/null || { cp "$TMP" "$SUDOERS"; chmod 0440 "$SUDOERS"; }
    rm -f "$TMP"
    visudo -c >/dev/null 2>&1 || { rm -f "$SUDOERS"; die "visudo -c failed on the final configuration, rule removed"; }
    grep -rqsE '^[#@]includedir[[:space:]]+/etc/sudoers.d|^@includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers \
        || echo "warning: /etc/sudoers does not include /etc/sudoers.d, the rule may be ignored" >&2
fi

# ------------------------------------------------------------- the service
CMD="$PY $LIB/check-agent.py"
case "$INIT" in
systemd)
    say "systemd unit"
    # NoNewPrivileges is deliberately NOT set: sudo is setuid and needs it.
    cat > /etc/systemd/system/check-agent.service <<UNIT
[Unit]
Description=check-agent (flush DNS and page caches on request)
After=network.target

[Service]
User=$RUN_USER
Group=$RUN_GROUP
EnvironmentFile=$CONF/env
Environment=CHECK_AGENT_TOKEN_FILE=$CONF/token
ExecStart=$CMD
Restart=on-failure
RestartSec=3
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable check-agent.service >/dev/null 2>&1
    [ "$START" = 1 ] && { systemctl restart check-agent.service || die "service failed to start (journalctl -u check-agent)"; }
    ;;
openrc)
    say "OpenRC script"
    cat > /etc/init.d/check-agent <<RC
#!/sbin/openrc-run
description="check-agent (flush DNS and page caches on request)"
command="$PY"
command_args="$LIB/check-agent.py"
command_user="$RUN_USER:$RUN_GROUP"
command_background=true
pidfile="/run/check-agent.pid"
output_log="/var/log/check-agent.log"
error_log="/var/log/check-agent.log"
depend() { need net; }
start_pre() {
    . $CONF/env
    # every variable of the env file must be exported, CHECK_AGENT_DNS_ONLY included
    export CHECK_AGENT_ORIGIN CHECK_AGENT_BIND CHECK_AGENT_PORT CHECK_AGENT_DNS_ONLY
    export CHECK_AGENT_TOKEN_FILE=$CONF/token
    checkpath -f -m 0640 -o "$RUN_USER:$RUN_GROUP" /var/log/check-agent.log
}
RC
    chmod 755 /etc/init.d/check-agent
    rc-update add check-agent default >/dev/null 2>&1
    [ "$START" = 1 ] && { rc-service check-agent restart || die "service failed to start"; }
    ;;
sysv)
    say "SysV init script"
    cat > /etc/init.d/check-agent <<'SYSV'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          check-agent
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: check-agent (flush DNS and page caches on request)
### END INIT INFO
# chkconfig: 2345 80 20
# description: check-agent
SYSV
    cat >> /etc/init.d/check-agent <<SYSV
PY="$PY"
DAEMON="$LIB/check-agent.py"
RUN_USER="$RUN_USER"
PIDFILE=/var/run/check-agent.pid
LOG=/var/log/check-agent.log
SYSV
    cat >> /etc/init.d/check-agent <<'SYSV'
. /etc/check-agent/env
# every variable of the env file must be exported: without CHECK_AGENT_DNS_ONLY
# a --dns-only install asked sudo for the page cache too and got refused (502)
export CHECK_AGENT_ORIGIN CHECK_AGENT_BIND CHECK_AGENT_PORT CHECK_AGENT_DNS_ONLY
export CHECK_AGENT_TOKEN_FILE=/etc/check-agent/token

is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case "$1" in
start)
    is_running && { echo "check-agent already running"; exit 0; }
    touch "$LOG"; chown "$RUN_USER" "$LOG" 2>/dev/null
    if command -v start-stop-daemon >/dev/null 2>&1; then
        start-stop-daemon --start --quiet --background --make-pidfile --pidfile "$PIDFILE" \
            --chuid "$RUN_USER" --startas /bin/sh -- -c "exec $PY $DAEMON >>$LOG 2>&1"
    else
        su -s /bin/sh "$RUN_USER" -c "exec $PY $DAEMON >>$LOG 2>&1 & echo \$!" > "$PIDFILE"
    fi
    sleep 1
    is_running && echo "check-agent started" || { echo "check-agent failed to start, see $LOG" >&2; exit 1; }
    ;;
stop)
    if is_running; then kill "$(cat "$PIDFILE")"; rm -f "$PIDFILE"; echo "check-agent stopped"; fi
    ;;
restart|force-reload) "$0" stop; "$0" start ;;
status) is_running && echo "check-agent running" || { echo "check-agent stopped"; exit 3; } ;;
*) echo "Usage: $0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
exit 0
SYSV
    chmod 755 /etc/init.d/check-agent
    if have update-rc.d; then update-rc.d check-agent defaults >/dev/null 2>&1
    elif have chkconfig; then chkconfig --add check-agent >/dev/null 2>&1; fi
    [ "$START" = 1 ] && { /etc/init.d/check-agent restart || die "service failed to start"; }
    ;;
*)
    say "no supported init system detected (systemd, OpenRC, SysV): no service installed"
    echo "run it by hand: CHECK_AGENT_TOKEN_FILE=$CONF/token CHECK_AGENT_ORIGIN='$ORIGIN' $CMD" >&2
    ;;
esac

say "check-agent installed (init: $INIT, user: $RUN_USER, listening on $BIND:$PORT)"
if [ "$NEWTOKEN" = 1 ]; then
    echo "token (also in $CONF/token, readable by root only): $(cat "$CONF/token")"
else
    echo "existing token kept ($CONF/token)"
fi
exit 0
