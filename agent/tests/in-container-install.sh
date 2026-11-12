#!/bin/sh
# Runs INSIDE a container: full install.sh cycle, agent started by the
# detected init, then real HTTP calls (token, CORS, sudo path), uninstall.
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

if command -v apt-get >/dev/null 2>&1; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq --no-install-recommends sudo python3 curl dnsmasq >/dev/null 2>&1
elif command -v apk >/dev/null 2>&1; then
    apk add -q sudo python3 curl openrc dnsmasq >/dev/null 2>&1
    mkdir -p /run/openrc; touch /run/openrc/softlevel
    openrc sysinit >/dev/null 2>&1; openrc default >/dev/null 2>&1
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q --allowerasing sudo python3 curl dnsmasq >/dev/null 2>&1
fi
dnsmasq --user=root --port=5354 --bind-interfaces --listen-address=127.0.0.1 --conf-file=/dev/null >/dev/null 2>&1

cd /agent || exit 1
sh install.sh --origin https://check.example.com > /tmp/install.out 2>&1 && ok "install.sh" || { bad "install.sh"; cat /tmp/install.out; }
head -n 3 /tmp/install.out | sed 's/^/     /'
TOKEN=$(cat /etc/check-agent/token)
[ ${#TOKEN} -ge 32 ] && ok "token generated" || bad "token"
[ "$(stat -c %a /etc/check-agent/token)" = 640 ] && ok "token mode 640" || bad "token mode"
[ -f /etc/sudoers.d/check-agent ] && ok "sudoers file" || bad "sudoers file"
visudo -c >/dev/null 2>&1 && ok "visudo -c" || bad "visudo -c"
if grep -q 'no supported init' /tmp/install.out; then
    echo "     (no init in this container: starting the agent by hand as check-agent)"
    su -s /bin/sh check-agent -c 'CHECK_AGENT_ORIGIN=https://check.example.com CHECK_AGENT_TOKEN_FILE=/etc/check-agent/token nohup python3 /usr/local/lib/check-agent/check-agent.py >/tmp/agent.log 2>&1 &'
fi
sleep 2
U=http://127.0.0.1:47625
H=$(curl -s $U/health); echo "$H" | grep -q '"authenticated": false' && ok "health open" || bad "health: $H"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST $U/flush); [ "$c" = 401 ] && ok "no token -> 401" || bad "no token -> $c"
c=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H 'Origin: https://check.example.com' $U/flush); [ "$c" = 204 ] && ok "preflight 204" || bad "preflight $c"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" -H 'Origin: https://evil.example' $U/flush); [ "$c" = 403 ] && ok "foreign origin 403" || bad "foreign origin $c"
R=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"dns":true,"page_cache":false}' $U/flush)
echo "$R" | grep -q '"target": "dnsmasq", "status": "flushed"' && ok "flush via sudo flushed dnsmasq" || bad "flush: $R"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" $U/flush); [ "$c" = 429 ] && ok "second flush 429" || bad "rate limit $c"
AUID=$(id -u check-agent); found=""
for d in /proc/[0-9]*; do
    if tr '\000' ' ' < $d/cmdline 2>/dev/null | grep -q 'python3 /usr/local/lib/check-agent/check-agent.py'; then
        found="$found $(awk '/^Uid:/{print $2}' $d/status)"
    fi
done
case "$found" in *"$AUID"*) ok "agent process runs as check-agent (uid $AUID)" ;; *) bad "agent process uid: '$found' want $AUID" ;; esac
# the agent user must not be able to modify the installed script
su -s /bin/sh check-agent -c 'echo x >> /usr/local/lib/check-agent/flush-caches.sh' 2>/dev/null && bad "agent user can write script" || ok "script not writable by agent user"

sh install.sh --uninstall >/dev/null 2>&1
[ ! -e /usr/local/lib/check-agent ] && [ ! -e /etc/check-agent ] && [ ! -e /etc/sudoers.d/check-agent ] && ! id check-agent >/dev/null 2>&1 \
    && ok "uninstall clean" || bad "uninstall left files/user"
echo "RESULT $([ $fail = 0 ] && echo PASS || echo FAIL)"
