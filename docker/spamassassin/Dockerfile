# SpamAssassin (spamd) for check, with a dedicated Unbound resolver that keeps nothing in cache.
# The application talks to spamd over TCP (SPAMC/1.5 protocol) on port 783.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      spamassassin spamd spamc unbound ca-certificates gnupg dirmngr curl \
      libnet-dns-perl libmail-dkim-perl libmail-spf-perl libio-socket-ssl-perl \
 && rm -rf /var/lib/apt/lists/*

COPY local.cf /etc/spamassassin/local.cf
COPY unbound.conf /etc/unbound/unbound.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && unbound-checkconf /etc/unbound/unbound.conf \
 && (sa-update -v || [ $? -eq 1 ]) \
 && spamassassin --lint -L

# Allowed clients: loopback and the private ranges Docker uses for its networks.
ENV SPAMD_ALLOWED_IPS=127.0.0.1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
ENV SPAMD_MAX_CHILDREN=4
EXPOSE 783
HEALTHCHECK --interval=60s --timeout=10s --start-period=60s \
  CMD printf 'PING SPAMC/1.5\r\n\r\n' | timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/783; cat >&3; cat <&3' | grep -q PONG
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
