#!/usr/bin/env python3
"""check-agent: tiny local HTTP agent that flushes DNS and page caches.

Python 3.6+, standard library only.

Endpoints
  GET  /health   liveness; reports whether the supplied token is valid
  POST /flush    runs flush-caches.sh --json; body {"dns":true,"page_cache":true}
  OPTIONS *      CORS / Private Network Access preflight

Configuration (environment variables, all optional except the token)
  CHECK_AGENT_BIND          listen address            (default 127.0.0.1)
  CHECK_AGENT_PORT          listen port               (default 47625)
  CHECK_AGENT_TOKEN         shared secret; else read from the token file
  CHECK_AGENT_TOKEN_FILE    token file                (default /etc/check-agent/token)
  CHECK_AGENT_ORIGIN        allowed web origin(s), comma separated
  CHECK_AGENT_SCRIPT        path to flush-caches.sh
  CHECK_AGENT_MIN_INTERVAL  seconds between two flushes (default 10)
"""

import argparse
import hmac
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

VERSION = "1.0"
DEFAULT_PORT = 47625
DEFAULT_TOKEN_FILE = "/etc/check-agent/token"
DEFAULT_SCRIPT = "/usr/local/lib/check-agent/flush-caches.sh"
MAX_BODY = 4096
SCRIPT_TIMEOUT = 150


def log(msg):
    sys.stderr.write("%s check-agent: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    sys.stderr.flush()


class Config(object):
    def __init__(self, token, origins=(), script=DEFAULT_SCRIPT,
                 min_interval=10.0, clock=time.monotonic, runner=None):
        self.token = token
        self.origins = list(origins)
        self.script = script
        self.min_interval = float(min_interval)
        self.dns_only = False
        self.clock = clock          # injectable for tests
        self.runner = runner or run_script
        self.lock = threading.Lock()
        self.last_flush = None      # clock value of the last accepted flush
        self.busy = False


def read_token(env=os.environ):
    tok = env.get("CHECK_AGENT_TOKEN", "").strip()
    if tok:
        return tok
    path = env.get("CHECK_AGENT_TOKEN_FILE", DEFAULT_TOKEN_FILE)
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def find_script(env=os.environ):
    path = env.get("CHECK_AGENT_SCRIPT")
    if path:
        return path
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flush-caches.sh")
    if os.path.exists(DEFAULT_SCRIPT):
        return DEFAULT_SCRIPT
    return local


def run_script(script, dns, page_cache):
    """Run flush-caches.sh; return (http_status, payload dict)."""
    args = ["--json"]
    if dns and not page_cache:
        args.append("--dns-only")
    elif page_cache and not dns:
        args.append("--page-cache-only")
    cmd = [script] + args
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=SCRIPT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 504, {"ok": False, "error": "flush script timed out"}
    except OSError as exc:
        return 500, {"ok": False, "error": "cannot run flush script: %s" % exc}
    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    try:
        data = json.loads(lines[-1])
    except (IndexError, ValueError):
        tail = (proc.stderr or "").strip().splitlines()[-1:]
        return 502, {"ok": False, "exit_code": proc.returncode,
                     "error": "flush script returned no JSON",
                     "stderr": tail[0][:300] if tail else ""}
    data["exit_code"] = proc.returncode
    return 200, data


class Handler(BaseHTTPRequestHandler):
    server_version = "check-agent/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------
    @property
    def cfg(self):
        return self.server.cfg

    def address_string(self):
        return self.client_address[0]     # no reverse DNS lookup

    def log_message(self, fmt, *args):
        log("%s %s" % (self.address_string(), fmt % args))

    def _origin_allowed(self):
        origin = self.headers.get("Origin")
        if origin is None:
            return True, None            # not a browser: token is the guard
        if origin in self.cfg.origins or "*" in self.cfg.origins:
            return True, origin
        return False, origin

    def _cors(self, origin):
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Expose-Headers", "Retry-After")
        self.send_header("Vary", "Origin")

    def _send(self, status, payload=None, extra=None):
        ok, origin = self._origin_allowed()
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if ok:
            self._cors(origin)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, str(v))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _authed(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        given = header[7:].strip().encode("utf-8")
        return hmac.compare_digest(given, self.cfg.token.encode("utf-8"))

    # -- verbs ------------------------------------------------------------
    def do_OPTIONS(self):
        ok, origin = self._origin_allowed()
        if not ok or origin is None:
            return self._send(403, {"ok": False, "error": "origin not allowed"})
        self.send_response(204)
        self._cors(origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path.split("?")[0] != "/health":
            return self._send(404, {"ok": False, "error": "not found"})
        ok, _ = self._origin_allowed()
        if not ok:
            return self._send(403, {"ok": False, "error": "origin not allowed"})
        self._send(200, {"ok": True, "agent": "check-agent", "version": VERSION, "dns_only": self.cfg.dns_only,
                         "authenticated": self._authed(),
                         "host": socket.gethostname(),
                         "min_interval": self.cfg.min_interval})

    def do_POST(self):
        # Always consume the body first so keep-alive connections stay in sync.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            return self._send(400, {"ok": False, "error": "bad Content-Length"})
        if length < 0:
            # rfile.read(-1) would read to EOF without limit (code review of 2026-11-12)
            self.close_connection = True
            return self._send(400, {"ok": False, "error": "bad Content-Length"})
        if length > MAX_BODY:
            self.close_connection = True
            return self._send(413, {"ok": False, "error": "body too large"})
        raw = self.rfile.read(length) if length else b""
        if self.path.split("?")[0] != "/flush":
            return self._send(404, {"ok": False, "error": "not found"})
        ok, _ = self._origin_allowed()
        if not ok:
            return self._send(403, {"ok": False, "error": "origin not allowed"})
        if not self._authed():
            return self._send(401, {"ok": False, "error": "missing or invalid token"},
                              {"WWW-Authenticate": 'Bearer realm="check-agent"'})
        opts = {}
        if raw.strip():
            try:
                opts = json.loads(raw.decode("utf-8"))
            except ValueError:
                return self._send(400, {"ok": False, "error": "invalid JSON"})
            if not isinstance(opts, dict):
                return self._send(400, {"ok": False, "error": "JSON object expected"})
        dns = opts.get("dns", True)
        page_cache = opts.get("page_cache", True)
        if not isinstance(dns, bool) or not isinstance(page_cache, bool):
            return self._send(400, {"ok": False, "error": "dns and page_cache must be booleans"})
        if not dns and not page_cache:
            return self._send(400, {"ok": False, "error": "nothing to flush"})
        if self.cfg.dns_only and page_cache:
            # installed with --dns-only (shared server): the page cache is never dropped here
            if not dns:
                return self._send(403, {"ok": False, "error": "page cache flush disabled on this host (dns-only)"})
            page_cache = False

        cfg = self.cfg
        with cfg.lock:
            now = cfg.clock()
            if cfg.busy:
                return self._send(429, {"ok": False, "error": "a flush is already running"},
                                  {"Retry-After": 5})
            if cfg.last_flush is not None and now - cfg.last_flush < cfg.min_interval:
                wait = int(cfg.min_interval - (now - cfg.last_flush)) + 1
                return self._send(429, {"ok": False, "error": "rate limited", "retry_after": wait},
                                  {"Retry-After": wait})
            cfg.last_flush = now
            cfg.busy = True
        try:
            log("flush requested dns=%s page_cache=%s" % (dns, page_cache))
            status, payload = cfg.runner(cfg.script, dns, page_cache)
        finally:
            with cfg.lock:
                cfg.busy = False
                cfg.last_flush = cfg.clock()
        log("flush done http=%s ok=%s" % (status, payload.get("ok")))
        self._send(status, payload)


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, cfg):
        self.cfg = cfg
        if ":" in addr[0]:
            self.address_family = socket.AF_INET6
        HTTPServer.__init__(self, addr, handler)

    def server_bind(self):
        # HTTPServer.server_bind calls getfqdn(), a needless (slow) DNS lookup.
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name = self.server_address[0]
        self.server_port = self.server_address[1]


def make_server(cfg, host="127.0.0.1", port=DEFAULT_PORT):
    return Server((host, port), Handler, cfg)


def main(argv=None):
    env = os.environ
    ap = argparse.ArgumentParser(description="Local agent flushing DNS and page caches.")
    ap.add_argument("--bind", default=env.get("CHECK_AGENT_BIND", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(env.get("CHECK_AGENT_PORT") or DEFAULT_PORT))
    args = ap.parse_args(argv)

    token = read_token()
    if len(token) < 16:
        log("refusing to start: no token (>= 16 chars) in CHECK_AGENT_TOKEN or %s"
            % env.get("CHECK_AGENT_TOKEN_FILE", DEFAULT_TOKEN_FILE))
        return 1
    origins = [o.strip().rstrip("/") for o in env.get("CHECK_AGENT_ORIGIN", "").split(",") if o.strip()]
    script = find_script()
    if not os.path.exists(script):
        log("refusing to start: flush script not found: %s" % script)
        return 1
    cfg = Config(token, origins, script, env.get("CHECK_AGENT_MIN_INTERVAL") or 10)
    cfg.dns_only = (env.get("CHECK_AGENT_DNS_ONLY") or "") in ("1", "true", "yes")
    try:
        srv = make_server(cfg, args.bind, args.port)
    except OSError as exc:
        log("cannot listen on %s:%s: %s" % (args.bind, args.port, exc))
        return 1
    log("listening on %s:%s, origins=%s, script=%s, root=%s"
        % (args.bind, args.port, origins or "none", script, os.geteuid() == 0))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
