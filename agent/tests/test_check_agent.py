"""Unit tests for check-agent.py (python3 -m unittest discover -s agent/tests)."""
import http.client
import importlib.util
import json
import os
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("check_agent", os.path.join(HERE, "..", "check-agent.py"))
ca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ca)

TOKEN = "t" * 32
ORIGIN = "https://check.example.com"


class FakeClock(object):
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.calls = []

        def runner(script, dns, page_cache):
            self.calls.append((dns, page_cache))
            return 200, {"ok": True, "actions": [], "page_cache": {"before_kb": 1, "after_kb": 0}}

        cfg = ca.Config(TOKEN, [ORIGIN], "/nonexistent", 10, clock=self.clock, runner=runner)
        self.srv = ca.make_server(cfg, "127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = dict(headers or {})
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), (json.loads(raw) if raw else None)

    AUTH = {"Authorization": "Bearer " + TOKEN}

    def test_health_open_but_reports_auth(self):
        st, _, body = self.req("GET", "/health")
        self.assertEqual(st, 200)
        self.assertFalse(body["authenticated"])
        st, _, body = self.req("GET", "/health", headers=self.AUTH)
        self.assertTrue(body["authenticated"])

    def test_flush_requires_token(self):
        for h in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic " + TOKEN}):
            st, hd, _ = self.req("POST", "/flush", {}, h)
            self.assertEqual(st, 401)
            self.assertIn("www-authenticate", hd)
        self.assertEqual(self.calls, [])

    def test_dns_only_host_never_drops_page_cache(self):
        self.srv.cfg.dns_only = True
        st, _, body = self.req("POST", "/flush", {"dns": False, "page_cache": True}, self.AUTH)
        self.assertEqual(st, 403)
        self.assertEqual(self.calls, [])
        st, _, _ = self.req("POST", "/flush", {}, self.AUTH)  # default asks for both
        self.assertEqual(st, 200)
        self.assertEqual(self.calls, [(True, False)])
        st, _, body = self.req("GET", "/health")
        self.assertTrue(body["dns_only"])

    def test_flush_ok_and_options_passed(self):
        st, _, body = self.req("POST", "/flush", {"dns": True, "page_cache": False}, self.AUTH)
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.calls, [(True, False)])

    def test_default_body_flushes_both(self):
        st, _, _ = self.req("POST", "/flush", None, self.AUTH)
        self.assertEqual(st, 200)
        self.assertEqual(self.calls, [(True, True)])

    def test_bad_bodies(self):
        self.assertEqual(self.req("POST", "/flush", b"{nope", self.AUTH)[0], 400)
        self.clock.now += 100
        self.assertEqual(self.req("POST", "/flush", {"dns": False, "page_cache": False}, self.AUTH)[0], 400)
        self.assertEqual(self.req("POST", "/flush", {"dns": "yes"}, self.AUTH)[0], 400)
        self.assertEqual(self.calls, [])

    def test_rate_limit(self):
        self.assertEqual(self.req("POST", "/flush", {}, self.AUTH)[0], 200)
        st, hd, body = self.req("POST", "/flush", {}, self.AUTH)
        self.assertEqual(st, 429)
        self.assertIn("retry-after", hd)
        self.assertEqual(len(self.calls), 1)
        self.clock.now += 10.5
        self.assertEqual(self.req("POST", "/flush", {}, self.AUTH)[0], 200)
        self.assertEqual(len(self.calls), 2)

    def test_preflight_allowed_origin(self):
        st, hd, _ = self.req("OPTIONS", "/flush", headers={
            "Origin": ORIGIN, "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
            "Access-Control-Request-Private-Network": "true"})
        self.assertEqual(st, 204)
        self.assertEqual(hd["access-control-allow-origin"], ORIGIN)
        self.assertEqual(hd["access-control-allow-private-network"], "true")
        self.assertIn("authorization", hd["access-control-allow-headers"].lower())
        self.assertIn("POST", hd["access-control-allow-methods"])

    def test_preflight_foreign_origin_refused(self):
        st, hd, _ = self.req("OPTIONS", "/flush", headers={"Origin": "https://evil.example"})
        self.assertEqual(st, 403)
        self.assertNotIn("access-control-allow-origin", hd)

    def test_cors_headers_on_actual_response(self):
        st, hd, _ = self.req("GET", "/health", headers={"Origin": ORIGIN})
        self.assertEqual(hd["access-control-allow-origin"], ORIGIN)

    def test_foreign_origin_cannot_flush_even_with_token(self):
        h = dict(self.AUTH, Origin="https://evil.example")
        st, hd, _ = self.req("POST", "/flush", {}, h)
        self.assertEqual(st, 403)
        self.assertNotIn("access-control-allow-origin", hd)
        self.assertEqual(self.calls, [])

    def test_unknown_path(self):
        self.assertEqual(self.req("GET", "/nope")[0], 404)
        self.assertEqual(self.req("POST", "/nope", {}, self.AUTH)[0], 404)


class ScriptRunnerTest(unittest.TestCase):
    # Executes the real flush-caches.sh. Even in --dry-run it must never run on a
    # developer host by accident: only inside a test container that sets the variable.
    @unittest.skipUnless(os.environ.get("CHECK_AGENT_REAL_SCRIPT") == "1",
                         "runs flush-caches.sh: set CHECK_AGENT_REAL_SCRIPT=1, inside a container only")
    def test_real_script_dry_run_parses(self):
        script = os.path.join(HERE, "..", "flush-caches.sh")
        # run_script adds sudo when not root, so call the script directly here
        import subprocess
        out = subprocess.run([script, "--json", "--dry-run"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, universal_newlines=True).stdout
        data = json.loads(out.strip().splitlines()[-1])
        self.assertIn("actions", data)
        self.assertTrue(data["ok"])


if __name__ == "__main__":
    unittest.main()
