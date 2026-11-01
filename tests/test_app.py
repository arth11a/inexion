import json
import os
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from testutil import C  # noqa: F401
import inx_app as A


class AppSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        A.HOME_DIR = os.path.join(cls.tmp.name, ".inexion")
        A.SETTINGS = os.path.join(A.HOME_DIR, "app.json")
        cls.state = A.State("http://127.0.0.1:1")
        cls.token = "t0ken-for-tests"
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        cls.port = cls.srv.server_address[1]
        cls.srv.RequestHandlerClass = A.make_handler(cls.state, cls.token, cls.port)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def call(self, path, body=None, headers=None, token=True):
        h = {"X-Token": self.token} if token else {}
        h.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path), data=data, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}

    def test_token_host_origin(self):
        self.assertEqual(self.call("/api/state")[0], 200)
        self.assertEqual(self.call("/api/state", token=False)[0], 403)
        self.assertEqual(self.call("/api/state", headers={"X-Token": "bad"})[0], 403)
        self.assertEqual(self.call("/api/state", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.call("/api/state", headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.call("/api/lock", {}, token=False)[0], 403)

    def test_page_needs_token_and_has_no_secret(self):
        for url, code in (("/", 403), ("/?t=wrong", 403)):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, url), timeout=5)
            self.assertEqual(cm.exception.code, code)
        with urllib.request.urlopen("http://127.0.0.1:%d/?t=%s" % (self.port, self.token), timeout=5) as r:
            self.assertEqual(r.status, 200)
            self.assertIn(b"INEXION", r.read())

    def test_wallet_flow_without_node(self):
        code, r = self.call("/api/create", {"password": "short", "password2": "short"})
        self.assertEqual(code, 400)
        code, r = self.call("/api/create", {"password": "long-enough-pass", "password2": "different-pass-1"})
        self.assertEqual(code, 400)
        code, r = self.call("/api/create", {"password": "long-enough-pass", "password2": "long-enough-pass"})
        self.assertEqual(code, 200)
        self.assertTrue(C.is_valid_address(self.state.address))
        with open(r["file"]) as f:
            saved = json.load(f)
        self.assertNotIn("seed", saved)                       # ключ в файле только зашифрованным
        self.assertEqual(oct(os.stat(r["file"]).st_mode)[-3:], "600")
        addr, rec = self.state.address, r["recovery"]
        self.assertEqual(self.call("/api/lock", {})[0], 200)
        self.assertFalse(self.state.unlocked())
        self.assertEqual(self.call("/api/send", {"to": addr, "amount": "1"})[0], 400)   # заблокирован
        self.assertEqual(self.call("/api/unlock", {"file": r["file"], "password": "wrong-password-1"})[0], 400)
        self.assertEqual(self.call("/api/unlock", {"file": "/etc/passwd", "password": "x"})[0], 400)
        self.assertEqual(self.call("/api/unlock", {"file": r["file"], "password": "long-enough-pass"})[0], 200)
        self.assertEqual(self.state.address, addr)
        code, r2 = self.call("/api/recovery", {"password": "long-enough-pass"})
        self.assertEqual((code, r2["recovery"]), (200, rec))
        self.assertEqual(self.call("/api/recovery", {"password": "nope-nope-nope"})[0], 400)
        code, r3 = self.call("/api/restore", {"code": rec, "password": "another-pass-123"})
        self.assertEqual((code, self.state.address), (200, addr))
        self.assertEqual(self.call("/api/node", {"url": "ftp://x"})[0], 400)
        self.assertEqual(self.call("/api/account")[0], 502)   # узла нет: понятная ошибка, не падение


if __name__ == "__main__":
    unittest.main()
