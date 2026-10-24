"""Tests for the security middleware: Host allow-list and session token."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from backend import security
except ImportError:  # pragma: no cover
    import security


class TestHostnameParsing(unittest.TestCase):
    def test_plain_host(self):
        self.assertEqual(security._hostname("example.com"), "example.com")

    def test_host_with_port(self):
        self.assertEqual(security._hostname("127.0.0.1:8000"), "127.0.0.1")

    def test_ipv6_bracketed(self):
        self.assertEqual(security._hostname("[::1]:8000"), "::1")

    def test_ipv6_bare(self):
        self.assertEqual(security._hostname("::1"), "::1")

    def test_case_is_ignored(self):
        self.assertEqual(security._hostname("LOCALHOST:8000"), "localhost")

    def test_empty(self):
        self.assertEqual(security._hostname(""), "")


class TestAllowLists(unittest.TestCase):
    def test_localhost_is_always_allowed(self):
        self.assertIn("127.0.0.1", security.ALLOWED_HOSTS)
        self.assertIn("localhost", security.ALLOWED_HOSTS)
        self.assertIn("::1", security.ALLOWED_HOSTS)

    def test_local_origins_are_allowed(self):
        self.assertIn(f"http://127.0.0.1:{security.PORT}", security.ALLOWED_ORIGINS)
        self.assertIn(f"http://localhost:{security.PORT}", security.ALLOWED_ORIGINS)

    def test_wildcard_origin_is_never_allowed(self):
        self.assertNotIn("*", security.ALLOWED_ORIGINS)

    def test_token_is_long_enough_to_be_unguessable(self):
        self.assertGreaterEqual(len(security.SESSION_TOKEN), 32)

    def test_unsafe_methods_cover_every_mutating_verb(self):
        for verb in ("POST", "PUT", "PATCH", "DELETE"):
            self.assertIn(verb, security.UNSAFE_METHODS)
        self.assertNotIn("GET", security.UNSAFE_METHODS)


class TestSecurityMiddleware(unittest.TestCase):
    """End-to-end checks against the real FastAPI app."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"FastAPI test client unavailable: {exc}")
        from backend.main import app
        cls.client = TestClient(app)
        cls.token = security.SESSION_TOKEN

    def test_get_on_allowed_host_is_served(self):
        r = self.client.get("/api/health", headers={"Host": "127.0.0.1"})
        self.assertEqual(r.status_code, 200)

    def test_get_on_foreign_host_is_blocked(self):
        r = self.client.get("/api/health", headers={"Host": "evil.example.com"})
        self.assertEqual(r.status_code, 403)

    def test_demo_routes_are_removed(self):
        for path in ("/api/stats", "/api/devices", "/api/decoys",
                     "/api/events", "/api/incidents", "/api/simulate/normal",
                     "/api/simulate/attack", "/api/decoy/FAKE-ADMIN",
                     "/api/device/DEVICE-007/allow",
                     "/api/device/DEVICE-007/isolate",
                     "/api/device/DEVICE-007/mark-safe"):
            r = self.client.get(path, headers={"Host": "127.0.0.1"})
            self.assertEqual(r.status_code, 404, path)

    def test_session_endpoint_returns_the_token(self):
        r = self.client.get("/api/session", headers={"Host": "127.0.0.1"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["token"], self.token)

    def test_post_without_a_token_is_rejected(self):
        r = self.client.post("/api/real/disconnect", headers={"Host": "127.0.0.1"})
        self.assertEqual(r.status_code, 401)

    def test_post_with_a_wrong_token_is_rejected(self):
        r = self.client.post("/api/real/disconnect",
                             headers={"Host": "127.0.0.1",
                                      security.TOKEN_HEADER: "wrong"})
        self.assertEqual(r.status_code, 401)

    def test_delete_without_a_token_is_rejected(self):
        r = self.client.delete("/api/ip/watch/1.2.3.4", headers={"Host": "127.0.0.1"})
        self.assertEqual(r.status_code, 401)

    def test_post_with_the_right_token_is_allowed(self):
        """The endpoint still runs; it just must not be rejected by the middleware."""
        r = self.client.post("/api/ip/watch",
                             headers={"Host": "127.0.0.1", security.TOKEN_HEADER: self.token},
                             json={"ip": "203.0.113.77", "note": "unit test"})
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
