"""Tests for the consented NextDNS activity feed.

No network calls: fetch_logs is replaced in the sync tests, and storage runs
against a temporary SQLite file.
"""
import http.server
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import database as db
from backend import network_intel


def event(ts="2026-10-24T09:01:00.000Z", domain="github.com", device="Laptop",
          severity="normal", status="default", client_ip="192.168.1.10"):
    return {
        "ts": ts, "domain": domain, "root_domain": domain, "device": device,
        "device_model": "", "device_id": "", "client_ip": client_ip,
        "protocol": "DoT", "status": status, "reasons": [],
        "severity": severity,
        "indicators": ([] if severity == "normal" else
                       [{"key": "test", "label": "Test indicator"}]),
        "source": "NextDNS",
    }


class TestClassification(unittest.TestCase):
    def test_ordinary_domain_is_normal(self):
        sev, keys = network_intel.classify_domain("github.com", "default")
        self.assertEqual(sev, "normal")
        self.assertEqual(keys, [])

    def test_punycode_is_suspicious(self):
        sev, keys = network_intel.classify_domain("xn--80ak6aa92e.com", "default")
        self.assertEqual(sev, "suspicious")
        self.assertIn("punycode", keys)

    def test_raw_ip_is_suspicious(self):
        sev, keys = network_intel.classify_domain("185.199.108.153", "default")
        self.assertEqual(sev, "suspicious")
        self.assertIn("raw-ip", keys)

    def test_high_entropy_label_is_suspicious(self):
        sev, keys = network_intel.classify_domain(
            "qzxwjkvbnmrtpy.example.com", "default")
        self.assertEqual(sev, "suspicious")
        self.assertIn("high-entropy", keys)

    def test_high_abuse_tld_is_watch(self):
        sev, keys = network_intel.classify_domain("example.tk", "default")
        self.assertEqual(sev, "watch")
        self.assertIn("high-abuse-tld", keys)

    def test_blocked_lookup_is_watch(self):
        sev, keys = network_intel.classify_domain("ads.example.com", "blocked")
        self.assertEqual(sev, "watch")
        self.assertIn("blocked-by-policy", keys)

    def test_blocklist_reason_escalates_to_alert(self):
        sev, keys = network_intel.classify_domain(
            "login.example.com", "blocked", [{"name": "phishing"}])
        self.assertEqual(sev, "alert")
        self.assertIn("blocklist-match", keys)

    def test_empty_domain_is_normal(self):
        self.assertEqual(network_intel.classify_domain("", "default"),
                         ("normal", []))


class TestNormalize(unittest.TestCase):
    def test_record_with_device_object(self):
        raw = {
            "timestamp": "2026-10-24T03:30:00Z",
            "domain": "YouTube.com.",
            "root": "youtube.com",
            "clientIp": "192.168.1.23",
            "protocol": "DoT",
            "status": "default",
            "device": {"id": "dev-1", "name": "Friend-Phone", "model": "Pixel"},
            "reasons": [],
        }
        out = network_intel.normalize_record(raw)
        self.assertEqual(out["domain"], "youtube.com")
        self.assertEqual(out["device"], "Friend-Phone")
        self.assertEqual(out["device_model"], "Pixel")
        self.assertEqual(out["ts"], "2026-10-24T03:30:00.000Z")
        self.assertEqual(out["severity"], "normal")

    def test_string_device_is_accepted(self):
        out = network_intel.normalize_record({
            "timestamp": "2026-10-24T09:00:00Z", "domain": "example.com",
            "device": "Tablet",
        })
        self.assertEqual(out["device"], "Tablet")

    def test_client_fallback_and_timezone(self):
        out = network_intel.normalize_record({
            "timestamp": "2026-10-24T09:00:00+05:30",
            "domain": "example.com", "client": "tablet",
            "status": "blocked", "reasons": "policy",
        })
        self.assertEqual(out["device"], "tablet")
        self.assertEqual(out["ts"], "2026-10-24T03:30:00.000Z")
        self.assertEqual(out["status"], "blocked")

    def test_missing_domain_is_ignored(self):
        self.assertIsNone(network_intel.normalize_record({"client": "x"}))

    def test_parse_logs_accepts_wrapper_and_deduplicates(self):
        record = {"timestamp": "2026-10-24T09:00:00Z", "domain": "a.example",
                  "client": "phone"}
        out = network_intel.parse_logs({"data": [record, record]})
        self.assertEqual(len(out), 1)

    def test_parse_logs_accepts_bare_list(self):
        out = network_intel.parse_logs([
            {"timestamp": "2026-10-24T09:00:00Z", "domain": "b.example",
             "client": "phone"},
        ])
        self.assertEqual(len(out), 1)

    def test_epoch_timestamp_is_normalized(self):
        out = network_intel.normalize_record({
            "timestamp": "2026-10-24T09:00:00Z", "domain": "epoch.example",
        })
        self.assertTrue(out["ts"].endswith("Z"))
        self.assertEqual(len(out["ts"]), 24)

    def test_millisecond_epoch_timestamp_is_normalized(self):
        out = network_intel.normalize_record({
            "timestamp": 1761296400000, "domain": "epoch.example",
        })
        self.assertEqual(out["ts"], "2025-10-24T09:00:00.000Z")

    def test_invalid_timestamp_does_not_break_normalization(self):
        out = network_intel.normalize_record({
            "timestamp": "not-a-date", "domain": "epoch.example",
        })
        self.assertEqual(out["ts"], "not-a-date")

    def test_raw_ip_root_falls_back_to_the_address(self):
        for domain in ("1.2.3.4", "2001:db8::1"):
            out = network_intel.normalize_record({
                "timestamp": "2026-10-24T09:00:00Z", "domain": domain,
            })
            self.assertEqual(out["root_domain"], domain)

    def test_parse_logs_rejects_non_list_data(self):
        with self.assertRaises(network_intel.NextDNSError):
            network_intel.parse_logs({"data": {"domain": "x.example"}})

    def test_parse_logs_skips_non_dict_records(self):
        self.assertEqual(network_intel.parse_logs({"data": ["nope", None]}), [])


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = db.DB_PATH
        db.DB_PATH = os.path.join(self.tmp.name, "cybershield-test.db")
        db.init_db()

    def tearDown(self):
        db.DB_PATH = self.old_path
        self.tmp.cleanup()

    def test_insert_is_idempotent(self):
        self.assertEqual(db.insert_dns_events([event()]), 1)
        self.assertEqual(db.insert_dns_events([event()]), 0)
        self.assertEqual(db.get_dns_stats(0)["total_queries"], 1)

    def test_filters_and_details(self):
        db.insert_dns_events([
            event(ts="2026-10-24T09:01:00.000Z", domain="github.com"),
            event(ts="2026-10-24T09:02:00.000Z", domain="evil.tk",
                  device="Friend-Phone", severity="suspicious", status="blocked"),
            event(ts="2026-10-24T09:03:00.000Z", domain="youtube.com",
                  device="Friend-Phone"),
        ])
        rows = db.get_dns_events(limit=10, hours=0)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["domain"], "youtube.com")
        filtered = db.get_dns_events(limit=10, device="Friend-Phone", hours=0)
        self.assertEqual(len(filtered), 2)
        flagged = db.get_dns_events(limit=10, severity="flagged", hours=0)
        self.assertEqual(len(flagged), 1)
        search = db.get_dns_events(limit=10, query="github", hours=0)
        self.assertEqual(len(search), 1)
        self.assertTrue(search[0]["indicators"] == [])

    def test_stats_devices_and_domains(self):
        db.insert_dns_events([
            event(domain="github.com", severity="normal"),
            event(domain="evil.tk", severity="suspicious",
                  status="blocked", device="Friend-Phone"),
            event(domain="evil.tk", severity="suspicious",
                  status="blocked", device="Friend-Phone", client_ip="192.168.1.11"),
        ])
        stats = db.get_dns_stats(0)
        self.assertEqual(stats["total_queries"], 3)
        self.assertEqual(stats["unique_domains"], 2)
        self.assertEqual(stats["devices"], 2)
        self.assertEqual(stats["suspicious"], 2)
        self.assertEqual(stats["blocked"], 2)
        self.assertEqual(stats["flagged"], 2)
        devices = {d["device"]: d for d in db.get_dns_devices(0)}
        self.assertEqual(devices["Friend-Phone"]["queries"], 2)
        self.assertEqual(len(devices["Friend-Phone"]["client_ips"]), 2)
        domains = db.get_dns_domains(0, limit=5)
        self.assertEqual(domains[0]["domain"], "evil.tk")
        self.assertEqual(domains[0]["queries"], 2)

    def test_invalid_limits_fall_back(self):
        db.insert_dns_events([event()])
        self.assertEqual(len(db.get_dns_events(limit="nope", hours=0)), 1)
        self.assertEqual(len(db.get_dns_domains(0, limit="nope")), 1)

    def test_prune_and_clear(self):
        db.insert_dns_events([
            event(ts="2020-01-01T00:00:00.000Z", domain="old.example"),
            event(ts="2026-10-24T09:01:00.000Z", domain="new.example"),
        ])
        self.assertEqual(db.prune_dns_events(days=1), 1)
        self.assertEqual(db.get_dns_stats(0)["total_queries"], 1)
        self.assertEqual(db.clear_dns_events(), 1)
        self.assertEqual(db.get_dns_stats(0)["total_queries"], 0)


class TestSync(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = tempfile.TemporaryDirectory()
        self.old_path = db.DB_PATH
        db.DB_PATH = os.path.join(self.tmp.name, "cybershield-test.db")
        db.init_db()
        network_intel.stop_background()
        with network_intel._lock:
            network_intel._paused = False
            network_intel._cache.update({"at": 0.0, "fingerprint": "", "result": {}})
        self.env = mock.patch.dict(os.environ, {
            "NEXTDNS_API_KEY": "test-secret-key",
            "NEXTDNS_PROFILE_ID": "test-profile",
            "CYBERSHIELD_CONFIG_DIR": self.config.name,
            "DNS_RETENTION_DAYS": "3650",
        })
        self.env.start()

    def tearDown(self):
        network_intel.stop_background()
        self.env.stop()
        db.DB_PATH = self.old_path
        self.tmp.cleanup()
        self.config.cleanup()
        with network_intel._lock:
            network_intel._paused = False
            network_intel._cache.update({"at": 0.0, "fingerprint": "", "result": {}})

    def test_unconfigured_does_not_raise(self):
        with mock.patch.dict(os.environ, {"NEXTDNS_API_KEY": "",
                                          "NEXTDNS_PROFILE_ID": ""}):
            res = network_intel.sync(force=True)
        self.assertFalse(res["configured"])
        self.assertFalse(res["ok"])

    def test_sync_stores_normalized_events(self):
        rows = [
            {"timestamp": "2026-10-24T09:01:00Z", "domain": "github.com",
             "clientIp": "192.168.1.10", "status": "default",
             "device": {"name": "Laptop"}, "reasons": []},
            {"timestamp": "2026-10-24T09:02:00Z", "domain": "evil.tk",
             "clientIp": "192.168.1.11", "status": "blocked",
             "device": {"name": "Friend-Phone"},
             "reasons": [{"name": "malware"}]},
        ]
        events = network_intel.parse_logs({"data": rows})
        with mock.patch.object(network_intel, "fetch_logs", return_value=events):
            res = network_intel.sync(force=True)
        self.assertTrue(res["ok"])
        self.assertEqual(res["events_added"], 2)
        stats = db.get_dns_stats(0)
        self.assertEqual(stats["total_queries"], 2)
        self.assertEqual(stats["alerts"], 1)
        self.assertEqual(stats["devices"], 2)

    def test_sync_reports_api_error_without_secrets(self):
        with mock.patch.object(network_intel, "fetch_logs",
                               side_effect=network_intel.NextDNSError("HTTP 401")):
            res = network_intel.sync(force=True)
        self.assertFalse(res["ok"])
        self.assertTrue(res["configured"])
        payload = json.dumps(res)
        self.assertNotIn("test-secret-key", payload)
        self.assertIn("401", res["error"])

    def test_status_never_contains_the_api_key(self):
        payload = json.dumps(network_intel.status_payload())
        self.assertNotIn("test-secret-key", payload)
        self.assertNotIn("test-profile", payload)

    def test_purge_pauses_until_an_explicit_refresh(self):
        events = network_intel.parse_logs({"data": [
            {"timestamp": "2026-10-24T09:01:00Z", "domain": "github.com",
             "clientIp": "192.168.1.10"}]})
        with mock.patch.object(network_intel, "fetch_logs", return_value=events):
            network_intel.sync(force=True)
            cleared = network_intel.purge()
            self.assertTrue(cleared["paused"])
            paused = network_intel.sync()
            self.assertTrue(paused.get("paused"))
            resumed = network_intel.refresh()
            self.assertTrue(resumed["sync"]["ok"])

    def test_background_worker_fetches_and_stores(self):
        events = network_intel.parse_logs({"data": [
            {"timestamp": "2026-10-24T09:01:00Z", "domain": "github.com",
             "clientIp": "192.168.1.10"}]})
        with mock.patch.object(network_intel, "background_interval",
                               return_value=0.01), \
                mock.patch.object(network_intel, "fetch_logs",
                                  return_value=events) as fetch:
            self.assertTrue(network_intel.start_background())
            for _ in range(100):
                if db.get_dns_stats(0)["total_queries"]:
                    break
                time.sleep(0.01)
            network_intel.stop_background()
        self.assertGreaterEqual(fetch.call_count, 1)
        self.assertEqual(db.get_dns_stats(0)["total_queries"], 1)

    def test_error_sync_is_cached_briefly(self):
        with mock.patch.object(network_intel, "fetch_logs",
                               side_effect=network_intel.NextDNSError("HTTP 429")) as fetch:
            first = network_intel.sync(force=True)
            second = network_intel.sync()
        self.assertFalse(first["ok"])
        self.assertTrue(second.get("cached"))
        self.assertEqual(fetch.call_count, 1)

    def test_cached_sync_does_not_call_the_api_twice(self):
        events = network_intel.parse_logs({"data": [
            {"timestamp": "2026-10-24T09:01:00Z", "domain": "github.com",
             "clientIp": "192.168.1.10"}]})
        with mock.patch.object(network_intel, "fetch_logs",
                               return_value=events) as fetch:
            network_intel.sync(force=True)
            network_intel.sync()
        self.assertEqual(fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, host):
        self.client = _FakeClient(host)


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = tempfile.TemporaryDirectory()
        self.old_path = db.DB_PATH
        db.DB_PATH = os.path.join(self.tmp.name, "cybershield-test.db")
        db.init_db()
        network_intel.stop_background()
        with network_intel._lock:
            network_intel._paused = False
            network_intel._cache.update({"at": 0.0, "fingerprint": "", "result": {}})
        self.env = mock.patch.dict(os.environ, {
            "NEXTDNS_API_KEY": "",
            "NEXTDNS_PROFILE_ID": "",
            "CYBERSHIELD_CONFIG_DIR": self.config.name,
            "DNS_RETENTION_DAYS": "3650",
        })
        self.env.start()

    def tearDown(self):
        network_intel.stop_background()
        self.env.stop()
        db.DB_PATH = self.old_path
        self.tmp.cleanup()
        self.config.cleanup()
        with network_intel._lock:
            network_intel._paused = False
            network_intel._cache.update({"at": 0.0, "fingerprint": "", "result": {}})

    def _path(self):
        return os.path.join(self.config.name, "nextdns.json")

    def test_connect_saves_owner_only_file_and_masks_status(self):
        events = network_intel.parse_logs({"data": [
            {"timestamp": "2026-10-24T09:01:00Z", "domain": "github.com",
             "clientIp": "192.168.1.10"}]})
        with mock.patch.object(network_intel, "_fetch_logs",
                               return_value=events) as fetch:
            result = network_intel.connect("test-secret-key", "abc123")
        self.assertTrue(result["ok"])
        self.assertEqual(result["fetched"], 1)
        self.assertEqual(result["events_added"], 1)
        self.assertEqual(fetch.call_args.args[0], "test-secret-key")
        self.assertEqual(fetch.call_args.args[1], "abc123")
        self.assertTrue(os.path.exists(self._path()))
        if os.name == "posix":
            mode = stat.S_IMODE(os.stat(self._path()).st_mode)
            self.assertEqual(mode, 0o600)
        status = network_intel.status_payload()
        self.assertTrue(status["configured"])
        self.assertEqual(status["config_source"], "file")
        payload = json.dumps(status)
        self.assertNotIn("test-secret-key", payload)
        self.assertNotIn("abc123", payload)

    def test_invalid_profile_is_rejected_before_fetching(self):
        with mock.patch.object(network_intel, "_fetch_logs") as fetch:
            with self.assertRaises(ValueError):
                network_intel.connect("test-key", "not a profile")
        fetch.assert_not_called()
        self.assertFalse(os.path.exists(self._path()))

    def test_invalid_stored_config_is_ignored(self):
        with open(self._path(), "w", encoding="utf-8") as fh:
            json.dump({"api_key": "test-key", "profile_id": "bad profile"}, fh)
        self.assertEqual(network_intel.config_source(), "none")
        self.assertFalse(network_intel.status_payload()["configured"])

    def test_refresh_clears_pause_without_credentials(self):
        network_intel.purge()
        self.assertTrue(network_intel.status_payload()["paused"])
        network_intel.sync(force=True)
        self.assertFalse(network_intel.status_payload()["paused"])

    def test_failed_connection_is_not_stored(self):
        with mock.patch.object(network_intel, "_fetch_logs",
                               side_effect=network_intel.NextDNSError("HTTP 401")):
            with self.assertRaises(network_intel.NextDNSError):
                network_intel.connect("test-key", "abc123")
        self.assertFalse(os.path.exists(self._path()))
        self.assertFalse(network_intel.status_payload()["configured"])

    def test_environment_credentials_cannot_be_overwritten(self):
        with mock.patch.dict(os.environ, {
            "NEXTDNS_API_KEY": "env-key",
            "NEXTDNS_PROFILE_ID": "env-profile",
        }):
            self.assertEqual(network_intel.config_source(), "environment")
            self.assertFalse(network_intel.status_payload(
                _FakeRequest("127.0.0.1"))["can_configure"])
            with self.assertRaises(PermissionError):
                network_intel.connect("new-key", "new-profile")
            with self.assertRaises(PermissionError):
                network_intel.disconnect()
        self.assertFalse(os.path.exists(self._path()))

    def test_disconnect_removes_credentials_but_keeps_history(self):
        events = network_intel.parse_logs({"data": [
            {"timestamp": "2026-10-24T09:01:00Z", "domain": "github.com",
             "clientIp": "192.168.1.10"}]})
        with mock.patch.object(network_intel, "_fetch_logs", return_value=events):
            network_intel.connect("test-secret-key", "abc123")
        result = network_intel.disconnect()
        self.assertTrue(result["removed"])
        self.assertFalse(os.path.exists(self._path()))
        self.assertFalse(network_intel.status_payload()["configured"])
        self.assertEqual(db.get_dns_stats(0)["total_queries"], 1)

    def test_poll_and_retention_settings_are_clamped(self):
        with mock.patch.dict(os.environ, {
                "NEXTDNS_POLL_SECONDS": "1", "DNS_RETENTION_DAYS": "99999"}):
            self.assertEqual(network_intel.background_interval(), 15)
            self.assertEqual(network_intel.retention_days(), 3650)
        with mock.patch.dict(os.environ, {
                "NEXTDNS_POLL_SECONDS": "nope", "DNS_RETENTION_DAYS": "nope"}):
            self.assertEqual(network_intel.background_interval(), 60)
            self.assertEqual(network_intel.retention_days(), 30)

    def test_local_request_detection(self):
        self.assertTrue(network_intel._is_local_request(_FakeRequest("127.0.0.1")))
        self.assertTrue(network_intel._is_local_request(_FakeRequest("127.0.0.2")))
        self.assertTrue(network_intel._is_local_request(_FakeRequest("::1")))
        self.assertTrue(network_intel._is_local_request(
            _FakeRequest("::ffff:127.0.0.1")))
        self.assertFalse(network_intel._is_local_request(_FakeRequest("192.168.1.20")))
        self.assertFalse(network_intel._is_local_request(_FakeRequest("127.evil")))
        self.assertTrue(network_intel.status_payload(
            _FakeRequest("127.0.0.1"))["can_configure"])
        self.assertFalse(network_intel.status_payload(
            _FakeRequest("192.168.1.20"))["can_configure"])

    def test_background_worker_starts_and_stops(self):
        self.assertTrue(network_intel.start_background())
        self.assertTrue(network_intel.background_running())
        self.assertFalse(network_intel.start_background())
        network_intel.stop_background()
        for _ in range(50):
            if not network_intel.background_running():
                break
            time.sleep(0.02)
        self.assertFalse(network_intel.background_running())

    def test_connect_route_requires_loopback(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(network_intel.router)
        client = TestClient(app)
        with mock.patch.object(network_intel, "_is_local_request", return_value=False):
            res = client.post("/api/network/connect", json={
                "api_key": "test-key", "profile_id": "abc123"})
        self.assertEqual(res.status_code, 403)

    def test_connect_and_disconnect_routes(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(network_intel.router)
        client = TestClient(app)
        events = network_intel.parse_logs({"data": [
            {"timestamp": "2026-10-24T09:01:00Z", "domain": "github.com",
             "clientIp": "192.168.1.10"}]})
        with mock.patch.object(network_intel, "_is_local_request", return_value=True), \
                mock.patch.object(network_intel, "_fetch_logs", return_value=events):
            res = client.post("/api/network/connect", json={
                "api_key": "test-secret-key", "profile_id": "abc123"})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["status"]["configured"])
        self.assertNotIn("test-secret-key", json.dumps(body))
        with mock.patch.object(network_intel, "_is_local_request", return_value=True):
            res = client.delete("/api/network/connect")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()["status"]["configured"])


class TestNextDNSHTTP(unittest.TestCase):
    class Handler(http.server.BaseHTTPRequestHandler):
        status_code = 200
        body = b'{"data": []}'
        requests = []

        def do_GET(self):
            type(self).requests.append({
                "path": self.path,
                "key": self.headers.get("X-Api-Key"),
                "accept": self.headers.get("Accept"),
            })
            self.send_response(type(self).status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(type(self).body)))
            self.end_headers()
            self.wfile.write(type(self).body)

        def log_message(self, *args):
            pass

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), cls.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.config = tempfile.TemporaryDirectory()
        type(self).Handler.requests = []
        type(self).Handler.status_code = 200
        type(self).Handler.body = b'{"data": []}'
        self.env = mock.patch.dict(os.environ, {
            "NEXTDNS_API_KEY": "test-secret-key",
            "NEXTDNS_PROFILE_ID": "test-profile",
            "NEXTDNS_BASE_URL": self.base,
            "CYBERSHIELD_CONFIG_DIR": self.config.name,
            "NO_PROXY": "127.0.0.1,localhost",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.config.cleanup()

    def test_sends_auth_and_parses_records(self):
        type(self).Handler.body = json.dumps({"data": [{
            "timestamp": "2026-10-24T09:01:00Z",
            "domain": "YouTube.com.",
            "clientIp": "192.168.1.23",
            "protocol": "DoT",
            "status": "default",
            "device": {"name": "Friend-Phone", "model": "Pixel"},
            "reasons": [],
        }]}).encode()
        events = network_intel.fetch_logs(50)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["domain"], "youtube.com")
        self.assertEqual(events[0]["device"], "Friend-Phone")
        request = type(self).Handler.requests[-1]
        parsed = urllib.parse.urlparse(request["path"])
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/profiles/test-profile/logs")
        self.assertEqual(query["limit"], ["50"])
        self.assertEqual(query["sort"], ["desc"])
        self.assertEqual(request["key"], "test-secret-key")

    def test_401_is_sanitized(self):
        type(self).Handler.status_code = 401
        with self.assertRaises(network_intel.NextDNSError) as ctx:
            network_intel.fetch_logs()
        self.assertIn("401", str(ctx.exception))
        self.assertNotIn("test-secret-key", str(ctx.exception))

    def test_429_is_reported(self):
        type(self).Handler.status_code = 429
        with self.assertRaises(network_intel.NextDNSError) as ctx:
            network_intel.fetch_logs()
        self.assertIn("429", str(ctx.exception))

    def test_invalid_json_is_reported(self):
        type(self).Handler.body = b"not-json"
        with self.assertRaises(network_intel.NextDNSError):
            network_intel.fetch_logs()

    def test_unexpected_payload_is_reported(self):
        type(self).Handler.body = b'{"data": {"domain": "x.example"}}'
        with self.assertRaises(network_intel.NextDNSError):
            network_intel.fetch_logs()

    def test_limit_is_clamped(self):
        network_intel.fetch_logs(1)
        network_intel.fetch_logs(99999)
        limits = []
        for request in type(self).Handler.requests[-2:]:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(request["path"]).query)
            limits.append(query["limit"][0])
        self.assertEqual(limits, ["10", "1000"])

    def test_missing_credentials_does_not_call_the_api(self):
        with mock.patch.dict(os.environ, {"NEXTDNS_API_KEY": "",
                                          "NEXTDNS_PROFILE_ID": ""}):
            with self.assertRaises(network_intel.NextDNSNotConfigured):
                network_intel.fetch_logs()
        self.assertEqual(type(self).Handler.requests, [])
