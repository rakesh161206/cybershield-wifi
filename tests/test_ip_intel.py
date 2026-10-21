"""Tests for IP intelligence: scope, purpose classification and scoring."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import ip_intel
from backend import ip_purpose


class TestScope(unittest.TestCase):
    def test_public_address(self):
        self.assertEqual(ip_intel.classify_scope("8.8.8.8"), "public")

    def test_private_addresses(self):
        for ip in ("192.168.1.1", "10.0.0.5", "172.16.4.4"):
            self.assertEqual(ip_intel.classify_scope(ip), "private")

    def test_loopback(self):
        self.assertEqual(ip_intel.classify_scope("127.0.0.1"), "loopback")

    def test_link_local(self):
        self.assertEqual(ip_intel.classify_scope("169.254.1.1"), "linklocal")

    def test_multicast(self):
        self.assertEqual(ip_intel.classify_scope("224.0.0.1"), "multicast")

    def test_cgnat(self):
        self.assertEqual(ip_intel.classify_scope("100.64.0.1"), "cgnat")

    def test_documentation_range(self):
        self.assertEqual(ip_intel.classify_scope("203.0.113.5"), "documentation")

    def test_ipv6_is_public(self):
        self.assertEqual(ip_intel.classify_scope("2606:4700:4700::1111"), "public")

    def test_bsd_style_ipv6_is_accepted(self):
        """macOS netstat prints 2404:6800:4007:8, which is not RFC 5952."""
        self.assertEqual(ip_intel.classify_scope("2404:6800:4007:8"), "public")

    def test_garbage_is_unknown(self):
        self.assertEqual(ip_intel.classify_scope("not-an-ip"), "unknown")


class TestPurpose(unittest.TestCase):
    def test_loopback(self):
        purpose, _, _ = ip_purpose.classify("127.0.0.1", {"scope": "loopback"}, [])
        self.assertEqual(purpose, "loopback")

    def test_private_address_is_a_lan_peer(self):
        purpose, _, _ = ip_purpose.classify("192.168.1.5", {"scope": "private"}, [])
        self.assertEqual(purpose, "lan-peer")

    def test_known_public_resolver(self):
        purpose, conf, _ = ip_purpose.classify("8.8.8.8", {"scope": "public"}, [53])
        self.assertEqual(purpose, "public-dns")
        self.assertEqual(conf, 1.0)

    def test_cdn_from_organisation_name(self):
        intel = {"scope": "public", "org": "CLOUDFLARENET, US"}
        purpose, _, _ = ip_purpose.classify("104.16.0.1", intel, [443])
        self.assertEqual(purpose, "cdn")

    def test_hosting_from_organisation_name(self):
        intel = {"scope": "public", "org": "Some VPS Provider"}
        purpose, _, _ = ip_purpose.classify("45.83.64.1", intel, [])
        self.assertEqual(purpose, "hosting")

    def test_tor_exit_from_the_feed(self):
        intel = {"scope": "public",
                 "reputation": {"matched": True, "lists": [{"name": "tor-exit", "type": "tor"}]}}
        purpose, conf, _ = ip_purpose.classify("171.25.193.25", intel, [443])
        self.assertEqual(purpose, "tor-exit")
        self.assertEqual(conf, 1.0)

    def test_bulletproof_from_the_feed(self):
        intel = {"scope": "public",
                 "reputation": {"matched": True,
                                "lists": [{"name": "bp", "type": "bulletproof"}]}}
        purpose, _, _ = ip_purpose.classify("1.2.3.4", intel, [])
        self.assertEqual(purpose, "bulletproof-hosting")

    def test_unknown_is_never_reported_as_safe(self):
        """An address with no classifying signal must stay 'unknown'."""
        purpose, _, evidence = ip_purpose.classify("1.2.3.4", {"scope": "public"}, [54321])
        self.assertEqual(purpose, "unknown")
        self.assertTrue(evidence)
        self.assertNotEqual(purpose, "public-dns")

    def test_backdoor_port_is_not_treated_as_ordinary(self):
        """Port 31337 has no benign reading."""
        purpose, _, _ = ip_purpose.classify("1.2.3.4", {"scope": "public"}, [31337])
        self.assertNotEqual(purpose, "cdn")
        self.assertNotEqual(purpose, "public-dns")

    def test_every_purpose_has_a_label(self):
        for key in ip_purpose.PURPOSES:
            self.assertEqual(ip_purpose.label(key)["key"], key)


class TestIPScoring(unittest.TestCase):
    def base_ctx(self, **kw):
        ctx = {"sources": ["cymru"], "scope": "public", "asn": "AS1",
               "ports": [443], "actor_class": "browser"}
        ctx.update(kw)
        return ctx

    def test_tor_exit_scores_high(self):
        rep = {"matched": True, "lists": [{"name": "tor-exit", "type": "tor"}]}
        s = ip_purpose.score("1.2.3.4", "tor-exit", self.base_ctx(reputation=rep))
        self.assertGreaterEqual(s["score"], 65)
        self.assertEqual(s["verdict"], "avoid")

    def test_bulletproof_hosting_scores_high(self):
        s = ip_purpose.score("1.2.3.4", "bulletproof-hosting", self.base_ctx())
        self.assertGreaterEqual(s["score"], 65)

    def test_cdn_alone_is_not_dangerous(self):
        s = ip_purpose.score("1.2.3.4", "cdn", self.base_ctx())
        self.assertLess(s["score"], 35)
        self.assertEqual(s["verdict"], "connect")

    def test_resolver_is_not_dangerous(self):
        s = ip_purpose.score("8.8.8.8", "public-dns", self.base_ctx())
        self.assertEqual(s["score"], 0)

    def test_unknown_costs_uncertainty_points_not_zero(self):
        s = ip_purpose.score("1.2.3.4", "unknown", self.base_ctx(sources=[]))
        self.assertGreater(s["score"], 0)
        self.assertTrue(any("uncertainty" in r for r in s["reasons"]))

    def test_unexpected_program_on_hosting_scores_higher(self):
        browser = ip_purpose.score("1.2.3.4", "hosting",
                                   self.base_ctx(actor_class="browser"))
        stranger = ip_purpose.score("1.2.3.4", "hosting",
                                    self.base_ctx(actor_class="application"))
        self.assertGreater(stranger["score"], browser["score"])

    def test_scan_shape_is_scored_for_remote_peers_only(self):
        remote = ip_purpose.score("1.2.3.4", "web-app",
                                  self.base_ctx(ports=[1, 2, 3, 4, 5, 6]))
        local = ip_purpose.score("127.0.0.1", "loopback",
                                 self.base_ctx(scope="loopback",
                                               ports=[1, 2, 3, 4, 5, 6]))
        self.assertGreater(remote["score"], local["score"])
        self.assertFalse(any("scanning shape" in r for r in local["reasons"]))

    def test_score_is_capped(self):
        s = ip_purpose.score("1.2.3.4", "bulletproof-hosting",
                             self.base_ctx(ports=list(range(1, 40)),
                                           actor_class="application",
                                           reputation={"matched": True, "lists": [
                                               {"name": "x", "type": "malware"}]}))
        self.assertLessEqual(s["score"], 100)


if __name__ == "__main__":
    unittest.main()
