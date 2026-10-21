"""Tests for the network scoring model and the IP purpose model."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import policy
from backend import threat_model


class TestNetworkScoring(unittest.TestCase):
    """policy.score_network: deterministic score, verdict and reasons."""

    def score(self, security, **kw):
        net = {"ssid": "TestNet", "security": security}
        net.update(kw)
        return policy.score_network(net, kw.pop("variants", {}), kw.pop("public_hint", False))

    def test_open_network_scores_85_and_is_avoid(self):
        score, verdict, reasons = self.score("Open")
        self.assertEqual(score, 85)
        self.assertEqual(verdict, "avoid")
        self.assertTrue(any("No encryption" in r for r in reasons))

    def test_wep_scores_92_and_is_avoid(self):
        score, verdict, _ = self.score("WEP")
        self.assertEqual(score, 92)
        self.assertEqual(verdict, "avoid")

    def test_wpa2_scores_15_and_is_connect(self):
        score, verdict, _ = self.score("WPA2 Personal")
        self.assertEqual(score, 15)
        self.assertEqual(verdict, "connect")

    def test_wpa3_scores_5_and_is_connect(self):
        score, verdict, _ = self.score("WPA3 Personal")
        self.assertEqual(score, 5)
        self.assertEqual(verdict, "connect")

    def test_unknown_security_scores_60(self):
        score, verdict, _ = self.score("Unknown")
        self.assertEqual(score, 60)
        self.assertEqual(verdict, "caution")

    def test_public_hotspot_floors_wpa2_at_45(self):
        net = {"ssid": "FreeAirportWiFi", "security": "WPA2 Personal"}
        score, verdict, _ = policy.score_network(net, {}, True)
        self.assertEqual(score, 45)
        self.assertEqual(verdict, "caution")

    def test_divergent_security_on_same_ssid_adds_15(self):
        net = {"ssid": "CoffeeShop", "security": "WPA2 Personal"}
        variants = {"CoffeeShop": {("1", "WPA2 Personal"), ("6", "Open")}}
        score, _, reasons = policy.score_network(net, variants, False)
        self.assertEqual(score, 30)
        self.assertTrue(any("evil twin" in r for r in reasons))

    def test_same_security_on_two_channels_adds_nothing(self):
        """Dual-band routers advertise the same SSID on two channels."""
        net = {"ssid": "HomeWifi", "security": "WPA2 Personal"}
        variants = {"HomeWifi": {("1", "WPA2 Personal"), ("6", "WPA2 Personal")}}
        score, _, _ = policy.score_network(net, variants, False)
        self.assertEqual(score, 15)

    def test_weak_signal_adds_5(self):
        score, _, _ = self.score("WPA2 Personal", signal_dbm=-85)
        self.assertEqual(score, 20)

    def test_score_never_leaves_the_range(self):
        for sec in ("Open", "WEP", "WPA", "WPA2", "WPA3", "Unknown"):
            score, _, _ = self.score(sec, signal_dbm=-100)
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)

    def test_verdict_thresholds(self):
        # WPA2 (15) -> connect, WPA (75) -> avoid, unknown (60) -> caution
        self.assertEqual(policy.score_network({"security": "WPA2"}, {}, False)[1], "connect")
        self.assertEqual(policy.score_network({"security": "Unknown"}, {}, False)[1], "caution")
        self.assertEqual(policy.score_network({"security": "WPA"}, {}, False)[1], "avoid")
        self.assertEqual(policy.score_network({"security": "WEP"}, {}, False)[1], "avoid")


class TestThreatModel(unittest.TestCase):
    def test_proximity_zones(self):
        self.assertEqual(threat_model.proximity(-45)["zone"], "same room")
        self.assertEqual(threat_model.proximity(-60)["zone"], "nearby")
        self.assertEqual(threat_model.proximity(-75)["zone"], "far")
        self.assertEqual(threat_model.proximity(-95)["zone"], "edge of range")
        self.assertEqual(threat_model.proximity(None)["zone"], "unknown")

    def test_every_security_class_has_a_threat_list(self):
        for cls in ("open", "wep", "wpa", "wpa2", "wpa3", "unknown"):
            self.assertIn(cls, threat_model.CATALOG)
            self.assertTrue(threat_model.CATALOG[cls])

    def test_assess_marks_the_current_network(self):
        nets = [{"ssid": "Mine", "security": "WPA2 Personal", "is_current": True,
                 "signal_dbm": -50, "channel": "1"}]
        out = threat_model.assess(nets)
        self.assertEqual(out[0]["recommendation"]["verdict"], "connect")
        self.assertTrue(any("you are on now" in r
                            for r in out[0]["recommendation"]["reasons"]))


if __name__ == "__main__":
    unittest.main()
