"""Tests for the CyberShield risk engine.

Run with:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.risk_engine import (calculate_risk, trust_from_risk,
                                 AUTO_ISOLATE_THRESHOLD, baseline_deviation)


class TestCalculateRisk(unittest.TestCase):
    """Each rule contributes a fixed number of points."""

    def test_clean_device_scores_zero(self):
        risk, reasons, level = calculate_risk({})
        self.assertEqual(risk, 0)
        self.assertEqual(level, "trusted")
        self.assertEqual(reasons, [])

    def test_auth_failures_above_five_adds_twenty(self):
        risk, reasons, _ = calculate_risk({"auth_failures": 6})
        self.assertEqual(risk, 20)
        self.assertTrue(any("authentication failures" in r for r in reasons))

    def test_auth_failures_at_five_adds_nothing(self):
        risk, _, _ = calculate_risk({"auth_failures": 5})
        self.assertEqual(risk, 0)

    def test_unknown_destinations_adds_twenty(self):
        risk, _, _ = calculate_risk({"unknown_destinations": True})
        self.assertEqual(risk, 20)

    def test_port_scan_adds_thirty(self):
        risk, _, _ = calculate_risk({"port_scan": True})
        self.assertEqual(risk, 30)

    def test_traffic_spike_adds_fifteen(self):
        risk, _, _ = calculate_risk({"traffic_spike": True})
        self.assertEqual(risk, 15)

    def test_request_rate_anomaly_adds_fifteen(self):
        risk, _, _ = calculate_risk({"request_rate_anomaly": True})
        self.assertEqual(risk, 15)

    def test_unauthorized_attempts_add_twenty(self):
        risk, _, _ = calculate_risk({"unauthorized_attempts": 1})
        self.assertEqual(risk, 20)

    def test_decoy_interaction_adds_forty_per_hit(self):
        risk, _, _ = calculate_risk({"decoy_interactions": 1})
        self.assertEqual(risk, 40)
        risk2, _, _ = calculate_risk({"decoy_interactions": 2})
        self.assertEqual(risk2, 80)

    def test_baseline_deviation_adds_fifteen(self):
        risk, _, _ = calculate_risk({"baseline_deviation": True})
        self.assertEqual(risk, 15)

    def test_risk_is_capped_at_100(self):
        risk, _, _ = calculate_risk({
            "auth_failures": 50, "unknown_destinations": True, "port_scan": True,
            "traffic_spike": True, "request_rate_anomaly": True,
            "unauthorized_attempts": 5, "decoy_interactions": 5,
            "baseline_deviation": True})
        self.assertEqual(risk, 100)

    def test_levels_match_thresholds(self):
        for features, expected in (
            ({}, "trusted"),
            ({"port_scan": True}, "trusted"),                      # 30
            ({"port_scan": True, "traffic_spike": True}, "suspicious"),   # 45
            ({"port_scan": True, "traffic_spike": True,
              "unknown_destinations": True}, "high"),               # 65
            ({"port_scan": True, "traffic_spike": True,
              "unknown_destinations": True,
              "auth_failures": 6}, "critical"),                     # 85
        ):
            _, _, level = calculate_risk(features)
            self.assertEqual(level, expected, features)

    def test_trust_is_the_complement_of_risk(self):
        self.assertEqual(trust_from_risk(0), 100)
        self.assertEqual(trust_from_risk(45), 55)
        self.assertEqual(trust_from_risk(100), 0)

    def test_isolation_threshold(self):
        self.assertEqual(AUTO_ISOLATE_THRESHOLD, 80)
        risk, _, _ = calculate_risk({"decoy_interactions": 2})
        self.assertGreaterEqual(risk, AUTO_ISOLATE_THRESHOLD)


class TestBaselineDeviation(unittest.TestCase):
    """A device is judged against its own recorded profile."""

    BASE = {"connections": 30, "destinations": 3, "port_attempts": 5,
            "request_freq": 30, "traffic": 120}

    def test_no_baseline_means_no_deviation(self):
        self.assertFalse(baseline_deviation(self.BASE, {}))

    def test_normal_behaviour_is_not_a_deviation(self):
        self.assertFalse(baseline_deviation(self.BASE, dict(self.BASE)))

    def test_large_increase_is_a_deviation(self):
        spiked = dict(self.BASE, connections=200, traffic=900)
        self.assertTrue(baseline_deviation(spiked, self.BASE))

    def test_small_jitter_is_not_a_deviation(self):
        jitter = dict(self.BASE, connections=40, traffic=140)
        self.assertFalse(baseline_deviation(jitter, self.BASE))

    def test_a_busy_device_is_not_punished_for_being_busy(self):
        busy = {"connections": 400, "destinations": 60, "port_attempts": 30,
                "request_freq": 500, "traffic": 4000}
        self.assertFalse(baseline_deviation(busy, busy))


if __name__ == "__main__":
    unittest.main()
