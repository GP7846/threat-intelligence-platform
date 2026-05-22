"""
tests/test_feeds.py — Integration + unit tests for the TIP pipeline.
Run with: python3 -m pytest tests/ -v
      or: python3 tests/test_feeds.py
"""

import sys
import os
import unittest

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.validator import is_valid_ip, is_valid_domain
from database.mongo_handler import MongoHandler
from feeds.feodo_tracker import FeodoTrackerFeed
from feeds.ssl_blacklist import SSLBlacklistFeed


# ─────────────────────────────────────────────────────────────
#  Unit tests — validator
# ─────────────────────────────────────────────────────────────

class TestValidator(unittest.TestCase):

    def test_valid_public_ipv4(self):
        self.assertTrue(is_valid_ip("185.220.101.45"))
        self.assertTrue(is_valid_ip("8.8.8.8"))

    def test_private_ips_rejected(self):
        self.assertFalse(is_valid_ip("192.168.1.1"))
        self.assertFalse(is_valid_ip("10.0.0.1"))
        self.assertFalse(is_valid_ip("172.16.0.1"))
        self.assertFalse(is_valid_ip("127.0.0.1"))

    def test_invalid_ip_strings(self):
        self.assertFalse(is_valid_ip("not-an-ip"))
        self.assertFalse(is_valid_ip(""))
        self.assertFalse(is_valid_ip("999.999.999.999"))

    def test_valid_domains(self):
        self.assertTrue(is_valid_domain("malicious.example.com"))
        self.assertTrue(is_valid_domain("c2.botnet.ru"))

    def test_invalid_domains(self):
        self.assertFalse(is_valid_domain(""))
        self.assertFalse(is_valid_domain("notadomain"))
        self.assertFalse(is_valid_domain("192.168.1.1"))


# ─────────────────────────────────────────────────────────────
#  Unit tests — risk scoring (no DB connection required)
# ─────────────────────────────────────────────────────────────

class TestRiskScoring(unittest.TestCase):

    def test_single_source_base_score(self):
        score = MongoHandler.calculate_risk_score(["FeodoTracker"], ["botnet"])
        # botnet is a critical tag → 40 + 10 = 50
        self.assertEqual(score, 50)

    def test_two_sources_boost(self):
        score = MongoHandler.calculate_risk_score(
            ["FeodoTracker", "Abuse.ch SSLBL"], ["ransomware"]
        )
        # 65 + 10 = 75
        self.assertEqual(score, 75)

    def test_three_sources_max_base(self):
        score = MongoHandler.calculate_risk_score(
            ["Feed1", "Feed2", "Feed3"], ["unknown"]
        )
        # 85 + 0 = 85
        self.assertEqual(score, 85)

    def test_score_capped_at_100(self):
        score = MongoHandler.calculate_risk_score(
            ["F1", "F2", "F3", "F4"], ["ransomware"]
        )
        self.assertLessEqual(score, 100)


# ─────────────────────────────────────────────────────────────
#  Live feed tests (require network; skipped if unreachable)
# ─────────────────────────────────────────────────────────────

class TestFeodoTrackerFeed(unittest.TestCase):

    def setUp(self):
        self.feed = FeodoTrackerFeed()

    def test_returns_list(self):
        result = self.feed.get_threats()
        self.assertIsInstance(result, list)

    def test_threat_schema(self):
        result = self.feed.get_threats()
        if not result:
            self.skipTest("No live data returned from FeodoTracker.")
        required = {"indicator", "type", "threat_type", "source"}
        for threat in result[:10]:
            self.assertTrue(required.issubset(threat.keys()),
                            f"Missing keys in: {threat}")
            self.assertEqual(threat["type"], "ip")
            self.assertTrue(is_valid_ip(threat["indicator"]),
                            f"Invalid IP in feed: {threat['indicator']}")

    def test_no_private_ips(self):
        result = self.feed.get_threats()
        for threat in result:
            self.assertTrue(
                is_valid_ip(threat["indicator"]),
                f"Private/invalid IP slipped through: {threat['indicator']}"
            )


class TestSSLBlacklistFeed(unittest.TestCase):

    def setUp(self):
        self.feed = SSLBlacklistFeed()

    def test_returns_list(self):
        result = self.feed.get_threats()
        self.assertIsInstance(result, list)

    def test_threat_schema(self):
        result = self.feed.get_threats()
        if not result:
            self.skipTest("No live data returned from SSL Blacklist.")
        for threat in result[:10]:
            self.assertIn("indicator", threat)
            self.assertIn("source",    threat)
            self.assertEqual(threat["type"], "ip")


# ─────────────────────────────────────────────────────────────
#  Full pipeline smoke test
# ─────────────────────────────────────────────────────────────

class TestPipelineSmoke(unittest.TestCase):

    def test_end_to_end_feodo(self):
        """Harvest → validate → attempt DB insert (requires MongoDB)."""
        feed    = FeodoTrackerFeed()
        threats = feed.get_threats()

        if not threats:
            self.skipTest("No data from FeodoTracker — skipping pipeline test.")

        db = MongoHandler()
        if not db.is_connected:
            self.skipTest("MongoDB not running — skipping DB insert test.")

        inserted = 0
        for t in threats[:10]:    # Only process 10 to keep test fast
            if db.insert_threat(t):
                inserted += 1

        print(f"\n[Smoke Test] Inserted/updated {inserted}/10 threats into MongoDB.")
        self.assertGreater(inserted, 0, "Expected at least 1 threat to be stored.")


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  TIP — Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)
