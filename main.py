import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

"""
Advanced Threat Intelligence Platform (TIP) — Master Daemon
"""

import time
import signal
from feeds.feodo_tracker import FeodoTrackerFeed
from feeds.ssl_blacklist import SSLBlacklistFeed
from feeds.alienvault_otx import AlienVaultOTXFeed
from database.mongo_handler import MongoHandler
from enforcer.firewall_enforcer import FirewallEnforcer
from dashboard.elk_pusher import ElkPusher
from utils.logger import system_logger
from utils.validator import is_valid_ip, is_valid_domain

_running = True

def _handle_signal(sig, frame):
    global _running
    system_logger.info("Shutdown signal received. Finishing current cycle then exiting...")
    _running = False

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


def run_pipeline():
    system_logger.info("=" * 60)
    system_logger.info("  STARTING THREAT INTELLIGENCE CYCLE")
    system_logger.info("=" * 60)

    system_logger.info("[Step 1/4] Initialising OSINT feed collectors...")
    raw_threats = []

    feeds = [
        FeodoTrackerFeed(),
        SSLBlacklistFeed(),
        AlienVaultOTXFeed(),
    ]

    for feed in feeds:
        try:
            results = feed.get_threats() or []
            raw_threats.extend(results)
        except Exception as exc:
            system_logger.error(f"Feed '{feed.__class__.__name__}' raised an exception: {exc}")

    system_logger.info(f"[Step 1/4] Collected {len(raw_threats)} raw indicators across all feeds.")

    system_logger.info("[Step 2/4] Validating and normalising indicators...")
    valid_threats = []
    seen = set()

    for threat in raw_threats:
        indicator = threat.get("indicator", "").strip()
        if not indicator or indicator in seen:
            continue
        itype = threat.get("type", "ip")
        if itype == "ip" and not is_valid_ip(indicator):
            continue
        if itype == "domain" and not is_valid_domain(indicator):
            continue
        seen.add(indicator)
        valid_threats.append(threat)

    system_logger.info(f"[Step 2/4] {len(valid_threats)} valid, unique indicators ready for storage.")

    system_logger.info("[Step 3/4] Pushing intelligence to MongoDB...")
    db = MongoHandler()
    processed = sum(1 for t in valid_threats if db.insert_threat(t))
    system_logger.info(f"[Step 3/4] Database sync complete. Processed {processed} indicators.")

    system_logger.info("[Step 4/4] Triggering kernel firewall enforcer...")
    enforcer = FirewallEnforcer()
    enforcer.enforce_policies()

    system_logger.info("[Step 4/4] Synchronising Elasticsearch / dashboard data...")
    pusher = ElkPusher()
    pusher.push_data()

    system_logger.info("=" * 60)
    system_logger.info("  CYCLE COMPLETE — sleeping 5 minutes")
    system_logger.info("=" * 60)


if __name__ == "__main__":
    system_logger.info("Initialising Master Security Daemon (TIP v2.0)...")

    cycle = 0
    while _running:
        cycle += 1
        system_logger.info(f"Cycle #{cycle} starting...")
        try:
            run_pipeline()
        except Exception as exc:
            system_logger.error(f"Critical pipeline failure on cycle #{cycle}: {exc}")
            system_logger.info("Backing off 60 s before retry...")
            time.sleep(60)
            continue

        for _ in range(60):
            if not _running:
                break
            time.sleep(5)

    system_logger.info("Master Daemon shut down cleanly.")
    sys.exit(0)