"""
feeds/feodo_tracker.py — Feodo Tracker botnet IP blocklist feed.
Source: https://feodotracker.abuse.ch  (no API key required)
"""

import requests
from utils.logger import feed_logger
from config.settings import FEODO_TRACKER_URL


class FeodoTrackerFeed:
    """Collects live botnet C2 IPs from the Feodo Tracker JSON blocklist."""

    SOURCE_NAME = "FeodoTracker"

    def __init__(self):
        self.url = FEODO_TRACKER_URL

    def get_threats(self) -> list[dict]:
        feed_logger.info(f"[{self.SOURCE_NAME}] Fetching feed from {self.url}...")
        threats: list[dict] = []

        try:
            resp = requests.get(self.url, timeout=15)
            resp.raise_for_status()

            for entry in resp.json():
                # Only ingest confirmed, live C2 nodes
                if entry.get("status") != "online":
                    continue

                ip = (entry.get("ip_address") or "").strip()
                if not ip:
                    continue

                threat = {
                    "indicator":    ip,
                    "type":         "ip",
                    "threat_type":  entry.get("malware", "botnet").lower(),
                    "source":       self.SOURCE_NAME,
                    "port":         entry.get("port"),          # extra context
                    "country":      entry.get("country", ""),
                    "as_number":    entry.get("as_number", ""),
                    "as_name":      entry.get("as_name",   ""),
                    "raw_status":   entry.get("status",    ""),
                }
                threats.append(threat)

            feed_logger.info(
                f"[{self.SOURCE_NAME}] Extracted {len(threats)} active botnet C2 IPs."
            )

        except requests.exceptions.Timeout:
            feed_logger.error(f"[{self.SOURCE_NAME}] Request timed out.")
        except requests.exceptions.HTTPError as exc:
            feed_logger.error(f"[{self.SOURCE_NAME}] HTTP error: {exc}")
        except Exception as exc:
            feed_logger.error(f"[{self.SOURCE_NAME}] Unexpected error: {exc}")

        return threats
