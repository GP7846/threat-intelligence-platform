"""
feeds/alienvault_otx.py — AlienVault Open Threat Exchange (OTX) feed.
Requires: ALIENVAULT_API_KEY set in .env
Docs: https://otx.alienvault.com/api
"""

import requests
from utils.logger import feed_logger
from config.settings import ALIENVAULT_API_KEY

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Pulse subscriptions to harvest (curated high-signal lists)
SUBSCRIBED_PULSES = [
    "malicious-ips",
    "banking-trojan",
    "botnet-c2",
]


class AlienVaultOTXFeed:
    """
    Fetches malicious IP and domain indicators from AlienVault OTX.
    Falls back gracefully if no API key is configured.
    """

    SOURCE_NAME = "AlienVault OTX"

    def __init__(self):
        self.api_key = ALIENVAULT_API_KEY
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

    def get_threats(self) -> list[dict]:
        if not self.api_key:
            feed_logger.warning(
                f"[{self.SOURCE_NAME}] No API key set — skipping feed. "
                "Set ALIENVAULT_API_KEY in your .env file."
            )
            return []

        feed_logger.info(f"[{self.SOURCE_NAME}] Fetching subscribed pulse indicators...")
        threats: list[dict] = []

        try:
            # Pull from the subscribed pulses endpoint (last 30 days)
            url = f"{OTX_BASE_URL}/pulses/subscribed"
            params = {"limit": 20, "page": 1}
            resp = requests.get(url, headers=self.headers, params=params, timeout=20)
            resp.raise_for_status()

            pulses = resp.json().get("results", [])
            feed_logger.info(f"[{self.SOURCE_NAME}] Processing {len(pulses)} pulses...")

            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    itype = indicator.get("type", "").lower()
                    value = (indicator.get("indicator") or "").strip()

                    if not value:
                        continue

                    # Map OTX types to our normalised types
                    if itype in ("ipv4", "ipv6"):
                        norm_type = "ip"
                    elif itype in ("domain", "hostname", "url"):
                        norm_type = "domain"
                    else:
                        continue  # Skip hashes, emails, etc.

                    threat = {
                        "indicator":   value,
                        "type":        norm_type,
                        "threat_type": pulse.get("name", "unknown").lower(),
                        "source":      self.SOURCE_NAME,
                        "pulse_id":    pulse.get("id", ""),
                        "pulse_tags":  pulse.get("tags", []),
                        "tlp":         pulse.get("tlp", "white"),
                    }
                    threats.append(threat)

            feed_logger.info(
                f"[{self.SOURCE_NAME}] Extracted {len(threats)} indicators from OTX pulses."
            )

        except requests.exceptions.Timeout:
            feed_logger.error(f"[{self.SOURCE_NAME}] Request timed out.")
        except requests.exceptions.HTTPError as exc:
            feed_logger.error(f"[{self.SOURCE_NAME}] HTTP error: {exc}")
        except Exception as exc:
            feed_logger.error(f"[{self.SOURCE_NAME}] Unexpected error: {exc}")

        return threats
