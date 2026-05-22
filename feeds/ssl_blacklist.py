"""
feeds/ssl_blacklist.py — Abuse.ch SSL IP Blacklist feed.
Source: https://sslbl.abuse.ch  (no API key required)
"""

import requests
from utils.logger import feed_logger
from config.settings import SSL_BLACKLIST_URL


class SSLBlacklistFeed:
    """Scrapes the Abuse.ch SSL Certificate Blacklist for malicious IPs."""

    SOURCE_NAME = "Abuse.ch SSLBL"

    def __init__(self):
        self.url = SSL_BLACKLIST_URL

    def get_threats(self) -> list[dict]:
        feed_logger.info(f"[{self.SOURCE_NAME}] Fetching feed from {self.url}...")
        threats: list[dict] = []

        try:
            resp = requests.get(self.url, timeout=15)
            resp.raise_for_status()

            for line in resp.text.splitlines():
                line = line.strip()
                # Skip comment lines and blanks
                if not line or line.startswith("#"):
                    continue

                parts = [p.strip() for p in line.split(",")]
                ip = parts[0]

                if not ip:
                    continue

                # The CSV columns are: ip,port,ssl_fingerprint (where available)
                port   = parts[1] if len(parts) > 1 else None
                ssl_fp = parts[2] if len(parts) > 2 else None

                threat = {
                    "indicator":   ip,
                    "type":        "ip",
                    "threat_type": "malicious_ssl",
                    "source":      self.SOURCE_NAME,
                    "port":        port,
                    "ssl_fp":      ssl_fp,
                }
                threats.append(threat)

            feed_logger.info(
                f"[{self.SOURCE_NAME}] Extracted {len(threats)} malicious SSL IPs."
            )

        except requests.exceptions.Timeout:
            feed_logger.error(f"[{self.SOURCE_NAME}] Request timed out.")
        except requests.exceptions.HTTPError as exc:
            feed_logger.error(f"[{self.SOURCE_NAME}] HTTP error: {exc}")
        except Exception as exc:
            feed_logger.error(f"[{self.SOURCE_NAME}] Unexpected error: {exc}")

        return threats
