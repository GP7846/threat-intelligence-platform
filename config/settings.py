"""
config/settings.py — Central configuration loader.
All sensitive values are read from environment variables (or a .env file).
Copy .env.example → .env and fill in your real keys before running.
"""

import os
from dotenv import load_dotenv

load_dotenv()  # reads .env from project root

# ── MongoDB ────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME   = os.getenv("DB_NAME",   "threat_intel")

# ── Enforcer ──────────────────────────────────────────────────
# Minimum risk score (0-100) before an IP is auto-blocked
BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "70"))

# ── OSINT API keys ────────────────────────────────────────────
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY",  "")

# ── Alerting ──────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
SLACK_WEBHOOK_URL   = os.getenv("SLACK_WEBHOOK_URL",   "")

# ── Elasticsearch / ELK ───────────────────────────────────────
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_INDEX_NAME     = os.getenv("ES_INDEX_NAME",     "threat-intelligence")

# ── Dashboard ─────────────────────────────────────────────────
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5000"))
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")

# ── Feed URLs (overridable for testing / mirror sites) ────────
FEODO_TRACKER_URL  = os.getenv(
    "FEODO_TRACKER_URL",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
)
SSL_BLACKLIST_URL  = os.getenv(
    "SSL_BLACKLIST_URL",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
)
