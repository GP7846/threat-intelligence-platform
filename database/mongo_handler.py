"""
database/mongo_handler.py — MongoDB persistence layer.
Responsibilities:
  - Connect with timeout / retry
  - Enforce unique index for deduplication
  - Insert new threats or update existing ones (upsert logic)
  - Compute dynamic risk scores
  - Provide query helpers for the enforcer and dashboard
"""

from __future__ import annotations

from datetime import datetime, timezone

from pymongo import MongoClient, DESCENDING, errors

from config.settings import MONGO_URI, DB_NAME, BLOCK_THRESHOLD
from utils.logger import system_logger

# ── Risk scoring weights ───────────────────────────────────────
_CRITICAL_TAGS = {"ransomware", "apt", "botnet", "qakbot", "banking-trojan",
                  "malicious_ssl", "emotet", "trickbot", "cobalt-strike"}

_BASE_SCORE_BY_SOURCES = {1: 40, 2: 65}   # 3+ → 85


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class MongoHandler:
    """Thread-safe MongoDB interface for the Threat Intelligence Platform."""

    COLLECTION = "indicators"

    def __init__(self):
        self._client: MongoClient | None = None
        self._collection = None
        self._connect()

    # ── Connection ────────────────────────────────────────────
    def _connect(self):
        try:
            self._client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5_000)
            db = self._client[DB_NAME]
            self._collection = db[self.COLLECTION]
            # Confirm connectivity
            self._client.admin.command("ping")
            # Ensure deduplication index exists
            self._collection.create_index("indicator", unique=True)
            system_logger.info("MongoDB connection established successfully.")
        except errors.ServerSelectionTimeoutError:
            system_logger.error(
                "MongoDB connection FAILED. Is mongod running? "
                f"URI attempted: {MONGO_URI}"
            )
            self._client = None

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    # ── Risk scoring ──────────────────────────────────────────
    @staticmethod
    def calculate_risk_score(sources: list[str], tags: list[str]) -> int:
        unique_sources = len(set(sources))
        base = _BASE_SCORE_BY_SOURCES.get(unique_sources, 85 if unique_sources >= 3 else 40)

        tag_set = {t.lower() for t in tags}
        boost = 10 if tag_set & _CRITICAL_TAGS else 0

        return min(base + boost, 100)

    # ── Insert / upsert ───────────────────────────────────────
    def insert_threat(self, threat_data: dict) -> bool:
        """
        Insert a new threat or update an existing one.
        Returns True on success, False on failure.
        """
        if not self.is_connected:
            return False

        indicator    = (threat_data.get("indicator") or "").strip()
        source       = threat_data.get("source", "Unknown")
        threat_type  = threat_data.get("threat_type", "unknown")
        itype        = threat_data.get("type", "ip")
        now          = _utc_now()

        if not indicator:
            return False

        initial_sources = [source]
        initial_tags    = [threat_type]
        score           = self.calculate_risk_score(initial_sources, initial_tags)

        document = {
            "indicator":   indicator,
            "type":        itype,
            "threat_type": threat_type,
            "risk_score":  score,
            "sources":     initial_sources,
            "tags":        initial_tags,
            "first_seen":  now,
            "last_seen":   now,
            "is_blocked":  False,
            # Extra context fields (may be None for some feeds)
            "port":        threat_data.get("port"),
            "country":     threat_data.get("country", ""),
            "as_name":     threat_data.get("as_name", ""),
        }

        try:
            self._collection.insert_one(document)
            return True

        except errors.DuplicateKeyError:
            # Indicator already known — enrich and re-score
            existing = self._collection.find_one({"indicator": indicator})
            if existing:
                updated_sources = list(set(existing.get("sources", []) + [source]))
                updated_tags    = list(set(existing.get("tags",    []) + [threat_type]))
                new_score       = self.calculate_risk_score(updated_sources, updated_tags)

                self._collection.update_one(
                    {"indicator": indicator},
                    {
                        "$set": {
                            "sources":    updated_sources,
                            "tags":       updated_tags,
                            "risk_score": new_score,
                            "last_seen":  now,
                        }
                    },
                )
            return True

        except Exception as exc:
            system_logger.error(f"[MongoDB] Failed to process indicator '{indicator}': {exc}")
            return False

    # ── Query helpers ─────────────────────────────────────────
    def get_high_risk_unblocked(self) -> list[dict]:
        """Return all unblocked IPs above the block threshold, ordered by risk score."""
        if not self.is_connected:
            return []
        return list(
            self._collection.find(
                {"is_blocked": False, "risk_score": {"$gte": BLOCK_THRESHOLD}, "type": "ip"},
                {"_id": 0},
            ).sort("risk_score", DESCENDING)
        )

    def mark_blocked(self, indicator: str) -> bool:
        if not self.is_connected:
            return False
        result = self._collection.update_one(
            {"indicator": indicator},
            {"$set": {"is_blocked": True, "blocked_at": _utc_now()}},
        )
        return result.modified_count > 0

    def mark_unblocked(self, indicator: str) -> bool:
        if not self.is_connected:
            return False
        result = self._collection.update_one(
            {"indicator": indicator},
            {"$set": {"is_blocked": False, "unblocked_at": _utc_now()}},
        )
        return result.modified_count > 0

    def get_all(self, limit: int = 500) -> list[dict]:
        """Return up to `limit` indicators for the dashboard, newest first."""
        if not self.is_connected:
            return []
        return list(
            self._collection.find({}, {"_id": 0})
            .sort("last_seen", DESCENDING)
            .limit(limit)
        )

    def stats(self) -> dict:
        """Return summary statistics for the dashboard."""
        if not self.is_connected:
            return {}
        col = self._collection
        total        = col.count_documents({})
        blocked      = col.count_documents({"is_blocked": True})
        high_risk    = col.count_documents({"risk_score": {"$gte": 70}})
        critical     = col.count_documents({"risk_score": {"$gte": 85}})
        return {
            "total":     total,
            "blocked":   blocked,
            "high_risk": high_risk,
            "critical":  critical,
            "safe":      total - blocked,
        }
