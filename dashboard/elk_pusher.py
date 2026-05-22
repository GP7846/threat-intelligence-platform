"""
dashboard/elk_pusher.py — Syncs MongoDB threat data into Elasticsearch.
Uses the bulk API for efficiency. Creates index + mapping on first run.
Elasticsearch is optional — the platform runs fine without it.
"""

from __future__ import annotations

import json

from database.mongo_handler import MongoHandler
from utils.logger import system_logger
from config.settings import ELASTICSEARCH_URL, ES_INDEX_NAME

try:
    from elasticsearch import Elasticsearch, helpers as es_helpers
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False


_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "indicator":   {"type": "keyword"},
            "type":        {"type": "keyword"},
            "threat_type": {"type": "keyword"},
            "risk_score":  {"type": "integer"},
            "sources":     {"type": "keyword"},
            "tags":        {"type": "keyword"},
            "first_seen":  {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
            "last_seen":   {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
            "blocked_at":  {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
            "is_blocked":  {"type": "boolean"},
            "country":     {"type": "keyword"},
            "port":        {"type": "integer"},
        }
    }
}


class ElkPusher:
    """Streams normalised threat intelligence from MongoDB → Elasticsearch."""

    def __init__(self):
        self.db = MongoHandler()
        self.es = None

        if not ES_AVAILABLE:
            system_logger.warning(
                "[ELK] elasticsearch-py not installed — ELK sync disabled. "
                "Run: pip install elasticsearch"
            )
            return

        try:
            self.es = Elasticsearch(ELASTICSEARCH_URL, request_timeout=10)
            if not self.es.ping():
                system_logger.warning(
                    f"[ELK] Elasticsearch not reachable at {ELASTICSEARCH_URL}. "
                    "ELK sync disabled for this cycle."
                )
                self.es = None
        except Exception as exc:
            system_logger.warning(f"[ELK] Connection error: {exc}. ELK sync disabled.")
            self.es = None

    def _ensure_index(self):
        """Create the index with the correct mapping if it doesn't already exist."""
        try:
            if not self.es.indices.exists(index=ES_INDEX_NAME):
                self.es.indices.create(index=ES_INDEX_NAME, body=_INDEX_MAPPING)
                system_logger.info(f"[ELK] Index '{ES_INDEX_NAME}' created with mapping.")
        except Exception as exc:
            system_logger.error(f"[ELK] Failed to create index: {exc}")

    def push_data(self):
        """Bulk-upsert all MongoDB records into Elasticsearch."""
        if not self.es:
            return

        self._ensure_index()

        threats = self.db.get_all(limit=5000)
        if not threats:
            system_logger.warning("[ELK] No data in MongoDB to synchronise.")
            return

        def _actions():
            for doc in threats:
                yield {
                    "_op_type": "index",
                    "_index":   ES_INDEX_NAME,
                    "_id":      doc.get("indicator"),
                    "_source":  doc,
                }

        try:
            success, errors = es_helpers.bulk(self.es, _actions(), raise_on_error=False)
            system_logger.info(
                f"[ELK] Bulk sync complete — success: {success}, errors: {len(errors)}."
            )
            if errors:
                for err in errors[:5]:   # Log first 5 errors only
                    system_logger.error(f"[ELK] Bulk error: {err}")
        except Exception as exc:
            system_logger.error(f"[ELK] Bulk push failed: {exc}")
