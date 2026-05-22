"""
utils/time_utils.py — UTC timestamp helpers used across the platform.
"""

from datetime import datetime, timezone


def utc_now_str() -> str:
    """Return current UTC time as 'YYYY-MM-DD HH:MM:SS'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def seconds_since(timestamp_str: str) -> float:
    """Return seconds elapsed since a 'YYYY-MM-DD HH:MM:SS' UTC timestamp."""
    try:
        past = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        return (datetime.now(timezone.utc) - past).total_seconds()
    except Exception:
        return -1.0
