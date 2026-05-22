"""
utils/helpers.py — Miscellaneous utility functions.
"""

from __future__ import annotations


def chunks(lst: list, size: int):
    """Yield successive `size`-sized chunks from `lst`."""
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def safe_get(d: dict, *keys, default=None):
    """Safely traverse nested dicts. Returns `default` if any key is missing."""
    val = d
    for key in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(key, default)
    return val


def deduplicate(items: list[dict], key: str) -> list[dict]:
    """Return a deduplicated list of dicts, keeping the first occurrence of each `key`."""
    seen: set = set()
    result: list[dict] = []
    for item in items:
        val = item.get(key)
        if val and val not in seen:
            seen.add(val)
            result.append(item)
    return result
