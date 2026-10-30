"""Identifiers and time stamps the program writes: one format each.

Both formats are on disk already (run folders, request receipts, reports), so they never change.
"""
from __future__ import annotations
from datetime import datetime, timezone
import uuid

__all__ = ['new_id', 'utc_now']


def new_id() -> str:
    """A fresh random identifier: 32 lowercase hexadecimal characters (runs, requests, instances, profiles)."""
    return uuid.uuid4().hex


def utc_now() -> str:
    """The current time in UTC as ISO 8601 with its offset, such as 2026-10-30T12:00:00.123456+00:00."""
    return datetime.now(timezone.utc).isoformat()
