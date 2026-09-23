"""Keeping a build's outputs in a private bucket, one prefix per build."""

from __future__ import annotations


class ArchiveError(RuntimeError):
    """Archiving a build failed."""
