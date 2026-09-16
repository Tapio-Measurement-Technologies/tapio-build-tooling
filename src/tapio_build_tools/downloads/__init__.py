"""Publishing release downloads to a static site in an object store."""

from __future__ import annotations


class DownloadsError(RuntimeError):
    """Publishing release downloads failed."""
