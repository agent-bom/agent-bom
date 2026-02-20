"""Shared base types for cloud provider discovery modules."""

from __future__ import annotations


class CloudDiscoveryError(Exception):
    """Raised when a cloud provider SDK is missing or an API call fails."""
