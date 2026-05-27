"""Utility functions for CT Watcher."""

import re
import time

from .config import COMMON_WORDS_5CHAR, COMMON_WORDS_8CHAR


def defang_domain(domain: str) -> str:
    """Defang a domain by replacing dots with [.]"""
    return domain.replace(".", "[.]")


def extract_target_id(domain: str) -> str | None:
    """Extract the ID from a domain matching our pattern.

    Returns the ID (5-8 char alphanumeric) or None if not found.
    """
    match = re.match(r"^api-([0-9a-zA-Z]{5,8})[\.\-]", domain, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def is_common_word_id(api_id: str | None) -> bool:
    """Check if the API ID is a common English word (false positive).

    Returns True if the ID appears to be a common word and should be filtered.
    Returns False if:
      - The ID contains digits (intentional obfuscation like 'admin1')
      - The ID is not in our common words list
    """
    if not api_id:
        return False

    api_id_lower = api_id.lower()

    # If it contains any digits, it's likely intentional (e.g., 'adm1n', '3dse1')
    # These should NOT be filtered - they look like target IDs
    if any(c.isdigit() for c in api_id_lower):
        return False

    # Check against our word lists based on length
    if len(api_id_lower) == 5:
        return api_id_lower in COMMON_WORDS_5CHAR
    elif len(api_id_lower) == 8:
        return api_id_lower in COMMON_WORDS_8CHAR

    return False


def get_base_domain(domain: str) -> str:
    """Extract base domain (last two parts) from a domain."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def calculate_freshness(cert_timestamp: float | None, fmt: str = "discord") -> str:
    """Calculate certificate freshness string.

    Args:
        cert_timestamp: Unix timestamp of certificate not_before, or None.
        fmt: Output format — "discord" for <t:unix:R>, "plain" for human-readable text.

    Returns:
        Formatted freshness string, or "Unknown" if timestamp is None.
    """
    if cert_timestamp is None:
        return "Unknown"

    if fmt == "discord":
        return f"<t:{int(cert_timestamp)}:R>"

    age_seconds = int(max(0, time.time() - cert_timestamp))
    if age_seconds < 60:
        return f"{age_seconds} seconds"
    if age_seconds < 3600:
        return f"{age_seconds // 60} minutes"
    return f"{age_seconds // 3600} hours"
