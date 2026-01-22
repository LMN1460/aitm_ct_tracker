"""Utility functions for CT Watcher."""

import re


def defang_domain(domain: str) -> str:
    """Defang a domain by replacing dots with [.]"""
    return domain.replace('.', '[.]')


def extract_target_id(domain: str) -> str | None:
    """Extract the ID from a domain matching our pattern.
    
    Returns the ID (5-char alphanumeric or 8-char hex) or None if not found.
    """
    match = re.match(r"^api-([0-9a-fA-F]{8}|[0-9a-zA-Z]{5})[\.\-]", domain, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def get_base_domain(domain: str) -> str:
    """Extract base domain (last two parts) from a domain."""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain
