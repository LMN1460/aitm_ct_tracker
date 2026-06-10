"""Custom RDAP client for domain lookups.

RDAP (Registration Data Access Protocol) is the modern replacement for WHOIS.
It returns structured JSON instead of free-text, making it easier to parse
registrar name and registration dates reliably.

This module uses the IANA bootstrap registry to find the correct RDAP server
for each TLD, with a local override file for ccTLDs that have working RDAP
servers but aren't registered with IANA yet.
"""

import json
import os
import tempfile
import time
from typing import Dict, Optional, Tuple

import requests

from .utils import get_base_domain
from .whois import whois_lookup

# --- constants ---
_OVERRIDES_FILE = os.path.join(os.path.dirname(__file__), "rdap_overrides.json")
_BOOTSTRAP_FILE = os.path.join(tempfile.gettempdir(), "ct_tracker_iana_rdap.json")
_BOOTSTRAP_TTL = 86400  # refresh IANA bootstrap every 24h
_REQUEST_TIMEOUT = 5
_CACHE_TTL = 3600  # 1h per-domain cache
_HEADERS = {"Accept": "application/rdap+json"}


# --- internal state (lazy-loaded) ---
_overrides_cache: Optional[Dict[str, str]] = None
_bootstrap_cache: Optional[Dict[str, str]] = None
_domain_cache: Dict[str, Tuple] = {}


def _load_overrides() -> Dict[str, str]:
    """Load local RDAP server overrides from JSON file."""
    global _overrides_cache
    if _overrides_cache is None:
        try:
            with open(_OVERRIDES_FILE) as f:
                _overrides_cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            _overrides_cache = {}
    return _overrides_cache


def _load_iana_bootstrap() -> Dict[str, str]:
    """Load IANA RDAP bootstrap registry.

    Tries a local cache file first; downloads fresh if missing or stale.
    The IANA file format is a JSON object with a "services" key:
        services: list of [[tld1, tld2, ...], [url1, url2, ...]] pairs.
    An empty URL list means the TLD has no registered RDAP server.
    """
    global _bootstrap_cache
    if _bootstrap_cache is not None:
        return _bootstrap_cache

    # Try local cache
    try:
        mtime = os.path.getmtime(_BOOTSTRAP_FILE)
        if time.time() - mtime < _BOOTSTRAP_TTL:
            with open(_BOOTSTRAP_FILE) as f:
                data = json.load(f)
            _bootstrap_cache = _parse_iana_services(data)
            return _bootstrap_cache
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    # Download fresh
    resp = requests.get(
        "https://data.iana.org/rdap/dns.json",
        timeout=_REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    try:
        with open(_BOOTSTRAP_FILE, "w") as f:
            json.dump(data, f)
    except OSError:
        pass

    _bootstrap_cache = _parse_iana_services(data)
    return _bootstrap_cache


def _parse_iana_services(data: dict) -> Dict[str, str]:
    """Flatten IANA bootstrap services into {tld: first_url} mapping."""
    result = {}
    for tlds, urls in data.get("services", []):
        if urls:
            url = urls[0]
            for tld in tlds:
                result[tld] = url
    return result


def _get_rdap_server(tld: str) -> Optional[str]:
    """Return the RDAP server URL for a TLD.

    Checks local overrides first, then falls back to the IANA bootstrap.
    """
    overrides = _load_overrides()
    if tld in overrides:
        return overrides[tld]
    try:
        bootstrap = _load_iana_bootstrap()
    except Exception as e:
        print(f"[!] IANA bootstrap download failed: {e}")
        bootstrap = {}
    return bootstrap.get(tld)


def _parse_registrar(data: dict) -> Optional[str]:
    """Extract registrar name from RDAP response.

    Two formats used in practice:
    1. Direct string: entity.fn = "NameSilo, LLC"
    2. jCard vCardArray: ["vcard", [
         ["fn", {}, "text", "NameSilo, LLC"]
       ]]
    """
    for entity in data.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        # Direct fn field — some registries use this
        if entity.get("fn"):
            return entity["fn"]
        # jCard format — walk properties array for the "fn" property
        vcard = entity.get("vcardArray")
        if vcard and len(vcard) > 1:
            for prop in vcard[1]:  # vcard[1] is the properties list
                # Each property is: ["name", {params}, "type", "value"]
                if prop[0] == "fn" and len(prop) >= 4:
                    return prop[3]  # prop[3] is the value
    return None


def _parse_reg_date(data: dict) -> Optional[str]:
    """Extract registration date (ISO 8601) from RDAP events."""
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            date_str = event.get("eventDate", "")
            return date_str if date_str else None
    return None


def _query_rdap_server(base_domain: str, server: str) -> Optional[dict]:
    """Make the RDAP HTTP request. Returns parsed JSON dict or None on failure.

    Handles network errors and non-2xx status codes uniformly.
    """
    try:
        resp = requests.get(
            f"{server.rstrip('/')}/domain/{base_domain}",
            headers=_HEADERS,
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.Timeout:
        print(f"[~] RDAP lookup timed out for {base_domain}")
        return None
    except Exception as e:
        print(f"[~] RDAP lookup failed for {base_domain} ({e})")
        return None

    if resp.status_code == 200:
        return resp.json()

    print(f"[~] RDAP lookup failed for {base_domain} (HTTP {resp.status_code})")
    return None


def _get_cached(base_domain: str) -> Optional[Tuple[Optional[str], Optional[str]]]:
    """Return cached result if still within TTL, else None."""
    if base_domain in _domain_cache:
        registrar, reg_date, cached_at = _domain_cache[base_domain]
        if time.time() - cached_at < _CACHE_TTL:
            return (registrar, reg_date)
    return None


def _lookup_domain(base_domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve TLD → RDAP server → query → parse, with WHOIS fallback.

    WHOIS is only used when the TLD has no known RDAP server.
    For TLDs with RDAP, a transient failure (404, timeout) returns (None, None).
    """
    tld = base_domain.rsplit(".", 1)[-1]
    server = _get_rdap_server(tld)
    if server:
        data = _query_rdap_server(base_domain, server)
        if data is not None:
            return (_parse_registrar(data), _parse_reg_date(data))
        return (None, None)

    return whois_lookup(base_domain)


def get_domain_info(domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Get registrar and registration date for a domain.

    Results are cached for 1 hour.
    Returns: (registrar, reg_date) where reg_date is 'YYYY-MM-DD' or None.
    """
    base_domain = get_base_domain(domain)

    cached = _get_cached(base_domain)
    if cached is not None:
        return cached

    result = _lookup_domain(base_domain)
    _domain_cache[base_domain] = (result[0], result[1], time.time())
    return result
