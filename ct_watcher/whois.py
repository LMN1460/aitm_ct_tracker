"""WHOIS fallback for domains where RDAP is unavailable.

The WHOIS protocol (RFC 3912) is a simple TCP-based query system.
This module uses whois.iana.org to discover the authoritative WHOIS
server for a TLD, then queries it for registrar and registration date.
"""

import re
import socket
import time
from typing import Dict, Optional, Tuple

_WHOIS_TIMEOUT = 5
_WHOIS_CACHE_TTL = 2592000  # 30 days — WHOIS servers rarely change

# regex patterns for extracting WHOIS server from IANA response
_IANA_WHOIS_RE = re.compile(r"whois:\s+(\S+)")

# regex patterns for extracting registrar name (case-insensitive, multiline)
_REGISTRAR_RES = [
    re.compile(r"^[ \t]*registrar:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*registrar name:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*sponsoring registrar:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    # fallback: some registries put the name on the next line (e.g. .eu)
    re.compile(r"^[ \t]*name:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
]

# regex patterns for extracting creation date
_CREATION_RES = [
    re.compile(r"^[ \t]*creation date:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*created:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*created on[\s.:]*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*registered on:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*registered:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*registered[ \t]+date[\s:]+(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^[ \t]*registration time:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE),
    # .jp uses bracket-delimited Japanese labels: [登録年月日]  2006/05/09
    re.compile(r"登録年月日\]\s*(\d{4}/\d{2}/\d{2})"),
]

# regex to strip trailing URL suffixes from registrar names:
# "MarkMonitor Inc. ( https://nic.at/registrar/434 )" → "MarkMonitor Inc."
_REGISTRAR_URL_RE = re.compile(r"\s*\(\s*https?://[^)]+\)\s*$")

# month-name to number for non-standard date formats
_MONTH_MAP = {
    "jan": "01", "feb": "02", "mar": "03", "apr": "04",
    "may": "05", "jun": "06", "jul": "07", "aug": "08",
    "sep": "09", "oct": "10", "nov": "11", "dec": "12",
}

# TLDs that need a prefix before the domain in the WHOIS query
_QUERY_PREFIXES = {
    "jp": "domain ",
}

# {tld: {"server": str|None, "ts": float}}
_whois_server_cache: Dict[str, dict] = {}


def _whois_query_raw(server: str, query: str) -> str:
    """Send a WHOIS query and return the raw response text."""
    with socket.create_connection((server, 43), timeout=_WHOIS_TIMEOUT) as sock:
        sock.sendall(f"{query}\r\n".encode())
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def _get_whois_server(tld: str) -> Optional[str]:
    """Discover the authoritative WHOIS server for a TLD via whois.iana.org."""
    cached = _whois_server_cache.get(tld)
    if cached and time.time() - cached["ts"] < _WHOIS_CACHE_TTL:
        return cached["server"]

    server = None
    try:
        raw = _whois_query_raw("whois.iana.org", tld)
        match = _IANA_WHOIS_RE.search(raw)
        if match:
            server = match.group(1).strip()
            if not server:
                server = None
    except Exception:
        pass

    _whois_server_cache[tld] = {"server": server, "ts": time.time()}
    return server


def _normalize_date(raw: str) -> Optional[str]:
    """Normalize WHOIS date strings to ISO 8601 (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS).

    Handles several non-standard formats seen across registries:
      .kr:  2007. 03. 02.        → 2007-03-02
      .tr:  2024-Aug-26.         → 2024-08-26
      .cn:  2003-03-17 12:20:05  → 2003-03-17T12:20:05
      .jp:  2006/05/09           → 2006-05-09
    """
    raw = raw.strip()

    # Standard ISO: 1997-09-15 or 1997-09-15T04:00:00Z
    m = re.match(r"^(\d{4}-\d{2}-\d{2})(.*)$", raw)
    if m:
        date = m.group(1)
        time_part = m.group(2).lstrip()
        if time_part:
            if not time_part.startswith("T"):
                time_part = "T" + time_part
            return date + time_part
        return date

    # .kr format: 2007. 03. 02.
    m = re.match(r"(\d{4})\.\s*(\d{2})\.\s*(\d{2})", raw)
    if m:
        return f"{m[1]}-{m[2]}-{m[3]}"

    # .tr format: 2024-Aug-26.
    m = re.match(r"(\d{4})-(\w{3})-(\d{2})", raw)
    if m:
        month = _MONTH_MAP.get(m[2].lower(), "01")
        return f"{m[1]}-{month}-{m[3]}"

    # .jp format: 2006/05/09
    return raw.replace("/", "-")[:10]


def _parse_whois(raw: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract registrar and registration date from a WHOIS response.

    Tries multiple regex patterns in priority order.
    Dates are normalized to YYYY-MM-DD.
    """
    registrar = None
    for pattern in _REGISTRAR_RES:
        match = pattern.search(raw)
        if match:
            registrar = match.group(1).strip()
            registrar = _REGISTRAR_URL_RE.sub("", registrar)
            if registrar:
                break

    reg_date = None
    for pattern in _CREATION_RES:
        match = pattern.search(raw)
        if match:
            reg_date = _normalize_date(match.group(1).strip())
            break

    return (registrar, reg_date)


def whois_lookup(base_domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Full WHOIS lookup — discover server, query, parse.

    Returns (registrar, reg_date) where reg_date is 'YYYY-MM-DD' or None.
    Returns (None, None) on any failure.
    """
    tld = base_domain.rsplit(".", 1)[-1]
    server = _get_whois_server(tld)
    if not server:
        print(
            f"[~] WHOIS lookup failed for {base_domain} "
            f"(no WHOIS server known for TLD \"{tld}\")"
        )
        return (None, None)

    try:
        query = _QUERY_PREFIXES.get(tld, "") + base_domain
        raw = _whois_query_raw(server, query)
    except Exception as e:
        print(f"[~] WHOIS lookup failed for {base_domain} ({e})")
        return (None, None)

    return _parse_whois(raw)
