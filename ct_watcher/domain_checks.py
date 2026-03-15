"""Domain checking functions - nameservers, registrar, attacker domain matching."""

import subprocess
from typing import List, Set, Tuple
import time
import whoisit
from typing import Dict, List, Optional, Set, Tuple

from .utils import get_base_domain


# RDAP bootstrap state and cache
_rdap_bootstrapped = False
_rdap_cache: Dict[str, tuple] = {}  # base_domain -> (registrar, reg_date, timestamp)
_RDAP_CACHE_TTL = 3600  # 1 hour


def _ensure_rdap_bootstrapped() -> bool:
    global _rdap_bootstrapped
    if not _rdap_bootstrapped:
        try:
            whoisit.bootstrap()
            _rdap_bootstrapped = True
        except Exception as e:
            print(f"[!] RDAP bootstrap failed: {e}")
            return False
    return True


def is_known_attacker_domain(domain: str, known_domains: Set[str]) -> bool:
    """Check if domain or its base domain matches known attacker domains."""
    domain = domain.lower().strip()
    
    # Check if exact match
    if domain in known_domains:
        return True
    
    # Check if base domain matches
    parts = domain.split('.')
    if len(parts) >= 2:
        # Check all possible base domains
        # e.g., for api.sub.example.com, check sub.example.com and example.com
        for i in range(len(parts) - 1):
            base = '.'.join(parts[i:])
            if base in known_domains:
                return True
    
    return False


def get_nameservers(domain: str) -> Tuple[bool, List[str]]:
    """Get nameservers for a domain.
    
    Returns tuple of (is_cloudflare, nameservers_list).
    """
    try:
        base_domain = get_base_domain(domain)
        
        # Get nameservers using dig
        result = subprocess.run(
            ["dig", "+short", "NS", base_domain],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        nameservers_output = result.stdout.strip()
        if not nameservers_output:
            return (False, [])
        
        # Parse nameservers (one per line)
        nameservers_list = [
            ns.strip().rstrip('.') 
            for ns in nameservers_output.split('\n') 
            if ns.strip()
        ]
        
        # Check if Cloudflare
        is_cloudflare = any(
            "cloudflare" in ns.lower() or "ns.cloudflare.com" in ns.lower() 
            for ns in nameservers_list
        )
        
        return (is_cloudflare, nameservers_list)
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout checking nameservers for {domain}")
    except FileNotFoundError:
        print(f"[!] dig command not found, cannot get nameservers for {domain}")
    except Exception as e:
        print(f"[!] Error checking nameservers for {domain}: {e}")
    
    return (False, [])


def get_domain_registrar(domain: str) -> str | None:
    """Get the registrar for a domain via whois. Returns registrar name or None."""
    try:
        base_domain = get_base_domain(domain)
        
        # Run whois command
        result = subprocess.run(
            ["whois", base_domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        whois_output = result.stdout.lower()
        
        # Try to identify common registrars
        registrar_patterns = [
            (["godaddy", "wild west domains"], "GoDaddy"),
            (["namecheap"], "Namecheap"),
            (["cloudflare"], "Cloudflare"),
            (["tucows"], "Tucows"),
            (["gandi"], "Gandi"),
            (["google"], "Google Domains"),
        ]
        
        for patterns, name in registrar_patterns:
            if any(p in whois_output for p in patterns):
                return name
        
        # Try to extract registrar from common field
        for line in result.stdout.split('\n'):
            if 'registrar:' in line.lower():
                registrar = line.split(':', 1)[1].strip()
                return registrar if registrar else None
        
        return None
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout checking whois for {domain}")
    except FileNotFoundError:
        print(f"[!] whois command not found, cannot get registrar for {domain}")
    except Exception as e:
        print(f"[!] Error checking whois for {domain}: {e}")


    return None


def get_domain_info(domain: str) -> tuple:
    """Get registrar and registration date for a domain.

    Tries RDAP first (structured JSON), falls back to WHOIS for unsupported TLDs.
    Results are cached for 1 hour to avoid rate limits.

    Returns:
        (registrar, reg_date) where reg_date is 'YYYY-MM-DD' string or None.
    """
    base_domain = get_base_domain(domain)

    # Check cache
    now = time.time()
    if base_domain in _rdap_cache:
        registrar, reg_date, cached_at = _rdap_cache[base_domain]
        if now - cached_at < _RDAP_CACHE_TTL:
            return (registrar, reg_date)

    registrar = None
    reg_date = None

    # Try RDAP first
    try:
        if _ensure_rdap_bootstrapped():
            result = whoisit.domain(base_domain)

            # Registrar lives under entities['registrar'][0]['name']
            entities = result.get('entities', {})
            reg_entities = entities.get('registrar', [])
            if reg_entities and reg_entities[0].get('name'):
                registrar = reg_entities[0]['name']

            # Registration date
            rd = result.get('registration_date')
            if rd:
                reg_date = rd.strftime('%Y-%m-%d') if hasattr(rd, 'strftime') else str(rd)[:10]
    except Exception as e:
        print(f"[~] RDAP lookup failed for {base_domain} ({e}), trying WHOIS")
        # Fall back to WHOIS for registrar (no reg date available from WHOIS)
        registrar = get_domain_registrar(domain)

    _rdap_cache[base_domain] = (registrar, reg_date, now)
    return (registrar, reg_date)
