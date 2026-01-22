"""Domain checking functions - nameservers, registrar, attacker domain matching."""

import subprocess
from typing import List, Set, Tuple

from .utils import get_base_domain


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
