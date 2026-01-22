"""File loading functions for CT Watcher."""

import json
import os
from typing import Dict, Set, Any

from .config import (
    KNOWN_DOMAINS_FILE,
    TARGETS_FILE,
    EMAIL_TEMPLATE_FILE,
    ATTACKER_IPS_FILE,
)

DEFAULT_EMAIL_TEMPLATE = """To the Security Team,

I detected new SSL certificate registrations matching known AitM phishing patterns targeting your organization.

IOCs:
{IOCS_LIST}

Context: Likely staging for a credential harvesting campaign. Recommended block on network edge.

Regards"""


def load_known_attacker_domains(filepath: str = KNOWN_DOMAINS_FILE) -> Set[str]:
    """Load known attacker domains from file and un-defang them.
    
    Expected format: one domain per line, defanged like littlenuggetsco[.]com
    """
    domains = set()
    if not os.path.exists(filepath):
        print(f"[*] No known domains file found at {filepath}")
        return domains
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Un-defang: replace [.] with .
                domain = line.replace('[.]', '.').replace('[dot]', '.').lower()
                domains.add(domain)
        print(f"[*] Loaded {len(domains)} known attacker domains")
    except Exception as e:
        print(f"[!] Error loading known domains: {e}")
    
    return domains


def load_target_mapping(filepath: str = TARGETS_FILE) -> Dict[str, Dict[str, str]]:
    """Load target organization mapping from JSON file.
    
    Expected format: {"hex_id": {"name": "Org Name", "email": "email@example.com"}}
    """
    mapping = {}
    if not os.path.exists(filepath):
        print(f"[*] No targets file found at {filepath}")
        return mapping
    
    try:
        with open(filepath, 'r') as f:
            mapping = json.load(f)
        print(f"[*] Loaded {len(mapping)} target organizations")
    except Exception as e:
        print(f"[!] Error loading targets: {e}")
    
    return mapping


def load_email_template(filepath: str = EMAIL_TEMPLATE_FILE) -> str:
    """Load email body template from file. Returns default template if file not found."""
    if not os.path.exists(filepath):
        print(f"[*] No email template found at {filepath}, using default")
        return DEFAULT_EMAIL_TEMPLATE
    
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"[!] Error loading email template: {e}, using default")
        return DEFAULT_EMAIL_TEMPLATE


def load_attacker_ips(filepath: str = ATTACKER_IPS_FILE) -> Dict[str, Any]:
    """Load attacker IPs from JSON file."""
    if not os.path.exists(filepath):
        return {"ips": {}, "last_updated": None}
    
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        print(f"[*] Loaded {len(data.get('ips', {}))} tracked attacker IPs")
        return data
    except Exception as e:
        print(f"[!] Error loading attacker IPs: {e}")
        return {"ips": {}, "last_updated": None}
