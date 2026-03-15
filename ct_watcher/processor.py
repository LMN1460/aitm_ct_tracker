"""Certificate message processing for CT Watcher."""

import json
import time
import traceback
from typing import List

from .config import (
    DOMAIN_REGEX,
    SEEN_DOMAINS_LIMIT,
    ALERTED_DOMAINS_LIMIT,
    ALERTED_CERTIFICATES_LIMIT,
    MAX_CERT_AGE_SECONDS,
    HIGH_CONFIDENCE_REGISTRARS,
)
from .state import state
from .domain_checks import is_known_attacker_domain, get_nameservers, get_domain_registrar
from .domain_checks import is_known_attacker_domain, get_nameservers, get_domain_info
from .ip_tracking import get_attacker_ips_for_domain
from .discord import send_discord_alert
from .utils import extract_target_id, is_common_word_id


def _is_high_confidence_registrar(registrar: str | None) -> bool:
    """Check if the registrar is in the high-confidence list."""
    if not registrar:
        return False
    registrar_lower = registrar.lower()
    return any(hc in registrar_lower for hc in HIGH_CONFIDENCE_REGISTRARS)


def _print_stats() -> None:
    """Print processing stats every minute."""
    current_time = time.time()
    if current_time - state.last_stats_time >= 60:
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"[{timestamp_str}] Processed {state.cert_count} certificates in the last minute | Total alerts: {state.total_alerts_count}")
        state.reset_stats()


def _handle_known_attacker(domain: str, all_domains: List[str], cert_id: int, not_before: float | None) -> bool:
    """Handle known attacker domain detection. Returns True if alert was sent."""
    if domain in state.alerted_domains:
        return False
    
    # Get nameserver and registrar info
    is_cloudflare, nameservers_list = get_nameservers(domain)
    registrar, reg_date = get_domain_info(domain)
    
    # Resolve and track IP addresses
    all_ips, non_cdn_ips = get_attacker_ips_for_domain(domain)
    
    print(f"[!] KNOWN ATTACKER DOMAIN DETECTED: {domain} (Registrar: {registrar}, IPs: {len(all_ips)}, Blockable: {len(non_cdn_ips)})")
    
    # Mark as alerted
    if len(state.alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
        state.clear_alerted_certificates()
    state.alerted_certificates.add(cert_id)
    
    if len(state.alerted_domains) > ALERTED_DOMAINS_LIMIT:
        state.clear_alerted_domains()
    state.alerted_domains.add(domain)
    
    # Known attacker domains are always high confidence
    send_discord_alert(
        domain, all_domains,
        cert_timestamp=not_before,
        is_known_attacker=True,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        high_confidence=True,
        reg_date=reg_date
    )
    state.total_alerts_count += 1
    return True


def _handle_pattern_match(domain: str, all_domains: List[str], cert_id: int, not_before: float | None) -> bool:
    """Handle pattern match detection. Returns True if alert was sent."""
    if domain in state.alerted_domains:
        return False
    
    print(f"[+] Potential match: {domain}")
    
    # Only alert if multiple domains in certificate
    if len(all_domains) <= 1:
        print(f"[~] Skipping {domain} (only single domain in certificate)")
        return False
    
    # Get nameserver and registrar info
    is_cloudflare, nameservers_list = get_nameservers(domain)
    registrar, reg_date = get_domain_info(domain)
    
    # Resolve and track IP addresses
    all_ips, non_cdn_ips = get_attacker_ips_for_domain(domain)
    
    # Determine confidence level
    # High confidence only if:
    # 1. The extracted ID matches a known target (in target_mapping), OR
    # 2. Registrar is GoDaddy/Namecheap AND Cloudflare nameservers AND multiple domains AND 8-char hex ID
    # 
    # Unknown 5-char alphanumeric IDs are always low confidence to avoid alert fatigue
    api_id = extract_target_id(domain)
    is_known_target = api_id and api_id in state.target_mapping
    is_suspicious_registrar = _is_high_confidence_registrar(registrar)
    is_8char_hex = api_id and len(api_id) == 8 and all(c in '0123456789abcdef' for c in api_id)
    
    # High confidence requires known target OR (all three conditions + 8-char hex ID)
    high_confidence = bool(
        is_known_target or 
        (is_suspicious_registrar and is_cloudflare and len(all_domains) > 1 and is_8char_hex)
    )
    
    confidence_str = "HIGH" if high_confidence else "LOW"
    cf_status = "Cloudflare" if is_cloudflare else "Non-Cloudflare"
    print(f"[!] ALERT [{confidence_str}]: Multiple domains ({len(all_domains)}), {cf_status} NS: {domain} (Registrar: {registrar}, IPs: {len(all_ips)}, Blockable: {len(non_cdn_ips)})")
    
    if is_known_target and api_id:
        print(f"    -> Known target: {state.target_mapping[api_id]['name']}")
    elif is_suspicious_registrar and is_cloudflare:
        print(f"    -> Suspicious pattern: {registrar} + Cloudflare nameservers")
    elif api_id:
        print(f"    -> Unknown ID: {api_id} (low confidence - manual review)")
    
    # Mark as alerted
    if len(state.alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
        state.clear_alerted_certificates()
    state.alerted_certificates.add(cert_id)
    
    if len(state.alerted_domains) > ALERTED_DOMAINS_LIMIT:
        state.clear_alerted_domains()
    state.alerted_domains.add(domain)
    
    send_discord_alert(
        domain, all_domains,
        cert_timestamp=not_before,
        is_known_attacker=False,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        high_confidence=high_confidence,
        reg_date=reg_date
    )
    state.total_alerts_count += 1
    return True


def process_message(message_str: str) -> None:
    """Process incoming CT log message from certstream server."""
    try:
        try:
            message = json.loads(message_str)
        except json.JSONDecodeError as e:
            print(f"[!] JSON decode error: {e}")
            return

        msg_type = message.get("message_type")
        if msg_type != "certificate_update":
            return

        data = message.get("data", {})
        leaf_cert = data.get("leaf_cert", {})
        all_domains = leaf_cert.get("all_domains", []) or []

        if not all_domains:
            return
        
        # Create unique certificate identifier
        cert_id = hash(tuple(sorted(d.strip().lower() for d in all_domains)))
        
        # Check if already processed
        if cert_id in state.alerted_certificates:
            return
        
        # Check certificate age
        not_before = leaf_cert.get("not_before")
        if not_before:
            try:
                cert_age_seconds = time.time() - not_before
                if cert_age_seconds > MAX_CERT_AGE_SECONDS:
                    return
            except (ValueError, TypeError):
                pass

        # Update stats
        state.cert_count += 1
        _print_stats()

        # Process each domain
        for d in all_domains:
            try:
                domain = d.strip().lower()

                # Dedupe
                if domain in state.seen_domains:
                    continue
                if len(state.seen_domains) > SEEN_DOMAINS_LIMIT:
                    state.clear_seen_domains()
                state.seen_domains.add(domain)

                # Check for known attacker domains first
                if is_known_attacker_domain(domain, state.known_attacker_domains):
                    if _handle_known_attacker(domain, all_domains, cert_id, not_before):
                        break
                    continue

                # Pattern match
                if DOMAIN_REGEX.match(domain):
                    # Extract the ID portion and check if it's a common word
                    api_id = extract_target_id(domain)
                    if api_id and is_common_word_id(api_id):
                        # Skip common words like 'local', 'admin', 'store'
                        continue
                    
                    if _handle_pattern_match(domain, all_domains, cert_id, not_before):
                        break
                        
            except Exception as e:
                print(f"[!] Error processing domain {d}: {e}")
                continue
                
    except Exception as e:
        print(f"[!] Error in process_message: {e}")
        traceback.print_exc()
