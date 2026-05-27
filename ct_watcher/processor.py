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
    DISCORD_WEBHOOK,
    DISCORD_WEBHOOK_WATCHED,
    APPRISE_URLS,
    APPRISE_URLS_WATCHED,
)
from .state import state
from .domain_checks import is_known_attacker_domain, get_nameservers, get_domain_info
from .ip_tracking import (
    get_attacker_ips_for_domain,
    resolve_and_classify,
    track_resolved_ips,
)
from .discord import send_discord_alert
from .apprise import send_apprise_alert
from .email_sender import send_automated_target_email
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
        print(
            f"[{timestamp_str}] Processed {state.cert_count} certificates"
            f" in the last minute | Total alerts: {state.total_alerts_count}"
        )
        state.reset_stats()


def _dispatch_alert(
    domain: str,
    all_domains: List[str],
    not_before: float | None,
    is_known_attacker: bool,
    registrar: str | None,
    is_cloudflare: bool,
    nameservers_list: List[str] | None,
    all_ips: List[str] | None,
    non_cdn_ips: List[str] | None,
    confirmed_attacker_ip_matches: List[str] | None,
    reg_date: str | None,
    email_status_details: str,
    email_status_state: str,
    target_info: dict | None,
    api_id: str | None,
) -> None:
    """Send alert to all configured notification channels (Discord and/or Apprise)."""
    # Determine watched org channels
    is_watched = api_id is not None and api_id in state.watched_org_ids
    watched_discord = DISCORD_WEBHOOK_WATCHED if is_watched else None
    watched_apprise = None
    if is_watched and APPRISE_URLS_WATCHED:
        watched_apprise = [u.strip() for u in APPRISE_URLS_WATCHED.split(",") if u.strip()]

    # Discord
    if DISCORD_WEBHOOK:
        send_discord_alert(
            domain,
            all_domains,
            cert_timestamp=not_before,
            is_known_attacker=is_known_attacker,
            registrar=registrar,
            is_cloudflare=is_cloudflare,
            nameservers=nameservers_list,
            all_ips=all_ips,
            non_cdn_ips=non_cdn_ips,
            confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
            reg_date=reg_date,
            email_status=email_status_details,
            email_status_state=email_status_state,
            extra_webhook_url=watched_discord,
            target_info=target_info,
        )

    # Apprise
    if APPRISE_URLS or watched_apprise:
        send_apprise_alert(
            domain,
            all_domains,
            cert_timestamp=not_before,
            is_known_attacker=is_known_attacker,
            registrar=registrar,
            is_cloudflare=is_cloudflare,
            nameservers=nameservers_list,
            all_ips=all_ips,
            non_cdn_ips=non_cdn_ips,
            confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
            reg_date=reg_date,
            email_status=email_status_details,
            target_info=target_info,
            extra_urls=watched_apprise,
        )


def _handle_known_attacker(
    domain: str, all_domains: List[str], cert_id: int, not_before: float | None
) -> bool:
    """Handle known attacker domain detection. Returns True if alert was sent."""
    with state.lock:
        if domain in state.alerted_domains:
            return False
        if len(state.alerted_domains) > ALERTED_DOMAINS_LIMIT:
            state.clear_alerted_domains()
        state.alerted_domains.add(domain)
        if len(state.alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
            state.clear_alerted_certificates()
        state.alerted_certificates.add(cert_id)

    # Get nameserver and registrar info
    is_cloudflare, nameservers_list = get_nameservers(domain)
    registrar, reg_date = get_domain_info(domain)

    # Resolve and track IP addresses
    all_ips, non_cdn_ips = get_attacker_ips_for_domain(domain)
    confirmed_attacker_ip_matches = sorted(ip for ip in all_ips if ip in state.known_attacker_ips)

    print(
        f"[!] KNOWN ATTACKER DOMAIN DETECTED: {domain}"
        f" (Registrar: {registrar}, IPs: {len(all_ips)},"
        f" Blockable: {len(non_cdn_ips)})"
    )

    # Known attacker domains are always high confidence
    api_id = extract_target_id(domain)
    target_info = state.target_mapping.get(api_id) if api_id else None

    # If no target found from the matched domain, scan all cert domains for an api-<id> beacon
    if not target_info:
        for d in all_domains:
            candidate_id = extract_target_id(d.strip().lower())
            if candidate_id in state.target_mapping:
                api_id = candidate_id
                target_info = state.target_mapping[api_id]
                break

    email_status = send_automated_target_email(
        target_info=target_info,
        domain=domain,
        all_domains=all_domains,
        non_cdn_ips=non_cdn_ips,
        api_id=api_id,
    )

    _dispatch_alert(
        domain=domain,
        all_domains=all_domains,
        not_before=not_before,
        is_known_attacker=True,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers_list=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
        reg_date=reg_date,
        email_status_details=email_status.details,
        email_status_state=email_status.state,
        target_info=target_info,
        api_id=api_id,
    )
    state.total_alerts_count += 1
    return True


def _handle_pattern_match(
    domain: str, all_domains: List[str], cert_id: int, not_before: float | None
) -> bool:
    """Handle pattern match detection. Returns True if alert was sent."""
    with state.lock:
        if domain in state.alerted_domains:
            return False
        if len(state.alerted_domains) > ALERTED_DOMAINS_LIMIT:
            state.clear_alerted_domains()
        state.alerted_domains.add(domain)

    print(f"[+] Potential match: {domain}")

    # Only alert if multiple domains in certificate
    if len(all_domains) <= 1:
        print(f"[~] Skipping {domain} (only single domain in certificate)")
        return False

    # Get nameserver and registrar info
    is_cloudflare, nameservers_list = get_nameservers(domain)
    registrar, reg_date = get_domain_info(domain)

    # Resolve IPs for confidence check — tracking deferred until high confidence confirmed
    all_ips, non_cdn_ips = resolve_and_classify(domain)
    confirmed_attacker_ip_matches = sorted(ip for ip in all_ips if ip in state.known_attacker_ips)

    # Determine confidence level
    # High confidence only if:
    # 1. The extracted ID matches a known target (in target_mapping), OR
    # 2. Registrar is GoDaddy/Namecheap AND Cloudflare nameservers AND
    #    multiple domains AND 8-char hex ID
    #
    # Unknown 5-char alphanumeric IDs are always low confidence to avoid
    # alert fatigue
    api_id = extract_target_id(domain)
    is_known_target = api_id in state.target_mapping
    is_suspicious_registrar = _is_high_confidence_registrar(registrar)
    is_8char_hex = api_id and len(api_id) == 8 and all(c in "0123456789abcdef" for c in api_id)

    # High confidence requires known target OR a suspicious infra pattern OR a confirmed IP match.
    has_confirmed_attacker_ip_match = bool(confirmed_attacker_ip_matches)
    high_confidence = bool(
        is_known_target
        or (is_suspicious_registrar and is_cloudflare and len(all_domains) > 1 and is_8char_hex)
        or has_confirmed_attacker_ip_match
    )

    if not high_confidence:
        print(f"[~] Skipping {domain} (low confidence - no alert)")
        return False

    # High confidence confirmed — now track IPs
    track_resolved_ips(all_ips, non_cdn_ips, domain)

    cf_status = "Cloudflare" if is_cloudflare else "Non-Cloudflare"
    print(
        f"[!] ALERT [HIGH]: Multiple domains ({len(all_domains)}),"
        f" {cf_status} NS: {domain} (Registrar: {registrar},"
        f" IPs: {len(all_ips)}, Blockable: {len(non_cdn_ips)})"
    )

    if is_known_target and api_id:
        print(f"    -> Known target: {state.target_mapping[api_id]['name']}")
    elif has_confirmed_attacker_ip_match:
        print(
            f"    -> Escalated to HIGH via known attacker IP match:"
            f" {', '.join(confirmed_attacker_ip_matches)}"
        )
    elif is_suspicious_registrar and is_cloudflare:
        print(f"    -> Suspicious pattern: {registrar} + Cloudflare nameservers")

    with state.lock:
        if len(state.alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
            state.clear_alerted_certificates()
        state.alerted_certificates.add(cert_id)

    target_info = state.target_mapping.get(api_id) if api_id else None
    email_status = send_automated_target_email(
        target_info=target_info,
        domain=domain,
        all_domains=all_domains,
        non_cdn_ips=non_cdn_ips,
        api_id=api_id,
    )

    _dispatch_alert(
        domain=domain,
        all_domains=all_domains,
        not_before=not_before,
        is_known_attacker=False,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers_list=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
        reg_date=reg_date,
        email_status_details=email_status.details,
        email_status_state=email_status.state,
        target_info=target_info,
        api_id=api_id,
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
        with state.lock:
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
                with state.lock:
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
