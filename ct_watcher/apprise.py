"""Apprise alerting for CT Watcher."""

from typing import List, Optional

import apprise

from .config import APPRISE_URLS, EMAIL_ENABLED
from .models import AlertInfo
from .state import state
from .utils import defang_domain, extract_target_id, calculate_freshness


def build_apprise_alert(alert: AlertInfo) -> str:
    """Build a simplified markdown alert for Apprise."""

    # Look up target info: prefer alert's target_info, fallback to state lookup by hex ID
    target_info = alert.target_info
    hex_id = extract_target_id(alert.domain)
    if target_info is None and hex_id and hex_id in state.target_mapping:
        target_info = state.target_mapping[hex_id]

    lines = []

    # Header: title, matched domain, target info
    title = (
        "🚨 KNOWN ATTACKER DOMAIN DETECTED"
        if alert.is_known_attacker
        else "⚠️ Potential Target Match"
    )
    lines.append(f"**{title}**")
    lines.append(f"**Matched Domain:** `{defang_domain(alert.domain)}`")
    if target_info:
        lines.append(f"**Target Organization:** {target_info['name']} ({target_info['email']})")
    elif hex_id:
        lines.append(f"**Hex ID:** `{hex_id}` (Unknown Target)")

    lines.append("")

    # Certificate info
    freshness_str = calculate_freshness(alert.not_before, fmt="plain")
    lines.append(f"**Certificate Freshness:** {freshness_str}")
    lines.append(f"**Domain Count:** {len(alert.all_domains)}")
    lines.append(f"**Registrar:** {alert.registrar or 'Unknown'}")
    lines.append(f"**Domain Registered:** {alert.reg_date or 'Unknown'}")
    if alert.certkit_url:
        lines.append(f"**CertKit:** {alert.certkit_url}")

    # Nameserver info
    if alert.nameservers_list is not None:
        cf_status = "Yes" if alert.is_cloudflare else "No"
        lines.append(f"**Cloudflare Nameservers:** {cf_status}")
        if alert.nameservers_list:
            ns_str = "\n".join(alert.nameservers_list)
            lines.append(f"**Nameservers:**\n```\n{ns_str}\n```")

    lines.append("")

    # IP addresses
    if alert.all_ips:
        ip_lines = []
        for ip in alert.all_ips[:10]:
            tag = "non-cdn" if alert.non_cdn_ips and ip in alert.non_cdn_ips else "cdn"
            ip_lines.append(f"  {ip} ({tag})")
        if len(alert.all_ips) > 10:
            ip_lines.append(f"  ... and {len(alert.all_ips) - 10} more")
        lines.append("**IP Addresses:**")
        lines.append("\n".join(ip_lines))

    # Confirmed attacker IP matches
    if alert.confirmed_attacker_ip_matches:
        matched = "\n".join(f"  {ip}" for ip in alert.confirmed_attacker_ip_matches[:20])
        if len(alert.confirmed_attacker_ip_matches) > 20:
            matched += f"\n  ... and {len(alert.confirmed_attacker_ip_matches) - 20} more"
        lines.append("**Confirmed Attacker IP Match:**")
        lines.append(matched)

    lines.append("")

    # All domains
    defanged_domains = [defang_domain(d) for d in alert.all_domains]
    domains_block = "\n".join(defanged_domains[:50])
    if len(alert.all_domains) > 50:
        domains_block += f"\n... and {len(alert.all_domains) - 50} more"
    lines.append("**All Domains in Certificate:**")
    lines.append(f"```\n{domains_block}\n```")

    # Email status
    if EMAIL_ENABLED and alert.email_status_details:
        lines.append(f"**Email Status:** {alert.email_status_details}")

    return "\n".join(lines)


def send_apprise_alert(
    alert: AlertInfo,
    extra_urls: Optional[List[str]] = None,
) -> None:
    """Send alert via Apprise to configured URLs."""

    urls = []
    if APPRISE_URLS:
        urls.extend(u.strip() for u in APPRISE_URLS.split(",") if u.strip())
    if extra_urls:
        urls.extend(extra_urls)

    if not urls:
        return

    body = build_apprise_alert(alert)

    title = (
        "🚨 CT Alert: Known Attacker"
        if alert.is_known_attacker
        else "⚠️ CT Alert: Potential Match"
    )

    apobj = apprise.Apprise()
    for url in urls:
        apobj.add(url)

    try:
        apobj.notify(title=title, body=body, body_format=apprise.NotifyFormat.MARKDOWN)
    except Exception as e:
        print(f"[!] Apprise notification failed for {alert.domain}: {e}")
