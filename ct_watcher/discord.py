"""Discord alerting for CT Watcher."""

import time
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import quote

from .config import DISCORD_WEBHOOK, SECOND_DISCORD_WEBHOOK
from .state import state
from .utils import defang_domain, extract_target_id


def generate_mailto_link(
    target_info: Optional[Dict[str, str]],
    domain: str,
    all_domains: List[str],
    non_cdn_ips: Optional[List[str]] = None
) -> str:
    """Generate a mailto link with pre-filled threat intel email."""
    # Determine recipient email and org name
    if target_info:
        to_email = target_info['email']
        org_name = target_info['name']
    else:
        to_email = "INSERT_TARGET_EMAIL"
        org_name = "INSERT_ORG_NAME"
    
    # Build subject
    subject = f"[Threat Intel] Phishing infrastructure detected targeting {org_name}"
    
    # Build IOCs list (defanged domains)
    iocs_list = "\r\n".join([defang_domain(d) for d in all_domains[:50]])
    if len(all_domains) > 50:
        iocs_list += f"\r\n... and {len(all_domains) - 50} more domains"
    
    # Add non-CDN IPs to IOCs (these are safe to block)
    if non_cdn_ips:
        iocs_list += "\r\n\r\nIP Addresses:\r\n"
        iocs_list += "\r\n".join(non_cdn_ips[:20])
        if len(non_cdn_ips) > 20:
            iocs_list += f"\r\n... and {len(non_cdn_ips) - 20} more IPs"
    
    # Build email body from template
    body = state.email_template.replace("{IOCS_LIST}", iocs_list)
    
    # URL encode the parameters
    mailto_url = f"mailto:{to_email}?subject={quote(subject)}&body={quote(body)}"
    
    return mailto_url


def build_embed(
    domain: str,
    all_domains: List[str],
    cert_timestamp: Optional[float] = None,
    is_known_attacker: bool = False,
    registrar: Optional[str] = None,
    is_cloudflare: bool = False,
    nameservers: Optional[List[str]] = None,
    all_ips: Optional[List[str]] = None,
    non_cdn_ips: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Build Discord embed for alert."""
    
    # Extract hex ID and look up target info
    hex_id = extract_target_id(domain)
    target_info = None
    if hex_id and hex_id in state.target_mapping:
        target_info = state.target_mapping[hex_id]
    
    # Calculate certificate freshness
    freshness_str = "Unknown"
    if cert_timestamp:
        age_seconds = time.time() - cert_timestamp
        if age_seconds < 60:
            freshness_str = f"{int(age_seconds)} seconds"
        elif age_seconds < 3600:
            freshness_str = f"{int(age_seconds / 60)} minutes"
        else:
            freshness_str = f"{int(age_seconds / 3600)} hours"
    
    # Defang domains and format as code block
    defanged_domains = [defang_domain(d) for d in all_domains]
    domains_block = "\n".join(defanged_domains[:50])
    if len(all_domains) > 50:
        domains_block += f"\n... and {len(all_domains) - 50} more"
    
    # Build embed
    embed = {
        "title": "🚨 Certificate Transparency Alert" if is_known_attacker else "⚠️ Potential Target Match",
        "color": 0xFF0000 if is_known_attacker else 0xFFA500,
        "fields": [
            {"name": "Matched Domain", "value": f"`{defang_domain(domain)}`", "inline": False},
            {"name": "Certificate Freshness", "value": freshness_str, "inline": True},
            {"name": "Domain Count", "value": str(len(all_domains)), "inline": True},
            {"name": "Registrar", "value": registrar if registrar else "Unknown", "inline": True}
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    }
    
    # Add nameserver information
    if nameservers is not None:
        cloudflare_status = "✅ Yes" if is_cloudflare else "❌ No"
        nameservers_str = "\n".join(nameservers) if nameservers else "Unable to retrieve"
        
        embed["fields"].append({
            "name": "Cloudflare Nameservers",
            "value": cloudflare_status,
            "inline": True
        })
        embed["fields"].append({
            "name": "Nameservers",
            "value": f"```\n{nameservers_str}\n```" if nameservers else "Unable to retrieve",
            "inline": False
        })
    
    # Add target information if available
    if target_info:
        embed["fields"].insert(1, {
            "name": "🎯 Target Organization",
            "value": f"**{target_info['name']}**\nContact: {target_info['email']}",
            "inline": False
        })
        embed["color"] = 0xFF0000
    elif hex_id and not is_known_attacker:
        embed["fields"].insert(1, {
            "name": "Hex ID",
            "value": f"`{hex_id}` (Unknown Target)",
            "inline": False
        })
    
    # Add alert type indicator
    if is_known_attacker:
        embed["description"] = "⚠️ **KNOWN ATTACKER DOMAIN DETECTED**"
    
    # Add IP address information
    if all_ips:
        ip_lines = []
        for ip in all_ips[:10]:
            if non_cdn_ips and ip in non_cdn_ips:
                ip_lines.append(f"{ip} ✅ (blockable)")
            else:
                ip_lines.append(f"{ip} ⚠️ (CDN - do not block)")
        
        ip_block = "\n".join(ip_lines)
        if len(all_ips) > 10:
            ip_block += f"\n... and {len(all_ips) - 10} more"
        
        embed["fields"].append({
            "name": "🌐 IP Addresses",
            "value": f"```\n{ip_block}\n```",
            "inline": False
        })
        
        if non_cdn_ips:
            embed["fields"].append({
                "name": "Blockable IPs",
                "value": f"`{len(non_cdn_ips)}` non-CDN IPs safe to block",
                "inline": True
            })
        else:
            embed["fields"].append({
                "name": "⚠️ CDN Warning",
                "value": "All IPs are CDN - do not block!",
                "inline": True
            })
    
    # Add all domains in code block
    embed["fields"].append({
        "name": "All Domains in Certificate",
        "value": f"```\n{domains_block}\n```",
        "inline": False
    })
    
    # Add mailto link
    mailto_link = generate_mailto_link(target_info, domain, all_domains, non_cdn_ips)
    embed["fields"].append({
        "name": "📧 Send Notification",
        "value": f"[Click here to send threat intel email]({mailto_link})",
        "inline": False
    })
    
    return embed


def send_discord_alert(
    domain: str,
    all_domains: List[str],
    cert_timestamp: Optional[float] = None,
    is_known_attacker: bool = False,
    registrar: Optional[str] = None,
    is_cloudflare: bool = False,
    nameservers: Optional[List[str]] = None,
    all_ips: Optional[List[str]] = None,
    non_cdn_ips: Optional[List[str]] = None,
    high_confidence: bool = True
) -> None:
    """Send alert to Discord webhook.
    
    Args:
        high_confidence: If True, sends to main webhook. If False, sends to
                        second webhook (for manual review) with notifications suppressed.
    """
    # Choose webhook based on confidence level
    if high_confidence:
        webhook_url = DISCORD_WEBHOOK
    else:
        # Use second webhook for low-confidence alerts, fall back to main if not set
        webhook_url = SECOND_DISCORD_WEBHOOK or DISCORD_WEBHOOK
    
    if not webhook_url:
        print("[!] Discord webhook URL not set; cannot send alert.")
        return
    
    embed = build_embed(
        domain, all_domains, cert_timestamp, is_known_attacker,
        registrar, is_cloudflare, nameservers, all_ips, non_cdn_ips
    )
    
    # Mark low-confidence alerts visually
    if not high_confidence:
        embed["title"] = "🔍 Manual Review: " + embed.get("title", "Alert")
        embed["color"] = 0x808080  # Gray for low confidence
        embed["footer"] = {"text": "Low confidence - manual review required"}
    
    payload: Dict[str, Any] = {"embeds": [embed]}
    
    # Suppress notifications for low-confidence alerts
    if not high_confidence:
        payload["flags"] = 4096  # SUPPRESS_NOTIFICATIONS flag

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code >= 300:
            print(f"[!] Discord webhook error {resp.status_code}: {resp.text}")
    except requests.exceptions.Timeout:
        print(f"[!] Discord webhook timeout for {domain}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Discord webhook request failed for {domain}: {e}")
