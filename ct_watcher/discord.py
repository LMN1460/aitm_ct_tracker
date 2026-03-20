"""Discord alerting for CT Watcher."""

import time
from datetime import datetime, timezone
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import quote, urlencode

from .config import DISCORD_WEBHOOK, SECOND_DISCORD_WEBHOOK
from .state import state
from .utils import defang_domain, extract_target_id


# Discord embed hard limits
DISCORD_MAX_EMBED_TOTAL = 6000
DISCORD_MAX_TITLE = 256
DISCORD_MAX_DESCRIPTION = 4096
DISCORD_MAX_FIELD_NAME = 256
DISCORD_MAX_FIELD_VALUE = 1024
DISCORD_MAX_FIELDS = 25
DISCORD_MAX_FOOTER_TEXT = 2048

# Keep a small safety margin to avoid edge-case payload rejection
DISCORD_SAFE_EMBED_TOTAL = 5600

# Twitter character limit for intent text
TWITTER_TEXT_LIMIT = 280


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


def _is_namecheap_registrar(registrar: Optional[str]) -> bool:
    """Return True if registrar appears to be Namecheap."""
    return bool(registrar and "namecheap" in registrar.lower())


def _cap_text(text: str, limit: int) -> str:
    """Cap text to a max length with truncation suffix."""
    if len(text) <= limit:
        return text
    if limit <= 15:
        return text[:limit]
    return text[: limit - 15] + "... (truncated)"


def _estimate_embed_chars(embed: Dict[str, Any]) -> int:
    """Approximate total character count for a Discord embed."""
    total = 0
    total += len(str(embed.get("title", "")))
    total += len(str(embed.get("description", "")))
    total += len(str(embed.get("url", "")))

    author = embed.get("author")
    if isinstance(author, dict):
        total += len(str(author.get("name", "")))

    footer = embed.get("footer")
    if isinstance(footer, dict):
        total += len(str(footer.get("text", "")))

    for field in embed.get("fields", []):
        total += len(str(field.get("name", "")))
        total += len(str(field.get("value", "")))

    return total


def _sanitize_embed(embed: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure embed fits Discord limits; only reduce if needed."""
    embed["title"] = _cap_text(str(embed.get("title", "")), DISCORD_MAX_TITLE)
    if "description" in embed:
        embed["description"] = _cap_text(str(embed.get("description", "")), DISCORD_MAX_DESCRIPTION)

    footer = embed.get("footer")
    if isinstance(footer, dict) and "text" in footer:
        footer["text"] = _cap_text(str(footer.get("text", "")), DISCORD_MAX_FOOTER_TEXT)

    fields = embed.get("fields", [])[:DISCORD_MAX_FIELDS]
    for field in fields:
        field["name"] = _cap_text(str(field.get("name", "")), DISCORD_MAX_FIELD_NAME)
        field["value"] = _cap_text(str(field.get("value", "")), DISCORD_MAX_FIELD_VALUE)
    embed["fields"] = fields

    # If still too large, drop optional fields first, then minimally truncate
    if _estimate_embed_chars(embed) > DISCORD_SAFE_EMBED_TOTAL:
        optional_field_names = {
            "Nameservers",
            "🌐 IP Addresses",
            "All Domains in Certificate",
            "Cloudflare Nameservers",
            "Blockable IPs",
            "⚠️ CDN Warning",
        }
        embed["fields"] = [
            f for f in embed.get("fields", [])
            if f.get("name") not in optional_field_names
        ]

    if _estimate_embed_chars(embed) > DISCORD_SAFE_EMBED_TOTAL:
        for field in embed.get("fields", []):
            field["value"] = _cap_text(str(field.get("value", "")), 512)
            if _estimate_embed_chars(embed) <= DISCORD_SAFE_EMBED_TOTAL:
                break

    return embed


def _build_namecheap_tweet_link(all_domains: List[str]) -> str:
    """Build Twitter/X intent link with defanged domains only."""
    intro = (
        "@Namecheap I have identified phishing infrastructure being setup "
        "to attack universities at the following domain:"
    )

    defanged_domains = [defang_domain(d) for d in all_domains]
    chosen_domains: List[str] = []

    for d in defanged_domains:
        candidate = intro + "\n" + "\n".join(chosen_domains + [d])
        if len(candidate) <= TWITTER_TEXT_LIMIT:
            chosen_domains.append(d)
        else:
            break

    if not chosen_domains and defanged_domains:
        # Keep at least one IOC even if very long.
        remaining = TWITTER_TEXT_LIMIT - len(intro) - 1
        first = defanged_domains[0][: max(0, remaining)]
        chosen_domains = [first]

    tweet_text = intro
    if chosen_domains:
        tweet_text += "\n" + "\n".join(chosen_domains)

    if len(chosen_domains) < len(defanged_domains):
        omitted = len(defanged_domains) - len(chosen_domains)
        suffix = f"\n+{omitted} more"
        if len(tweet_text) + len(suffix) <= TWITTER_TEXT_LIMIT:
            tweet_text += suffix

    return f"https://twitter.com/intent/tweet?{urlencode({'text': tweet_text})}"


def build_embed(
    domain: str,
    all_domains: List[str],
    cert_timestamp: Optional[float] = None,
    is_known_attacker: bool = False,
    registrar: Optional[str] = None,
    is_cloudflare: bool = False,
    nameservers: Optional[List[str]] = None,
    all_ips: Optional[List[str]] = None,
    non_cdn_ips: Optional[List[str]] = None,
    confirmed_attacker_ip_matches: Optional[List[str]] = None,
    reg_date: Optional[str] = None,
    email_status: Optional[str] = None,
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
            {"name": "Registrar", "value": registrar if registrar else "Unknown", "inline": True},
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    }

    # Add domain registration date field if available
    if reg_date:
        try:
            reg_dt = datetime.fromisoformat(reg_date)
            if reg_dt.tzinfo is None:
                reg_dt = reg_dt.replace(tzinfo=timezone.utc)
            days_old = (datetime.now(timezone.utc) - reg_dt).days
            reg_date_display = f"{reg_date} ({days_old} days old)"
        except Exception:
            reg_date_display = reg_date
        embed["fields"].append({
            "name": "📅 Domain Registered",
            "value": reg_date_display,
            "inline": True
        })
    else:
        embed["fields"].append({
            "name": "📅 Domain Registered",
            "value": "Unknown (RDAP unavailable)",
            "inline": True
        })
    
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

    if confirmed_attacker_ip_matches:
        matched_ips = "\n".join(confirmed_attacker_ip_matches[:20])
        if len(confirmed_attacker_ip_matches) > 20:
            matched_ips += f"\n... and {len(confirmed_attacker_ip_matches) - 20} more"
        embed["fields"].append({
            "name": "🧨 Confirmed Attacker IP Match",
            "value": f"```\n{matched_ips}\n```",
            "inline": False
        })

    if email_status:
        embed["fields"].append({
            "name": "Email Status",
            "value": email_status,
            "inline": False,
        })
    
    # Add all domains in code block
    embed["fields"].append({
        "name": "All Domains in Certificate",
        "value": f"```\n{domains_block}\n```",
        "inline": False
    })
    
    # Add actions. Tweet action is Namecheap-only and domains-only to keep size low.
    mailto_link = generate_mailto_link(target_info, domain, all_domains, non_cdn_ips)
    actions = [f"[Email threat intel]({mailto_link})"]
    if _is_namecheap_registrar(registrar):
        tweet_link = _build_namecheap_tweet_link(all_domains)
        actions.append(f"[Tweet to @Namecheap]({tweet_link})")

    embed["fields"].append({
        "name": "📣 Actions",
        "value": " | ".join(actions),
        "inline": False
    })

    return _sanitize_embed(embed)


def _build_minimal_embed(
    domain: str,
    all_domains: List[str],
    registrar: Optional[str],
    cert_timestamp: Optional[float],
    confirmed_attacker_ip_matches: Optional[List[str]],
    reg_date: Optional[str]
) -> Dict[str, Any]:
    """Build a compact fallback embed when Discord rejects the full payload."""
    freshness = "Unknown"
    if cert_timestamp:
        age_seconds = int(max(0, time.time() - cert_timestamp))
        if age_seconds < 60:
            freshness = f"{age_seconds}s"
        elif age_seconds < 3600:
            freshness = f"{age_seconds // 60}m"
        else:
            freshness = f"{age_seconds // 3600}h"

    fields = [
        {"name": "Matched Domain", "value": f"`{defang_domain(domain)}`", "inline": False},
        {"name": "Domain Count", "value": str(len(all_domains)), "inline": True},
        {"name": "Registrar", "value": registrar or "Unknown", "inline": True},
        {"name": "Certificate Freshness", "value": freshness, "inline": True},
    ]
    if reg_date:
        fields.append({"name": "📅 Domain Registered", "value": reg_date, "inline": True})
    if confirmed_attacker_ip_matches:
        fields.append({
            "name": "🧨 Confirmed Attacker IP Match",
            "value": ", ".join(confirmed_attacker_ip_matches[:5]),
            "inline": False,
        })

    mailto_link = generate_mailto_link(None, domain, all_domains, None)
    actions = [f"[Email threat intel]({mailto_link})"]
    if _is_namecheap_registrar(registrar):
        tweet_link = _build_namecheap_tweet_link(all_domains)
        actions.append(f"[Tweet to @Namecheap]({tweet_link})")
    fields.append({"name": "📣 Actions", "value": " | ".join(actions), "inline": False})

    minimal = {
        "title": "⚠️ CT Alert (Compact)",
        "color": 0xFF0000,
        "fields": fields,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
    }
    return _sanitize_embed(minimal)


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
    confirmed_attacker_ip_matches: Optional[List[str]] = None,
    high_confidence: bool = True,
    reg_date: Optional[str] = None,
    email_status: Optional[str] = None,
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
        registrar, is_cloudflare, nameservers, all_ips, non_cdn_ips,
        confirmed_attacker_ip_matches, reg_date, email_status
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
            if resp.status_code == 400:
                # One fallback retry with a minimal payload to avoid silent alert loss.
                minimal_embed = _build_minimal_embed(
                    domain=domain,
                    all_domains=all_domains,
                    registrar=registrar,
                    cert_timestamp=cert_timestamp,
                    confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
                    reg_date=reg_date,
                )
                minimal_payload: Dict[str, Any] = {"embeds": [minimal_embed]}
                if not high_confidence:
                    minimal_payload["flags"] = 4096
                retry_resp = requests.post(webhook_url, json=minimal_payload, timeout=10)
                if retry_resp.status_code >= 300:
                    print(f"[!] Discord fallback webhook error {retry_resp.status_code}: {retry_resp.text}")
    except requests.exceptions.Timeout:
        print(f"[!] Discord webhook timeout for {domain}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Discord webhook request failed for {domain}: {e}")
