#!/usr/bin/env python3
import json
import os
import re
import requests
import websocket
import time
import subprocess
import sys
import traceback
import ipaddress
from urllib.parse import quote
from dotenv import load_dotenv

# ============================================================
# CONFIG
# ============================================================

load_dotenv()
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK")
if not DISCORD_WEBHOOK:
    raise RuntimeError("DISCORD_WEBHOOK is not set in the environment or .env file")

# Updated pattern to match:
# Match api-<ID> where:
#   - 5-char IDs are alphanumeric (e.g., 3dse1 for RIT)
#   - 8-char IDs are hex only (e.g., 529aed63 for UCSB)
# Excludes known cloud/SaaS patterns
# Examples:
#   api-3dse1.riym.carbideintegration.com (RIT, 5-char alphanumeric)
#   api-529aed63.ucsb.littlenuggetsco.com (UCSB, 8-char hex)
DOMAIN_REGEX = re.compile(
    r"^api-(?:[0-9a-zA-Z]{5}|[0-9a-fA-F]{8})[\.\-](?!.*(?:upsolver\.com|ngrok\.|workers\.dev|multi\.software|huaweiclouds\.|amazonaws\.com|azure\.|googleusercontent\.com))",
    re.IGNORECASE
)

SEEN_DOMAINS_LIMIT = 10000
seen_domains = set()

# Track already alerted domains to avoid duplicate notifications
alerted_domains = set()
ALERTED_DOMAINS_LIMIT = 10000

# Track already alerted certificates to avoid duplicate notifications for same cert
alerted_certificates = set()
ALERTED_CERTIFICATES_LIMIT = 10000

# Stats tracking
cert_count = 0
last_stats_time = time.time()
total_alerts_count = 0

# Known attacker domains (loaded from file)
known_attacker_domains = set()

# Target organizations mapping (loaded from JSON)
target_mapping = {}

# Email template (loaded from file)
email_template = ""

# Reconnection tracking
reconnect_delay = 1
max_reconnect_delay = 60

# Attacker IP tracking file
ATTACKER_IPS_FILE = "attacker_ips.json"
attacker_ips_data = {"ips": {}, "last_updated": None}

# Known CDN/Cloud IP ranges to exclude from IOCs
# These should not be suggested for blocking
CDN_RANGES = [
    # Cloudflare IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Fastly
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
    "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
    "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
    "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
    "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    # Akamai (partial - major ranges)
    "23.0.0.0/12", "104.64.0.0/10",
    # Amazon CloudFront (partial)
    "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "52.84.0.0/15",
    "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18",
    "54.239.192.0/19", "70.132.0.0/18", "99.84.0.0/16", "143.204.0.0/16",
    "204.246.164.0/22", "204.246.168.0/22", "205.251.192.0/19", "216.137.32.0/19",
]

# Parse CDN ranges into network objects for efficient lookup
cdn_networks = []
for cidr in CDN_RANGES:
    try:
        cdn_networks.append(ipaddress.ip_network(cidr))
    except ValueError:
        pass


# ============================================================
# TARGET MAPPING
# ============================================================

def load_target_mapping(filepath="targets.json"):
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


def extract_hex_id(domain):
    """Extract the ID from a domain matching our pattern.
    Returns the ID (5-char alphanumeric or 8-char hex) or None if not found.
    """
    # Try 8-char hex first, then 5-char alphanumeric
    match = re.match(r"^api-([0-9a-fA-F]{8}|[0-9a-zA-Z]{5})[\.\-]", domain, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def defang_domain(domain):
    """Defang a domain by replacing dots with [.]"""
    return domain.replace('.', '[.]')


# ============================================================
# KNOWN ATTACKER DOMAINS
# ============================================================

def load_known_attacker_domains(filepath="known_domains.txt"):
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


def is_known_attacker_domain(domain, known_domains):
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


# ============================================================
# DOMAIN CHECKS
# ============================================================

def get_nameservers(domain):
    """Get nameservers for a domain. Returns tuple of (is_cloudflare, nameservers_list)."""
    try:
        # Extract base domain (e.g., ucsb.littlenuggetsco.com -> littlenuggetsco.com)
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain
        
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
        nameservers_list = [ns.strip().rstrip('.') for ns in nameservers_output.split('\n') if ns.strip()]
        
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


def is_cdn_ip(ip_str):
    """Check if an IP address belongs to a known CDN/cloud provider."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in cdn_networks:
            if ip in network:
                return True
    except ValueError:
        pass
    return False


def resolve_domain_ip(domain):
    """Resolve a domain to its IP address(es). Returns list of non-CDN IPs."""
    ips = []
    try:
        # Get all A records
        result = subprocess.run(
            ["dig", "+short", "A", domain],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        for line in result.stdout.strip().split('\n'):
            ip = line.strip()
            if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                ips.append(ip)
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout resolving IP for {domain}")
    except Exception as e:
        print(f"[!] Error resolving IP for {domain}: {e}")
    
    return ips


def load_attacker_ips(filepath=ATTACKER_IPS_FILE):
    """Load attacker IPs from JSON file."""
    global attacker_ips_data
    if not os.path.exists(filepath):
        attacker_ips_data = {"ips": {}, "last_updated": None}
        return attacker_ips_data
    
    try:
        with open(filepath, 'r') as f:
            attacker_ips_data = json.load(f)
        print(f"[*] Loaded {len(attacker_ips_data.get('ips', {}))} tracked attacker IPs")
    except Exception as e:
        print(f"[!] Error loading attacker IPs: {e}")
        attacker_ips_data = {"ips": {}, "last_updated": None}
    
    return attacker_ips_data


def save_attacker_ips(filepath=ATTACKER_IPS_FILE):
    """Save attacker IPs to JSON file."""
    global attacker_ips_data
    try:
        attacker_ips_data["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(filepath, 'w') as f:
            json.dump(attacker_ips_data, f, indent=2)
    except Exception as e:
        print(f"[!] Error saving attacker IPs: {e}")


def track_attacker_ip(ip, domain, is_cdn=False):
    """Track an attacker IP address with associated domain."""
    global attacker_ips_data
    
    if ip not in attacker_ips_data["ips"]:
        attacker_ips_data["ips"][ip] = {
            "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "domains": [domain],
            "is_cdn": is_cdn,
            "count": 1
        }
        print(f"[+] New attacker IP tracked: {ip} {'(CDN)' if is_cdn else ''}")
    else:
        entry = attacker_ips_data["ips"][ip]
        entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry["count"] += 1
        if domain not in entry["domains"]:
            entry["domains"].append(domain)
            # Keep only last 50 domains per IP
            if len(entry["domains"]) > 50:
                entry["domains"] = entry["domains"][-50:]
    
    # Save periodically (every update for now, could optimize)
    save_attacker_ips()


def get_attacker_ips_for_domain(domain):
    """Resolve domain and track IPs. Returns tuple of (all_ips, non_cdn_ips)."""
    all_ips = resolve_domain_ip(domain)
    non_cdn_ips = []
    
    for ip in all_ips:
        is_cdn = is_cdn_ip(ip)
        track_attacker_ip(ip, domain, is_cdn)
        if not is_cdn:
            non_cdn_ips.append(ip)
    
    return (all_ips, non_cdn_ips)


def get_domain_registrar(domain):
    """Get the registrar for a domain via whois. Returns registrar name or None."""
    try:
        # Extract base domain
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain
        
        # Run whois command
        result = subprocess.run(
            ["whois", base_domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        whois_output = result.stdout.lower()
        
        # Try to identify common registrars
        if "godaddy" in whois_output or "wild west domains" in whois_output:
            return "GoDaddy"
        elif "namecheap" in whois_output:
            return "Namecheap"
        elif "cloudflare" in whois_output:
            return "Cloudflare"
        elif "tucows" in whois_output:
            return "Tucows"
        elif "gandi" in whois_output:
            return "Gandi"
        elif "google" in whois_output:
            return "Google Domains"
        
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


# ============================================================
# DISCORD ALERTING
# ============================================================

def load_email_template(filepath="email_template.txt"):
    """Load email body template from file. Returns default template if file not found."""
    default_template = """To the Security Team,

I detected new SSL certificate registrations matching known AitM phishing patterns targeting your organization.

IOCs:
{IOCS_LIST}

Context: Likely staging for a credential harvesting campaign. Recommended block on network edge.

Regards"""
    
    if not os.path.exists(filepath):
        print(f"[*] No email template found at {filepath}, using default")
        return default_template
    
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"[!] Error loading email template: {e}, using default")
        return default_template


def generate_mailto_link(target_info, domain, all_domains, email_template, is_known_attacker=False, non_cdn_ips=None):
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
    body = email_template.replace("{IOCS_LIST}", iocs_list)
    
    # URL encode the parameters
    mailto_url = f"mailto:{to_email}?subject={quote(subject)}&body={quote(body)}"
    
    return mailto_url


def send_discord_alert(domain, all_domains, cert_timestamp=None, is_known_attacker=False, registrar=None, is_cloudflare=False, nameservers=None, all_ips=None, non_cdn_ips=None):

    # this should not happen, but just in case
    # and to fix type warning
    if not DISCORD_WEBHOOK:
        print("[!] Discord webhook URL not set; cannot send alert.")
        return
    
    # Extract hex ID and look up target info
    hex_id = extract_hex_id(domain)
    target_info = None
    if hex_id and hex_id in target_mapping:
        target_info = target_mapping[hex_id]
    
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
    domains_block = "\n".join(defanged_domains[:50])  # Limit to 50 domains
    if len(all_domains) > 50:
        domains_block += f"\n... and {len(all_domains) - 50} more"
    
    # Build embed
    embed = {
        "title": "🚨 Certificate Transparency Alert" if is_known_attacker else "⚠️ Potential Target Match",
        "color": 0xFF0000 if is_known_attacker else 0xFFA500,  # Red for known attacker, orange for pattern match
        "fields": [
            {
                "name": "Matched Domain",
                "value": f"`{defang_domain(domain)}`",
                "inline": False
            },
            {
                "name": "Certificate Freshness",
                "value": freshness_str,
                "inline": True
            },
            {
                "name": "Domain Count",
                "value": str(len(all_domains)),
                "inline": True
            },
            {
                "name": "Registrar",
                "value": registrar if registrar else "Unknown",
                "inline": True
            }
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
        embed["color"] = 0xFF0000  # Red for confirmed target
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
        # Format IPs, marking CDN ones
        ip_lines = []
        for ip in all_ips[:10]:  # Limit to 10 IPs
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
        
        # Summary of blockable IPs
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
    
    # Add mailto link for one-click email
    mailto_link = generate_mailto_link(target_info, domain, all_domains, email_template, is_known_attacker, non_cdn_ips)
    embed["fields"].append({
        "name": "📧 Send Notification",
        "value": f"[Click here to send threat intel email]({mailto_link})",
        "inline": False
    })
    
    payload = {"embeds": [embed]}

    try:
        resp = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        if resp.status_code >= 300:
            print(f"[!] Discord webhook error {resp.status_code}: {resp.text}")
    except requests.exceptions.Timeout:
        print(f"[!] Discord webhook timeout for {domain}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Discord webhook request failed for {domain}: {e}")


# ============================================================
# MESSAGE PROCESSING
# ============================================================

def process_message(message_str):
    """Process incoming CT log message from local certstream server."""
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
        
        # Create a unique identifier for this certificate based on its domains
        # Sort domains to ensure consistent hash regardless of order
        cert_id = hash(tuple(sorted(d.strip().lower() for d in all_domains)))
        
        # Check if we've already alerted on this certificate
        global alerted_certificates
        if cert_id in alerted_certificates:
            return  # Skip this certificate, already processed
        
        # Check certificate age - discard if older than 1 hour
        not_before = leaf_cert.get("not_before")
        if not_before:
            try:
                # not_before is a Unix timestamp
                cert_age_seconds = time.time() - not_before
                if cert_age_seconds > 3600:  # 1 hour in seconds
                    return  # Silently discard old certificates
            except (ValueError, TypeError):
                pass  # If timestamp parsing fails, continue processing

        # Update stats
        global cert_count, last_stats_time, total_alerts_count
        cert_count += 1
        
        # Print stats every 60 seconds
        current_time = time.time()
        if current_time - last_stats_time >= 60:
            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"[{timestamp_str}] Processed {cert_count} certificates in the last minute | Total alerts: {total_alerts_count}")
            cert_count = 0
            last_stats_time = current_time

        global seen_domains, alerted_domains, known_attacker_domains
        for d in all_domains:
            try:
                domain = d.strip().lower()

                # Dedupe certificate processing
                if domain in seen_domains:
                    continue
                if len(seen_domains) > SEEN_DOMAINS_LIMIT:
                    seen_domains.clear()
                seen_domains.add(domain)

                # Check for known attacker domains first (highest priority)
                if is_known_attacker_domain(domain, known_attacker_domains):
                    # Check if already alerted on this specific domain
                    if domain in alerted_domains:
                        continue
                    
                    # Get nameserver and registrar info for display purposes
                    is_cloudflare, nameservers_list = get_nameservers(domain)
                    registrar = get_domain_registrar(domain)
                    
                    # Resolve and track IP addresses
                    all_ips, non_cdn_ips = get_attacker_ips_for_domain(domain)
                    
                    print(f"[!] KNOWN ATTACKER DOMAIN DETECTED: {domain} (Registrar: {registrar}, IPs: {len(all_ips)}, Blockable: {len(non_cdn_ips)})")
                    
                    # Mark this certificate as alerted to prevent duplicate alerts
                    # on other subdomains in the same certificate
                    if len(alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
                        alerted_certificates.clear()
                    alerted_certificates.add(cert_id)
                    
                    # Also track the specific domain
                    if len(alerted_domains) > ALERTED_DOMAINS_LIMIT:
                        alerted_domains.clear()
                    alerted_domains.add(domain)
                    
                    send_discord_alert(
                        domain, all_domains, 
                        cert_timestamp=not_before, 
                        is_known_attacker=True, 
                        registrar=registrar,
                        is_cloudflare=is_cloudflare,
                        nameservers=nameservers_list,
                        all_ips=all_ips,
                        non_cdn_ips=non_cdn_ips
                    )
                    total_alerts_count += 1
                    
                    # Skip processing other domains in this certificate
                    break

                # Pattern match
                if DOMAIN_REGEX.match(domain):
                    # Check if already alerted
                    if domain in alerted_domains:
                        continue
                    
                    print(f"[+] Potential match: {domain}")
                    
                    # Check if multiple domains in certificate (>1)
                    has_multiple_domains = len(all_domains) > 1
                    
                    if has_multiple_domains:
                        # Get nameserver info for display purposes
                        is_cloudflare, nameservers_list = get_nameservers(domain)
                        
                        # Get registrar info for display purposes (non-blocking)
                        registrar = get_domain_registrar(domain)
                        
                        # Resolve and track IP addresses
                        all_ips, non_cdn_ips = get_attacker_ips_for_domain(domain)
                        
                        cf_status = "Cloudflare" if is_cloudflare else "Non-Cloudflare"
                        print(f"[!] ALERT: Multiple domains ({len(all_domains)}), {cf_status} NS: {domain} (Registrar: {registrar}, IPs: {len(all_ips)}, Blockable: {len(non_cdn_ips)})")
                        
                        # Mark this certificate as alerted
                        if len(alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
                            alerted_certificates.clear()
                        alerted_certificates.add(cert_id)
                        
                        if len(alerted_domains) > ALERTED_DOMAINS_LIMIT:
                            alerted_domains.clear()
                        alerted_domains.add(domain)
                        send_discord_alert(
                            domain, all_domains, 
                            cert_timestamp=not_before, 
                            is_known_attacker=False, 
                            registrar=registrar,
                            is_cloudflare=is_cloudflare,
                            nameservers=nameservers_list,
                            all_ips=all_ips,
                            non_cdn_ips=non_cdn_ips
                        )
                        total_alerts_count += 1
                        
                        # Skip processing other domains in this certificate
                        break
                    else:
                        # Skip if only single domain
                        print(f"[~] Skipping {domain} (only single domain in certificate)")
            except Exception as e:
                print(f"[!] Error processing domain {d}: {e}")
                continue
    except Exception as e:
        print(f"[!] Error in process_message: {e}")
        traceback.print_exc()


# ============================================================
# WEBSOCKET HANDLERS
# ============================================================

def on_message(ws, message):
    """Handle incoming WebSocket messages."""
    try:
        process_message(message)
    except Exception as e:
        print(f"[!] Unhandled error in on_message: {e}")
        traceback.print_exc()


def on_error(ws, error):
    """Handle WebSocket errors."""
    print(f"[!] WebSocket error: {error}")


def on_close(ws, close_status_code, close_msg):
    """Handle WebSocket close."""
    print(f"[!] WebSocket closed: {close_status_code} - {close_msg}")


def on_open(ws):
    """Handle WebSocket open."""
    global reconnect_delay
    reconnect_delay = 1  # Reset reconnect delay on successful connection
    print("[*] WebSocket connection established")


# ============================================================
# MAIN
# ============================================================

def main():
    if not DISCORD_WEBHOOK:
        print("[!] Discord webhook URL not set; cannot send alert.")
        raise RuntimeError("DISCORD_WEBHOOK is not set in the environment or .env file")
    
    # Load known attacker domains, targets, email template, and tracked IPs
    global known_attacker_domains, target_mapping, email_template, reconnect_delay, attacker_ips_data
    known_attacker_domains = load_known_attacker_domains("known_domains.txt")
    target_mapping = load_target_mapping("targets.json")
    email_template = load_email_template("email_template.txt")
    attacker_ips_data = load_attacker_ips(ATTACKER_IPS_FILE)
    
    print("[*] Starting CertStream watcher (local certstream-server-go)...")
    
    # Main reconnection loop
    while True:
        try:
            print(f"[*] Connecting to ws://127.0.0.1:8080/ ...")
            
            # Connect to local certstream-server-go instance
            ws = websocket.WebSocketApp(
                "ws://127.0.0.1:8080/",
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
                on_open=on_open
            )
            
            # Run forever with auto-reconnect
            ws.run_forever(ping_interval=30, ping_timeout=10)
            
            # If we get here, connection was closed
            print(f"[*] Connection closed, reconnecting in {reconnect_delay} seconds...")
            time.sleep(reconnect_delay)
            
            # Exponential backoff with max delay
            reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down gracefully...")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Unexpected error in main loop: {e}")
            traceback.print_exc()
            print(f"[*] Reconnecting in {reconnect_delay} seconds...")
            time.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)


if __name__ == "__main__":
    main()

