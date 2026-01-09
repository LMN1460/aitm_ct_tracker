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
# Match api-<5 or 8 hex chars> but exclude known cloud/SaaS patterns
# Examples:
#   api-3dse1.rata.littlenuggetsco.com (RIT, shorter)
#   api-529aed63.ucsb.littlenuggetsco.com (UCSB, standard)
DOMAIN_REGEX = re.compile(
    r"^api-(?:[0-9a-fA-F]{5}|[0-9a-fA-F]{8})[\.\-](?!.*(?:upsolver\.com|ngrok\.|workers\.dev|multi\.software|huaweiclouds\.|amazonaws\.com|azure\.|googleusercontent\.com))",
    re.IGNORECASE
)

SEEN_DOMAINS_LIMIT = 10000
seen_domains = set()

# Track already alerted domains to avoid duplicate notifications
alerted_domains = set()
ALERTED_DOMAINS_LIMIT = 10000

# Stats tracking
cert_count = 0
last_stats_time = time.time()

# Known attacker domains (loaded from file)
known_attacker_domains = set()

# Target organizations mapping (loaded from JSON)
target_mapping = {}

# Email template (loaded from file)
email_template = ""

# Reconnection tracking
reconnect_delay = 1
max_reconnect_delay = 60


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
    """Extract the hex ID from a domain matching our pattern.
    Returns the hex ID (5 or 8 chars) or None if not found.
    """
    match = re.match(r"^api-([0-9a-fA-F]{5}|[0-9a-fA-F]{8})", domain, re.IGNORECASE)
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

def check_nameservers(domain):
    """Check if domain uses Cloudflare nameservers. Returns True if Cloudflare detected."""
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
        
        nameservers = result.stdout.lower()
        if "cloudflare" in nameservers or "ns.cloudflare.com" in nameservers:
            print(f"[~] Cloudflare nameservers detected for {domain}, skipping alert")
            return True
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout checking nameservers for {domain}")
    except FileNotFoundError:
        print(f"[!] dig command not found, skipping nameserver check for {domain}")
    except Exception as e:
        print(f"[!] Error checking nameservers for {domain}: {e}")
    
    return False


def check_godaddy_registrar(domain):
    """Check if domain is registered with GoDaddy via whois. Returns True if GoDaddy detected."""
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
        if "godaddy" in whois_output or "wild west domains" in whois_output:
            print(f"[~] GoDaddy registrar detected for {domain}, skipping alert")
            return True
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout checking whois for {domain}")
    except FileNotFoundError:
        print(f"[!] whois command not found, skipping registrar check for {domain}")
    except Exception as e:
        print(f"[!] Error checking whois for {domain}: {e}")
    
    return False


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


def generate_mailto_link(target_info, domain, all_domains, email_template, is_known_attacker=False):
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
    
    # Build IOCs list (defanged)
    iocs_list = "\n".join([defang_domain(d) for d in all_domains[:50]])
    if len(all_domains) > 50:
        iocs_list += f"\n... and {len(all_domains) - 50} more domains"
    
    # Build email body from template
    body = email_template.replace("{IOCS_LIST}", iocs_list)
    
    # URL encode the parameters
    mailto_url = f"mailto:{to_email}?subject={quote(subject)}&body={quote(body)}"
    
    return mailto_url


def send_discord_alert(domain, all_domains, cert_timestamp=None, is_known_attacker=False):

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
            }
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    }
    
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
    
    # Add all domains in code block
    embed["fields"].append({
        "name": "All Domains in Certificate",
        "value": f"```\n{domains_block}\n```",
        "inline": False
    })
    
    # Add mailto link for one-click email
    mailto_link = generate_mailto_link(target_info, domain, all_domains, email_template, is_known_attacker)
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
        global cert_count, last_stats_time
        cert_count += 1
        
        # Print stats every 60 seconds
        current_time = time.time()
        if current_time - last_stats_time >= 60:
            print(f"[*] Processed {cert_count} certificates in the last minute")
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
                    # Check if already alerted
                    if domain in alerted_domains:
                        continue
                    
                    print(f"[!] KNOWN ATTACKER DOMAIN DETECTED: {domain}")
                    if len(alerted_domains) > ALERTED_DOMAINS_LIMIT:
                        alerted_domains.clear()
                    alerted_domains.add(domain)
                    send_discord_alert(domain, all_domains, cert_timestamp=not_before, is_known_attacker=True)
                    continue

                # Pattern match
                if DOMAIN_REGEX.match(domain):
                    # Check if already alerted
                    if domain in alerted_domains:
                        continue
                    
                    print(f"[+] Potential match: {domain}")
                    
                    # Check for ALL THREE indicators:
                    # 1. GoDaddy registrar
                    # 2. Cloudflare nameservers
                    # 3. Multiple domains in the certificate (>1)
                    # All must be present to trigger alert (reduces false positives)
                    has_godaddy = check_godaddy_registrar(domain)
                    has_cloudflare = check_nameservers(domain)
                    has_multiple_domains = len(all_domains) > 1
                    
                    if has_godaddy and has_cloudflare and has_multiple_domains:
                        print(f"[!] ALERT: Domain has GoDaddy + Cloudflare + multiple domains ({len(all_domains)}): {domain}")
                        if len(alerted_domains) > ALERTED_DOMAINS_LIMIT:
                            alerted_domains.clear()
                        alerted_domains.add(domain)
                        send_discord_alert(domain, all_domains, cert_timestamp=not_before, is_known_attacker=False)
                    else:
                        # Skip if not all indicators present
                        print(f"[~] Skipping {domain} (GoDaddy: {has_godaddy}, Cloudflare: {has_cloudflare}, Multi-domain: {has_multiple_domains})")
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
    
    # Load known attacker domains, targets, and email template
    global known_attacker_domains, target_mapping, email_template, reconnect_delay
    known_attacker_domains = load_known_attacker_domains("known_domains.txt")
    target_mapping = load_target_mapping("targets.json")
    email_template = load_email_template("email_template.txt")
    
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

