#!/usr/bin/env python3
import json
import os
import re
import requests
import websocket
import time
import subprocess
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
            
    except Exception as e:
        print(f"[!] Error checking whois for {domain}: {e}")
    
    return False


# ============================================================
# DISCORD ALERTING
# ============================================================

def send_discord_alert(domain, all_domains):

    # this should not happen, but just in case
    # and to fix type warning
    if not DISCORD_WEBHOOK:
        print("[!] Discord webhook URL not set; cannot send alert.")
        return
    
    content = (
        f"⚠ **CT Hit Detected**\n"
        f"Matched domain: `{domain}`\n"
        f"All domains in cert:\n" +
        "\n".join(f"- `{d}`" for d in all_domains)
    )

    payload = {"content": content[:2000]}  # Discord limit safeguard

    resp = requests.post(DISCORD_WEBHOOK, json=payload)
    if resp.status_code >= 300:
        print(f"[!] Discord webhook error {resp.status_code}: {resp.text}")


# ============================================================
# MESSAGE PROCESSING
# ============================================================

def process_message(message_str):
    """Process incoming CT log message from local certstream server."""
    try:
        message = json.loads(message_str)
    except json.JSONDecodeError:
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
            send_discord_alert(domain, all_domains)
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
                send_discord_alert(domain, all_domains)
            else:
                # Skip if not all indicators present
                print(f"[~] Skipping {domain} (GoDaddy: {has_godaddy}, Cloudflare: {has_cloudflare}, Multi-domain: {has_multiple_domains})")


# ============================================================
# WEBSOCKET HANDLERS
# ============================================================

def on_message(ws, message):
    """Handle incoming WebSocket messages."""
    process_message(message)


def on_error(ws, error):
    """Handle WebSocket errors."""
    print(f"[!] WebSocket error: {error}")


def on_close(ws, close_status_code, close_msg):
    """Handle WebSocket close."""
    print(f"[!] WebSocket closed: {close_status_code} - {close_msg}")


def on_open(ws):
    """Handle WebSocket open."""
    print("[*] WebSocket connection established")


# ============================================================
# MAIN
# ============================================================

def main():
    if not DISCORD_WEBHOOK:
        print("[!] Discord webhook URL not set; cannot send alert.")
        raise RuntimeError("DISCORD_WEBHOOK is not set in the environment or .env file")
    
    # Load known attacker domains
    global known_attacker_domains
    known_attacker_domains = load_known_attacker_domains("known_domains.txt")
    
    print("[*] Starting CertStream watcher (local certstream-server-go)...")
    print("[*] Connecting to ws://127.0.0.1:8080/ ...")
    
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


if __name__ == "__main__":
    main()

