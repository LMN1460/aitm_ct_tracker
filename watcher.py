#!/usr/bin/env python3
import json
import os
import re
import requests
import websocket
import time
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

# Stats tracking
cert_count = 0
last_stats_time = time.time()


# ============================================================
# DISCORD ALERTING
# ============================================================

def send_discord_alert(domain, all_domains, source="certstream"):

    # this should not happen, but just in case
    # and to fix type warning
    if not DISCORD_WEBHOOK:
        print("[!] Discord webhook URL not set; cannot send alert.")
        return
    
    content = (
        f"⚠ **CT Hit Detected**\n"
        f"Source: `{source}`\n"
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

    # Update stats
    global cert_count, last_stats_time
    cert_count += 1
    
    # Print stats every 60 seconds
    current_time = time.time()
    if current_time - last_stats_time >= 60:
        print(f"[*] Processed {cert_count} certificates in the last minute")
        cert_count = 0
        last_stats_time = current_time

    global seen_domains
    for d in all_domains:
        domain = d.strip().lower()

        # Dedupe
        if domain in seen_domains:
            continue
        if len(seen_domains) > SEEN_DOMAINS_LIMIT:
            seen_domains.clear()
        seen_domains.add(domain)

        # Pattern match
        if DOMAIN_REGEX.match(domain):
            print(f"[+] Match: {domain}")
            send_discord_alert(domain, all_domains, source="local-certstream")


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

