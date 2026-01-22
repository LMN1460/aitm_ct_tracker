"""Configuration and constants for CT Watcher."""

import os
import re
import ipaddress
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Discord webhook URL (required)
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK")
if not DISCORD_WEBHOOK:
    raise RuntimeError("DISCORD_WEBHOOK is not set in the environment or .env file")

# Domain pattern matching
# Match api-<ID> where:
#   - 5-char IDs are alphanumeric (e.g., 3dse1 for RIT)
#   - 8-char IDs are hex only (e.g., 529aed63 for UCSB)
# Excludes known cloud/SaaS patterns
DOMAIN_REGEX = re.compile(
    r"^api-(?:[0-9a-zA-Z]{5}|[0-9a-fA-F]{8})[\.\-]"
    r"(?!.*(?:upsolver\.com|ngrok\.|workers\.dev|multi\.software|"
    r"huaweiclouds\.|amazonaws\.com|azure\.|googleusercontent\.com))",
    re.IGNORECASE
)

# Deduplication limits
SEEN_DOMAINS_LIMIT = 10000
ALERTED_DOMAINS_LIMIT = 10000
ALERTED_CERTIFICATES_LIMIT = 10000

# File paths
ATTACKER_IPS_FILE = "attacker_ips.json"
KNOWN_DOMAINS_FILE = "known_domains.txt"
TARGETS_FILE = "targets.json"
EMAIL_TEMPLATE_FILE = "email_template.txt"

# Reconnection settings
INITIAL_RECONNECT_DELAY = 1
MAX_RECONNECT_DELAY = 60

# WebSocket settings
CERTSTREAM_WS_URL = "ws://127.0.0.1:8080/"
WS_PING_INTERVAL = 30
WS_PING_TIMEOUT = 10

# Certificate age limit (1 hour)
MAX_CERT_AGE_SECONDS = 3600

# Known CDN/Cloud IP ranges to exclude from IOCs
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
def _parse_cdn_networks():
    networks = []
    for cidr in CDN_RANGES:
        try:
            networks.append(ipaddress.ip_network(cidr))
        except ValueError:
            pass
    return networks

CDN_NETWORKS = _parse_cdn_networks()
