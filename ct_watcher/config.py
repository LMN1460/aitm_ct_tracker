"""Configuration and constants for CT Watcher."""

import os
import re
import ipaddress
from dotenv import load_dotenv


def _parse_bool_env(name: str, default: bool = False) -> bool:
    """Parse common boolean env var values."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int_env(name: str, default: int) -> int:
    """Parse integer env var values with fallback."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default

# Load environment variables
load_dotenv()

# Discord webhook URL (required) - for high-confidence alerts
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK")
if not DISCORD_WEBHOOK:
    raise RuntimeError("DISCORD_WEBHOOK is not set in the environment or .env file")

# Second Discord webhook (optional) - for low-confidence alerts (manual review)
# These alerts are sent without @mentions/notifications
SECOND_DISCORD_WEBHOOK = os.environ.get("SECOND_DISCORD_WEBHOOK")

# SMTP settings for automated threat-intel emails
SMTP_ENABLED = _parse_bool_env("SMTP_ENABLED", False)
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.fastmail.com")
SMTP_PORT = _parse_int_env("SMTP_PORT", 587)
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", "")
SMTP_REPLY_TO = os.environ.get("SMTP_REPLY_TO", "")
SMTP_USE_STARTTLS = _parse_bool_env("SMTP_USE_STARTTLS", True)
SMTP_USE_SSL = _parse_bool_env("SMTP_USE_SSL", False)
SMTP_TIMEOUT_SECONDS = _parse_int_env("SMTP_TIMEOUT_SECONDS", 15)

AUTOMATED_EMAIL_DISCLAIMER = os.environ.get(
    "AUTOMATED_EMAIL_DISCLAIMER",
    "This is an automated message. Please reply if you have questions or if this appears to be in error.",
)

# Registrars that indicate high confidence (commonly used by attackers)
HIGH_CONFIDENCE_REGISTRARS = frozenset([
    "godaddy",
    "namecheap",
])

# Domain pattern matching
# Match api-<ID>. where:
#   - 5-char IDs are alphanumeric (e.g., 3dse1 for RIT)
#   - 8-char IDs are hex only (e.g., 529aed63 for UCSB)
# The ID must be followed by a dot (its own subdomain) to reduce false positives
# Excludes known cloud/SaaS patterns
DOMAIN_REGEX = re.compile(
    r"^api-(?:[0-9a-zA-Z]{5}|[0-9a-fA-F]{8})\."
    r"(?!.*(?:upsolver\.com|ngrok\.|workers\.dev|multi\.software|"
    r"huaweiclouds\.|amazonaws\.com|azure\.|googleusercontent\.com))",
    re.IGNORECASE
)

# Regex to extract the ID portion from api-<ID> patterns
API_ID_EXTRACT_REGEX = re.compile(r"^api-([0-9a-zA-Z]{5,8})[\.\-]", re.IGNORECASE)

# Common English words (5 chars) that cause false positives
# These are filtered out UNLESS they contain digits (which suggests intentional obfuscation)
# Keep this list focused on words that appear in legitimate subdomains
COMMON_WORDS_5CHAR = frozenset([
    # Common subdomain prefixes
    "admin", "local", "store", "stage", "stats", "proxy", "cache", "queue",
    "media", "video", "audio", "image", "photo", "files", "asset", "share",
    "cloud", "board", "delta", "alpha", "beta1", "gamma", "omega", "sigma",
    "money", "forum", "login", "oauth", "token", "auth1", "guest", "users",
    "order", "trade", "sales", "promo", "price", "stock", "brand", "hello",
    "world", "react", "state", "redux", "query", "event", "alert", "point",
    "track", "trace", "agent", "robot", "smart", "swift", "quick", "speed",
    "power", "super", "ultra", "extra", "micro", "macro", "metro", "retro",
    "cyber", "elite", "royal", "crown", "prime", "first", "fresh", "clean",
    "clear", "white", "black", "green", "coral", "amber", "ivory", "pearl",
    "stone", "spark", "flame", "blaze", "storm", "frost", "water", "ocean",
    "river", "beach", "terra", "earth", "space", "lunar", "solar", "astro",
    "north", "south", "inter", "intra", "outer", "inner", "upper", "lower",
    "front", "panel", "table", "chart", "graph", "index", "batch", "chunk",
    "block", "chain", "stack", "layer", "level", "floor", "tower", "plaza",
    "house", "manor", "villa", "lodge", "hotel", "motel", "suite", "salon",
    "berry", "apple", "grape", "lemon", "mango", "peach", "melon", "olive",
    "maple", "cedar", "birch", "aspen", "tiger", "eagle", "horse", "mouse",
    "pilot", "scout", "cadet", "watch", "guard", "safe1", "vault", "armor",
    "draft", "cargo", "depot", "fleet", "drive", "motor", "wheel", "brake",
    "craft", "build", "maker", "forge", "works", "mills", "light", "voice",
    "sound", "music", "tempo", "radio", "pulse", "waves", "vibes", "beats",
    # Tech/API terms
    "debug", "print", "parse", "async", "await", "yield", "input", "setup",
    "fetch", "posts", "items", "nodes", "edges", "links", "paths", "route",
    "start", "begin", "ended", "close", "abort", "retry", "error", "catch",
    # Common Korean/Spanish/etc transliterations that appear in domains
    "movil", "nuevo", "final", "total", "grupo", "vista", "campo", "banco",
])

# 8-character common words/patterns to filter
COMMON_WORDS_8CHAR = frozenset([
    "internal", "external", "platform", "services", "endpoint", "frontend",
    "backend1", "database", "security", "payments", "checkout", "accounts",
    "settings", "profiles", "messages", "comments", "products", "category",
    "customer", "merchant", "business", "personal", "standard", "premium1",
    "workflow", "pipeline", "registry", "instance", "resource", "template",
    "download", "uploading", "redirect", "callback", "webhooks", "triggers",
    "schedule", "calendar", "bookmark", "favorite", "archives", "backups1",
    "recovery", "validate", "verified", "approved", "accepted", "rejected",
    "complete", "progress", "pending1", "queued01", "process1", "handling",
])

# Deduplication limits
SEEN_DOMAINS_LIMIT = 10000
ALERTED_DOMAINS_LIMIT = 10000
ALERTED_CERTIFICATES_LIMIT = 10000

# File paths
ATTACKER_IPS_FILE = "attacker_ips.json"
KNOWN_IPS_FILE = "known_ips.txt"
KNOWN_DOMAINS_FILE = "known_domains.txt"
TARGETS_FILE = "targets.json"
EMAIL_TEMPLATE_FILE = "email_template.txt"

# Reconnection settings
INITIAL_RECONNECT_DELAY = 1
MAX_RECONNECT_DELAY = 60

# WebSocket settings
CERTSTREAM_WS_URL = os.environ.get("CERTSTREAM_WS_URL")
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
