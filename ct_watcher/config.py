"""Configuration and constants for CT Watcher."""

import os
import re
import ipaddress
from typing import List
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

# Discord webhook URL (optional — at least one of DISCORD_WEBHOOK or APPRISE_URLS must be set)
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK")

# Optional secondary webhook for watched organizations
DISCORD_WEBHOOK_WATCHED = os.environ.get("DISCORD_WEBHOOK_WATCHED")

# Apprise URLs for multi-service notifications (optional — comma-separated)
APPRISE_URLS = os.environ.get("APPRISE_URLS")
APPRISE_URLS_WATCHED = os.environ.get("APPRISE_URLS_WATCHED")

# Validate: at least one notification channel must be configured
if not DISCORD_WEBHOOK and not APPRISE_URLS:
    raise RuntimeError(
        "Neither DISCORD_WEBHOOK nor APPRISE_URLS is set. "
        "At least one notification channel must be configured."
    )

# Master kill-switch for all email functionality (mailto links, SMTP status, automated emails)
EMAIL_ENABLED = _parse_bool_env("EMAIL_ENABLED", True)

# SMTP settings for automated threat-intel emails
SMTP_ENABLED = _parse_bool_env("SMTP_ENABLED", False)
SMTP_ONLY_WATCHED = _parse_bool_env("SMTP_ONLY_WATCHED", False)
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
    "This is an automated message. Please reply if you have questions"
    " or if this appears to be in error.",
)

# Email subject line. {TARGET_NAME} placeholder gets replaced with the
# target organization name at send time.
EMAIL_SUBJECT = os.environ.get(
    "EMAIL_SUBJECT",
    "[Threat Intel] Phishing infrastructure detected targeting {TARGET_NAME}",
)


# Domain pattern matching
# Match api-<ID>. where:
#   - 5-char IDs are alphanumeric (e.g., 3dse1 for RIT)
#   - 8-char IDs are alphanumeric (e.g., 529aed63 for UCSB, 62a1edm3 for Morgan State)
# The ID must be followed by a dot (its own subdomain) to reduce false positives
# Excludes known cloud/SaaS patterns
DOMAIN_REGEX = re.compile(
    r"^api-[0-9a-zA-Z]{5,8}\."
    r"(?!.*(?:upsolver\.com|ngrok\.|workers\.dev|pages\.dev|multi\.software|"
    r"huaweiclouds\.|amazonaws\.com|azure\.|googleusercontent\.com|ondigitalocean\.com))",
    re.IGNORECASE,
)

# Regex to extract the ID portion from api-<ID> patterns
API_ID_EXTRACT_REGEX = re.compile(r"^api-([0-9a-zA-Z]{5,8})[\.\-]", re.IGNORECASE)

# Common English words (5 chars) that cause false positives
# These are filtered out UNLESS they contain digits (which suggests intentional obfuscation)
# Keep this list focused on words that appear in legitimate subdomains
COMMON_WORDS_5CHAR = frozenset(
    [
        # Common subdomain prefixes
        "admin",
        "local",
        "store",
        "stage",
        "stats",
        "proxy",
        "cache",
        "queue",
        "media",
        "video",
        "audio",
        "image",
        "photo",
        "files",
        "asset",
        "share",
        "cloud",
        "board",
        "delta",
        "alpha",
        "beta1",
        "gamma",
        "omega",
        "sigma",
        "money",
        "forum",
        "login",
        "oauth",
        "token",
        "auth1",
        "guest",
        "users",
        "order",
        "trade",
        "sales",
        "promo",
        "price",
        "stock",
        "brand",
        "hello",
        "world",
        "react",
        "state",
        "redux",
        "query",
        "event",
        "alert",
        "point",
        "track",
        "trace",
        "agent",
        "robot",
        "smart",
        "swift",
        "quick",
        "speed",
        "power",
        "super",
        "ultra",
        "extra",
        "micro",
        "macro",
        "metro",
        "retro",
        "cyber",
        "elite",
        "royal",
        "crown",
        "prime",
        "first",
        "fresh",
        "clean",
        "clear",
        "white",
        "black",
        "green",
        "coral",
        "amber",
        "ivory",
        "pearl",
        "stone",
        "spark",
        "flame",
        "blaze",
        "storm",
        "frost",
        "water",
        "ocean",
        "river",
        "beach",
        "terra",
        "earth",
        "space",
        "lunar",
        "solar",
        "astro",
        "north",
        "south",
        "inter",
        "intra",
        "outer",
        "inner",
        "upper",
        "lower",
        "front",
        "panel",
        "table",
        "chart",
        "graph",
        "index",
        "batch",
        "chunk",
        "block",
        "chain",
        "stack",
        "layer",
        "level",
        "floor",
        "tower",
        "plaza",
        "house",
        "manor",
        "villa",
        "lodge",
        "hotel",
        "motel",
        "suite",
        "salon",
        "berry",
        "apple",
        "grape",
        "lemon",
        "mango",
        "peach",
        "melon",
        "olive",
        "maple",
        "cedar",
        "birch",
        "aspen",
        "tiger",
        "eagle",
        "horse",
        "mouse",
        "pilot",
        "scout",
        "cadet",
        "watch",
        "guard",
        "safe1",
        "vault",
        "armor",
        "draft",
        "cargo",
        "depot",
        "fleet",
        "drive",
        "motor",
        "wheel",
        "brake",
        "craft",
        "build",
        "maker",
        "forge",
        "works",
        "mills",
        "light",
        "voice",
        "sound",
        "music",
        "tempo",
        "radio",
        "pulse",
        "waves",
        "vibes",
        "beats",
        # Tech/API terms
        "debug",
        "print",
        "parse",
        "async",
        "await",
        "yield",
        "input",
        "setup",
        "fetch",
        "posts",
        "items",
        "nodes",
        "edges",
        "links",
        "paths",
        "route",
        "start",
        "begin",
        "ended",
        "close",
        "abort",
        "retry",
        "error",
        "catch",
        # Common Korean/Spanish/etc transliterations that appear in domains
        "movil",
        "nuevo",
        "final",
        "total",
        "grupo",
        "vista",
        "campo",
        "banco",
    ]
)

# 8-character common words/patterns to filter
COMMON_WORDS_8CHAR = frozenset(
    [
        "internal",
        "external",
        "platform",
        "services",
        "endpoint",
        "frontend",
        "backend1",
        "database",
        "security",
        "payments",
        "checkout",
        "accounts",
        "settings",
        "profiles",
        "messages",
        "comments",
        "products",
        "category",
        "customer",
        "merchant",
        "business",
        "personal",
        "standard",
        "premium1",
        "workflow",
        "pipeline",
        "registry",
        "instance",
        "resource",
        "template",
        "download",
        "uploading",
        "redirect",
        "callback",
        "webhooks",
        "triggers",
        "schedule",
        "calendar",
        "bookmark",
        "favorite",
        "archives",
        "backups1",
        "recovery",
        "validate",
        "verified",
        "approved",
        "accepted",
        "rejected",
        "complete",
        "progress",
        "pending1",
        "queued01",
        "process1",
        "handling",
    ]
)

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
WATCHED_ORG_IDS_FILE = "watched_org_ids.txt"

# Reconnection settings
INITIAL_RECONNECT_DELAY = 1
MAX_RECONNECT_DELAY = 60

# WebSocket settings
_certstream_ws_url = os.environ.get("CERTSTREAM_WS_URL")
if not _certstream_ws_url:
    raise RuntimeError("CERTSTREAM_WS_URL is not set in the environment or .env file")
CERTSTREAM_WS_URL: str = _certstream_ws_url
WS_PING_INTERVAL = 30
WS_PING_TIMEOUT = 10

# Certificate age limit (1 hour)
MAX_CERT_AGE_SECONDS = 3600

# Known CDN/Cloud IP ranges to exclude from IOCs.
# Loaded dynamically from cdn_fetcher at startup.
# See ct_watcher/cdn_fetcher.py for fetching logic.
CDN_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
