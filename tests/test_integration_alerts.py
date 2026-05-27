import sys
import os
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.discord import send_discord_alert
from ct_watcher.apprise import send_apprise_alert


SAMPLE_ALL_DOMAINS = [
    "api-529aed63.evil.com",
    "evil.com",
    "www.evil.com",
    "mail.evil.com",
]

SAMPLE_ALERT_KWARGS = {
    "domain": "api-529aed63.evil.com",
    "all_domains": SAMPLE_ALL_DOMAINS,
    "cert_timestamp": 1700000000,
    "is_known_attacker": True,
    "registrar": "Namecheap",
    "is_cloudflare": True,
    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "all_ips": ["1.2.3.4", "5.6.7.8"],
    "non_cdn_ips": ["1.2.3.4"],
    "confirmed_attacker_ip_matches": ["1.2.3.4"],
    "reg_date": "2024-01-15",
    "email_status": "Email sent successfully",
    "email_status_state": "sent",
    "target_info": {"name": "Test University", "email": "security@test.edu"},
}


@pytest.mark.skipif(
    not os.environ.get("TEST_DISCORD_WEBHOOK"),
    reason="TEST_DISCORD_WEBHOOK not set",
)
def test_discord_sends_alert():
    """Send a real Discord alert to verify delivery.

    Set TEST_DISCORD_WEBHOOK to a test Discord webhook URL to run this test.
    """
    webhook = os.environ["TEST_DISCORD_WEBHOOK"]
    with patch("ct_watcher.discord.DISCORD_WEBHOOK", webhook):
        send_discord_alert(**SAMPLE_ALERT_KWARGS)


@pytest.mark.skipif(
    not os.environ.get("TEST_APPRISE_URL"),
    reason="TEST_APPRISE_URL not set",
)
def test_apprise_sends_alert():
    """Send a real Apprise alert to verify delivery.

    Set TEST_APPRISE_URL to an Apprise URL (e.g., discord://..., slack://...,
    pushover://...) to run this test.
    """
    apprise_url = os.environ["TEST_APPRISE_URL"]
    apprise_kwargs = {k: v for k, v in SAMPLE_ALERT_KWARGS.items() if k != "email_status_state"}
    with patch("ct_watcher.apprise.APPRISE_URLS", apprise_url):
        send_apprise_alert(**apprise_kwargs)
