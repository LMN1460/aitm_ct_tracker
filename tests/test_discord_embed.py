import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.discord import build_embed, _build_minimal_embed


SAMPLE_TARGET = {"name": "Test University", "email": "security@test.edu"}
SAMPLE_TARGET_MAPPING = {"529aed63": SAMPLE_TARGET}


class TestDiscordEmbedTitleAndColor:
    """Tests for embed title and color."""

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_known_attacker_title_and_color(self):
        embed = build_embed(
            domain="attacker.com",
            all_domains=["attacker.com"],
            is_known_attacker=True,
        )
        assert "Certificate Transparency Alert" in embed["title"]
        assert embed["color"] == 0xFF0000

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_pattern_match_title_and_color(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            is_known_attacker=False,
        )
        assert "Potential Target Match" in embed["title"]
        assert embed["color"] == 0xFFA500


class TestDiscordTargetResolution:
    """Tests for target organization resolution scenarios."""

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_target_info_passed_directly(self):
        """Known attacker domain with no api-ID, target resolved from scanning all_domains."""
        embed = build_embed(
            domain="attacker.com",
            all_domains=["attacker.com", "api-529aed63.evil.com"],
            is_known_attacker=True,
            target_info=SAMPLE_TARGET,
        )
        target_fields = [f for f in embed["fields"] if "Target Organization" in f["name"]]
        assert len(target_fields) == 1
        assert "Test University" in target_fields[0]["value"]
        assert "security@test.edu" in target_fields[0]["value"]

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_target_info_from_state_lookup(self):
        """api-ID in matched domain, target found in state.target_mapping."""
        from ct_watcher import state

        original = state.state.target_mapping.copy()
        try:
            state.state.target_mapping = SAMPLE_TARGET_MAPPING
            embed = build_embed(
                domain="api-529aed63.evil.com",
                all_domains=["api-529aed63.evil.com"],
            )
            target_fields = [f for f in embed["fields"] if "Target Organization" in f["name"]]
            assert len(target_fields) == 1
            assert "Test University" in target_fields[0]["value"]
        finally:
            state.state.target_mapping = original

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_unknown_target_hex_id(self):
        """api-ID in matched domain but not in target_mapping."""
        from ct_watcher import state

        original = state.state.target_mapping.copy()
        try:
            state.state.target_mapping = {}
            embed = build_embed(
                domain="api-abcdef.evil.com",
                all_domains=["api-abcdef.evil.com"],
                is_known_attacker=False,
            )
            hex_fields = [f for f in embed["fields"] if f["name"] == "Hex ID"]
            assert len(hex_fields) == 1
            assert "abcdef" in hex_fields[0]["value"]
            assert "Unknown Target" in hex_fields[0]["value"]
        finally:
            state.state.target_mapping = original

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_no_api_id_no_target(self):
        """Bare domain with no api-ID and no target_info passed."""
        embed = build_embed(
            domain="attacker.com",
            all_domains=["attacker.com"],
        )
        target_fields = [f for f in embed["fields"] if "Target Organization" in f["name"]]
        hex_fields = [f for f in embed["fields"] if f["name"] == "Hex ID"]
        assert len(target_fields) == 0
        assert len(hex_fields) == 0

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_known_attacker_sets_red_color(self):
        """Known attacker with target info should have red color."""
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            is_known_attacker=True,
            target_info=SAMPLE_TARGET,
        )
        assert embed["color"] == 0xFF0000


class TestDiscordFieldOrdering:
    """Tests for field ordering in the embed."""

    @patch("ct_watcher.discord.EMAIL_ENABLED", True)
    def test_email_status_before_actions(self):
        """Email Status field must appear before Actions field."""
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            email_status="Email sent successfully",
            email_status_state="sent",
        )
        field_names = [f["name"] for f in embed["fields"]]
        email_status_idx = field_names.index("Email Status")
        actions_idx = field_names.index("📣 Actions")
        assert email_status_idx < actions_idx

    @patch("ct_watcher.discord.EMAIL_ENABLED", True)
    def test_email_status_after_all_domains(self):
        """Email Status field must appear after All Domains in Certificate."""
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            email_status="Email sent successfully",
            email_status_state="sent",
        )
        field_names = [f["name"] for f in embed["fields"]]
        all_domains_idx = field_names.index("All Domains in Certificate")
        email_status_idx = field_names.index("Email Status")
        assert email_status_idx > all_domains_idx


class TestDiscordEmbedFields:
    """Tests for individual field rendering."""

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_matched_domain_defanged(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
        )
        matched_field = [f for f in embed["fields"] if f["name"] == "Matched Domain"][0]
        assert "api-529aed63[.]evil[.]com" in matched_field["value"]

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_freshness_discord_timestamp(self):
        ts = 1700000000
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            cert_timestamp=ts,
        )
        freshness_field = [f for f in embed["fields"] if f["name"] == "Certificate Freshness"][0]
        assert freshness_field["value"] == "<t:1700000000:R>"

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_freshness_unknown(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            cert_timestamp=None,
        )
        freshness_field = [f for f in embed["fields"] if f["name"] == "Certificate Freshness"][0]
        assert freshness_field["value"] == "Unknown"

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_domain_count(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com", "evil.com", "www.evil.com"],
        )
        count_field = [f for f in embed["fields"] if f["name"] == "Domain Count"][0]
        assert count_field["value"] == "3"

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_registrar_shown(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            registrar="Namecheap",
        )
        reg_field = [f for f in embed["fields"] if f["name"] == "Registrar"][0]
        assert reg_field["value"] == "Namecheap"

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_confirmed_attacker_ip_match_field(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            confirmed_attacker_ip_matches=["1.2.3.4", "5.6.7.8"],
        )
        ip_match_fields = [f for f in embed["fields"] if "Confirmed Attacker IP Match" in f["name"]]
        assert len(ip_match_fields) == 1
        assert "1.2.3.4" in ip_match_fields[0]["value"]

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_ip_addresses_with_cdn_tags(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            all_ips=["1.2.3.4", "5.6.7.8"],
            non_cdn_ips=["1.2.3.4"],
        )
        ip_fields = [f for f in embed["fields"] if "IP Addresses" in f["name"]]
        assert len(ip_fields) == 1
        assert "1.2.3.4 (non-cdn)" in ip_fields[0]["value"]
        assert "5.6.7.8 (cdn)" in ip_fields[0]["value"]

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_nameserver_info(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            nameservers=["ns1.cloudflare.com"],
            is_cloudflare=True,
        )
        cf_field = [f for f in embed["fields"] if "Cloudflare Nameservers" in f["name"]][0]
        assert "Yes" in cf_field["value"]

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_domain_registered_discord_timestamp(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            reg_date="2024-01-15",
        )
        reg_field = [f for f in embed["fields"] if "Domain Registered" in f["name"]][0]
        assert reg_field["value"] == "<t:1705276800:R>"

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_domain_registered_invalid_date(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            reg_date="not-a-date",
        )
        reg_field = [f for f in embed["fields"] if "Domain Registered" in f["name"]][0]
        assert reg_field["value"] == "not-a-date"

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_domain_registered_unknown(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            reg_date=None,
        )
        reg_field = [f for f in embed["fields"] if "Domain Registered" in f["name"]][0]
        assert reg_field["value"] == "Unknown (RDAP unavailable)"


class TestDiscordAllDomainsBlock:
    """Tests for all domains rendering."""

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_all_domains_defanged(self):
        embed = build_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com", "evil.com"],
        )
        domains_field = [f for f in embed["fields"] if "All Domains in Certificate" in f["name"]][0]
        assert "api-529aed63[.]evil[.]com" in domains_field["value"]
        assert "evil[.]com" in domains_field["value"]

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_domains_capped_at_50(self):
        domains = [f"api-529aed63.sub{i}.evil.com" for i in range(60)]
        embed = build_embed(
            domain=domains[0],
            all_domains=domains,
        )
        domains_field = [f for f in embed["fields"] if "All Domains in Certificate" in f["name"]][0]
        # The field value is capped at 50 domains, then truncated to 512 chars by _sanitize_embed.
        # Verify the first domain is present and the field does NOT contain all 60 domains.
        assert "api-529aed63[.]sub0[.]evil[.]com" in domains_field["value"]
        assert "api-529aed63[.]sub59[.]evil[.]com" not in domains_field["value"]


class TestMinimalEmbed:
    """Tests for _build_minimal_embed fallback."""

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_minimal_embed_has_required_fields(self):
        embed = _build_minimal_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com", "evil.com"],
            registrar="Namecheap",
            cert_timestamp=1700000000,
            confirmed_attacker_ip_matches=None,
            reg_date=None,
        )
        field_names = [f["name"] for f in embed["fields"]]
        assert "Matched Domain" in field_names
        assert "Domain Count" in field_names
        assert "Registrar" in field_names
        assert "Certificate Freshness" in field_names

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_minimal_embed_freshness_discord_timestamp(self):
        ts = 1700000000
        embed = _build_minimal_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            registrar="Namecheap",
            cert_timestamp=ts,
            confirmed_attacker_ip_matches=None,
            reg_date=None,
        )
        freshness_field = [f for f in embed["fields"] if f["name"] == "Certificate Freshness"][0]
        assert freshness_field["value"] == "<t:1700000000:R>"

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_minimal_embed_confirmed_ip_match(self):
        embed = _build_minimal_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            registrar="Namecheap",
            cert_timestamp=None,
            confirmed_attacker_ip_matches=["1.2.3.4"],
            reg_date=None,
        )
        ip_fields = [f for f in embed["fields"] if "Confirmed Attacker IP Match" in f["name"]]
        assert len(ip_fields) == 1
        assert "1.2.3.4" in ip_fields[0]["value"]

    @patch("ct_watcher.discord.EMAIL_ENABLED", False)
    def test_minimal_embed_domain_registered_timestamp(self):
        embed = _build_minimal_embed(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            registrar="Namecheap",
            cert_timestamp=None,
            confirmed_attacker_ip_matches=None,
            reg_date="2024-01-15",
        )
        reg_field = [f for f in embed["fields"] if "Domain Registered" in f["name"]][0]
        assert reg_field["value"] == "<t:1705276800:R>"
