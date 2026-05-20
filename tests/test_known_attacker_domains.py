import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.domain_checks import is_known_attacker_domain


class TestKnownAttackerDomains:
    """Tests for is_known_attacker_domain function."""

    def test_exact_match(self, known_attacker_domains):
        """Exact domain match should return True."""
        if not known_attacker_domains:
            pytest.skip("known_domains.txt not available")
        domain = next(iter(known_attacker_domains))
        assert is_known_attacker_domain(domain, known_attacker_domains)

    def test_subdomain_match(self, known_attacker_domains):
        """Subdomains of known domains should return True."""
        if not known_attacker_domains:
            pytest.skip("known_domains.txt not available")
        base = next(iter(known_attacker_domains))
        subdomain = f"api-62a1edm3.ghg.{base}"
        assert is_known_attacker_domain(subdomain, known_attacker_domains)

    def test_deep_subdomain_match(self, known_attacker_domains):
        """Deep subdomains of known domains should return True."""
        if not known_attacker_domains:
            pytest.skip("known_domains.txt not available")
        base = next(iter(known_attacker_domains))
        deep = f"a.b.c.d.{base}"
        assert is_known_attacker_domain(deep, known_attacker_domains)

    def test_no_match_random_domain(self, known_attacker_domains):
        """Random domain should return False."""
        assert not is_known_attacker_domain("notanattacker.com", known_attacker_domains)

    def test_no_match_similar_tld(self, known_attacker_domains):
        """Domain with similar name but different TLD should return False."""
        if not known_attacker_domains:
            pytest.skip("known_domains.txt not available")
        base = next(iter(known_attacker_domains))
        fake = base.replace(".com", ".evil.com")
        assert not is_known_attacker_domain(fake, known_attacker_domains)

    def test_no_match_partial_base(self, known_attacker_domains):
        """Domain that contains known domain as substring should not match."""
        assert not is_known_attacker_domain("nottheretrogallery.com", known_attacker_domains)
