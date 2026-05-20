import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.config import DOMAIN_REGEX
from ct_watcher.utils import extract_target_id, is_common_word_id


class TestDomainRegex:
    """Tests for DOMAIN_REGEX pattern matching."""

    @pytest.mark.parametrize("domain", [
        "api-62a1edm3.ghg.theretrogallery.com",
        "api-3dse1.example.com",
        "api-529aed63.example.com",
        "api-a540f86.example.com",
        "api-abcdef.example.com",
        "api-ABCDEFG.example.com",
        "api-12345.example.com",
        "api-a1b2c3d4.example.com",
    ])
    def test_matches_valid_ids(self, domain):
        assert DOMAIN_REGEX.match(domain), f"Should match: {domain}"

    @pytest.mark.parametrize("domain", [
        "api-xyz.example.com",
        "api-abcd.example.com",
        "api-abcdefghijk.example.com",
        "api-abcdefghijkl.example.com",
        "notapi-abcde.example.com",
        "xapi-abcde.example.com",
        "api-abcde",
    ])
    def test_rejects_invalid_ids(self, domain):
        assert not DOMAIN_REGEX.match(domain), f"Should reject: {domain}"

    @pytest.mark.parametrize("domain", [
        "api-test.ngrok.io",
        "api-test.ngrok-free.app",
        "api-test.workers.dev",
        "api-test.amazonaws.com",
        "api-test.azure.something.com",
        "api-test.googleusercontent.com",
        "api-test.huaweiclouds.example.com",
        "api-test.multi.software",
        "api-test.upsolver.com",
    ])
    def test_rejects_cloud_saas(self, domain):
        assert not DOMAIN_REGEX.match(domain), f"Should reject cloud/SaaS: {domain}"


class TestExtractTargetId:
    """Tests for extract_target_id function."""

    @pytest.mark.parametrize("domain,expected", [
        ("api-62a1edm3.ghg.theretrogallery.com", "62a1edm3"),
        ("api-3dse1.example.com", "3dse1"),
        ("api-529aed63.example.com", "529aed63"),
        ("api-a540f86.example.com", "a540f86"),
        ("api-abcde.sub.example.com", "abcde"),
        ("api-ABCDEF.example.com", "abcdef"),
        ("api-abcde.example.com", "abcde"),
        ("api-abcdef.example.com", "abcdef"),
        ("api-abcdefg.example.com", "abcdefg"),
        ("api-abcdefgh.example.com", "abcdefgh"),
    ])
    def test_extracts_correctly(self, domain, expected):
        assert extract_target_id(domain) == expected

    @pytest.mark.parametrize("domain", [
        "notapi-abcde.example.com",
        "api-xyz.example.com",
        "api-abcdefghijk.example.com",
        "api-abcde",
        "example.com",
    ])
    def test_returns_none_for_invalid(self, domain):
        assert extract_target_id(domain) is None


class TestIsCommonWordId:
    """Tests for is_common_word_id false positive filtering."""

    @pytest.mark.parametrize("api_id", [
        "admin", "local", "store", "stage", "stats",
        "proxy", "cache", "queue", "media", "video",
        "audio", "cloud", "login", "oauth", "token",
        "debug", "fetch", "route", "error", "start",
    ])
    def test_filters_5char_common_words(self, api_id):
        assert is_common_word_id(api_id) is True

    @pytest.mark.parametrize("api_id", [
        "internal", "external", "platform", "services",
        "database", "security", "settings", "products",
        "download", "callback", "schedule", "complete",
    ])
    def test_filters_8char_common_words(self, api_id):
        assert is_common_word_id(api_id) is True

    @pytest.mark.parametrize("api_id", [
        "3dse1", "admin1", "l0cal", "st0re",
        "62a1edm3", "529aed63", "a540f86",
    ])
    def test_does_not_filter_ids_with_digits(self, api_id):
        assert is_common_word_id(api_id) is False

    @pytest.mark.parametrize("api_id", [
        "xyzqw", "abcdef", "qwerty", "foobar",
        "abcde", "abcdefgh",
    ])
    def test_does_not_filter_unknown_words(self, api_id):
        assert is_common_word_id(api_id) is False

    def test_empty_string(self):
        assert is_common_word_id("") is False
        assert is_common_word_id(None) is False
