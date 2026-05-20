import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.utils import defang_domain, get_base_domain


class TestDefangDomain:
    """Tests for defang_domain function."""

    def test_simple_domain(self):
        assert defang_domain("example.com") == "example[.]com"

    def test_subdomain(self):
        assert defang_domain("api.example.com") == "api[.]example[.]com"

    def test_deep_subdomain(self):
        assert defang_domain("a.b.c.example.com") == "a[.]b[.]c[.]example[.]com"

    def test_already_defanged(self):
        assert defang_domain("api[.]example[.]com") == "api[[.]]example[[.]]com"


class TestGetBaseDomain:
    """Tests for get_base_domain function."""

    def test_simple_domain(self):
        assert get_base_domain("example.com") == "example.com"

    def test_subdomain(self):
        assert get_base_domain("api.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert get_base_domain("a.b.c.example.com") == "example.com"

    def test_single_part(self):
        assert get_base_domain("localhost") == "localhost"

    def test_two_parts(self):
        assert get_base_domain("example.co.uk") == "co.uk"
