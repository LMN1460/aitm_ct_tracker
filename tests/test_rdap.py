import json
import os
import sys

import requests
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.rdap import (
    _parse_registrar,
    _parse_reg_date,
    _parse_iana_services,
    _get_rdap_server,
    get_domain_info,
)

import ct_watcher.rdap as rdap_module

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
_COM_RDAP = "https://rdap.verisign.com/com/v1/"


def _load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def _make_response(status_code: int = 200, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


# --- pytest fixtures ---


@pytest.fixture(autouse=True)
def clear_rdap_cache():
    """Clear domain cache before and after every test."""
    rdap_module._domain_cache.clear()
    yield
    rdap_module._domain_cache.clear()


@pytest.fixture
def verisign_bootstrap():
    """Patch IANA bootstrap so .com points to Verisign."""
    with patch.object(rdap_module, "_bootstrap_cache", None):
        with patch.object(rdap_module, "_load_iana_bootstrap", return_value={"com": _COM_RDAP}):
            yield


@pytest.fixture
def mock_response():
    """Return a factory for MagicMock responses."""

    def _factory(status_code: int = 200, json_data=None):
        return _make_response(status_code, json_data)

    return _factory


# --- parsing tests ---


class TestRegistrarParsing:
    def test_vcard_array(self):
        data = _load_fixture("rdap_google_com.json")
        assert _parse_registrar(data) == "MarkMonitor Inc."

    def test_fn_direct_fallback(self):
        data = {"entities": [{"roles": ["registrar"], "fn": "SomeRegistrar LLC"}]}
        assert _parse_registrar(data) == "SomeRegistrar LLC"

    def test_no_registrar_entity(self):
        assert _parse_registrar({"entities": []}) is None
        assert _parse_registrar({}) is None


class TestRegDateParsing:
    def test_registration_date(self):
        data = _load_fixture("rdap_google_com.json")
        assert _parse_reg_date(data) == "1997-09-15T04:00:00Z"

    def test_no_registration_event(self):
        assert _parse_reg_date({"events": []}) is None
        assert _parse_reg_date({}) is None


class TestIANABootstrap:
    def test_parse_services(self):
        data = {
            "services": [
                [["com", "net"], [_COM_RDAP]],
                [["tk"], []],
            ]
        }
        result = _parse_iana_services(data)
        assert result == {"com": _COM_RDAP, "net": _COM_RDAP}


class TestOverrides:
    def test_override_takes_priority(self):
        with patch.object(rdap_module, "_overrides_cache", None):
            with patch.object(
                rdap_module, "_load_overrides", return_value={"zz": "https://rdap.example/"}
            ):
                with patch.object(
                    rdap_module, "_load_iana_bootstrap", return_value={"zz": "https://rdap.other/"}
                ):
                    assert _get_rdap_server("zz") == "https://rdap.example/"

    def test_falls_back_to_iana(self):
        with patch.object(rdap_module, "_overrides_cache", None):
            with patch.object(rdap_module, "_load_overrides", return_value={}):
                with patch.object(
                    rdap_module, "_load_iana_bootstrap", return_value={"com": _COM_RDAP}
                ):
                    assert _get_rdap_server("com") == _COM_RDAP


# --- integration tests ---


class TestDomainLookup:
    def test_second_lookup_reads_cache(self, verisign_bootstrap, mock_response):
        fixture = _load_fixture("rdap_google_com.json")
        resp = mock_response(status_code=200, json_data=fixture)

        with patch("ct_watcher.rdap.requests.get", return_value=resp) as mock_get:
            r1, d1 = get_domain_info("api-abc.google.com")
            r2, d2 = get_domain_info("api-abc.google.com")

        assert r1 == "MarkMonitor Inc."
        assert d1 == "1997-09-15T04:00:00Z"
        assert r2 == r1
        assert d2 == d1
        assert mock_get.call_count == 1

    def test_404_returns_none(self, verisign_bootstrap, mock_response):
        resp = mock_response(status_code=404)

        with patch("ct_watcher.rdap.requests.get", return_value=resp):
            r, d = get_domain_info("example.com")

        assert r is None
        assert d is None

    def test_timeout_returns_none(self, verisign_bootstrap):
        with patch("ct_watcher.rdap.requests.get", side_effect=requests.Timeout):
            r, d = get_domain_info("example.com")

        assert r is None
        assert d is None

    def test_no_known_server_returns_none(self):
        with (
            patch.object(rdap_module, "_overrides_cache", None),
            patch.object(rdap_module, "_load_iana_bootstrap", return_value={"com": _COM_RDAP}),
            patch.object(rdap_module, "_load_overrides", return_value={}),
            patch("ct_watcher.rdap.whois_lookup", return_value=(None, None)) as mock_whois,
        ):
            r, d = get_domain_info("example.tk")

        assert r is None
        assert d is None
        mock_whois.assert_called_once_with("example.tk")
