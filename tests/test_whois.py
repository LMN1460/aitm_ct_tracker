import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.whois import (
    _parse_whois,
    _get_whois_server,
    _normalize_date,
    whois_lookup,
)

import ct_watcher.whois as whois_module

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


# --- fixtures ---

@pytest.fixture(autouse=True)
def clear_whois_cache():
    whois_module._whois_server_cache.clear()
    yield
    whois_module._whois_server_cache.clear()


# --- date normalization tests ---

class TestNormalizeDate:
    def test_iso_date(self):
        assert _normalize_date("1997-09-15") == "1997-09-15"

    def test_iso_datetime(self):
        assert _normalize_date("1997-09-15T04:00:00Z") == "1997-09-15T04:00:00Z"

    def test_iso_with_space(self):
        assert _normalize_date("2003-03-17 12:20:05") == "2003-03-17T12:20:05"

    def test_kr_dot_format(self):
        assert _normalize_date("2007. 03. 02.") == "2007-03-02"

    def test_tr_month_format(self):
        assert _normalize_date("2024-Aug-26.") == "2024-08-26"

    def test_jp_slash_format(self):
        assert _normalize_date("2006/05/09") == "2006-05-09"


# --- parsing tests ---

class TestWhoisParsing:
    def test_verisign_format(self):
        raw = _load_fixture("whois_verisign.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar == "MarkMonitor Inc."
        assert reg_date == "1997-09-15T04:00:00Z"

    def test_tci_ru_format(self):
        raw = _load_fixture("whois_tci_ru.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar == "RU-CENTER-RU"
        assert reg_date == "1997-09-23T09:45:07Z"

    def test_mx_format(self):
        raw = _load_fixture("whois_mx.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar == "Markmonitor"
        assert reg_date == "2009-05-12"

    def test_no_match_returns_none(self):
        registrar, reg_date = _parse_whois("garbage text with no registrar")
        assert registrar is None
        assert reg_date is None

    def test_rotld_ro_format(self):
        raw = _load_fixture("whois_rotld_ro.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar == "ICI - Registrar"
        assert reg_date == "2020-11-09"

    def test_nic_at_format_strips_url_suffix(self):
        raw = _load_fixture("whois_nic_at.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar == "MarkMonitor Inc."
        assert reg_date is None

    def test_jp_bracket_date(self):
        raw = _load_fixture("whois_jprs_jp.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar is None
        assert reg_date == "2006-05-09"

    def test_dk_format(self):
        raw = _load_fixture("whois_dk_hostmaster.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar == "MarkMonitor Inc."
        assert reg_date == "1999-01-10"

    def test_cn_format(self):
        raw = _load_fixture("whois_cn_cnnic.txt")
        registrar, reg_date = _parse_whois(raw)
        assert registrar == (
            "\u53a6\u95e8\u6613\u540d\u79d1\u6280\u80a1\u4efd\u6709\u9650\u516c\u53f8"
        )
        assert reg_date == "2003-03-17T12:20:05"

    def test_kr_dot_date_format(self):
        raw = _load_fixture("whois_kr_kisa.txt")
        _registrar, reg_date = _parse_whois(raw)
        assert reg_date == "2007-03-02"

    def test_tr_month_date_format(self):
        raw = _load_fixture("whois_tr_nic.txt")
        _registrar, reg_date = _parse_whois(raw)
        assert reg_date == "2001-08-23"


# --- server discovery tests ---

class TestWhoisServerDiscovery:
    def test_extracts_server_from_iana_response(self):
        with patch.object(
            whois_module, "_whois_query_raw", return_value="whois:        whois.tcinet.ru\n"
        ):
            server = _get_whois_server("ru")
        assert server == "whois.tcinet.ru"

    def test_empty_whois_line_returns_none(self):
        with patch.object(whois_module, "_whois_query_raw", return_value="whois:        \n"):
            server = _get_whois_server("vn")
        assert server is None

    def test_cache_hit_avoids_query(self):
        whois_module._whois_server_cache["ru"] = {"server": "whois.tcinet.ru", "ts": 99999999999}
        with patch.object(whois_module, "_whois_query_raw") as mock:
            server = _get_whois_server("ru")
        assert server == "whois.tcinet.ru"
        mock.assert_not_called()


# --- integration test ---

class TestWhoisLookup:
    def test_full_lookup_verisign(self):
        whois_module._whois_server_cache["com"] = {"server": "whois.example.com", "ts": 99999999999}
        raw = _load_fixture("whois_verisign.txt")

        with patch.object(whois_module, "_whois_query_raw", return_value=raw) as mock:
            registrar, reg_date = whois_lookup("google.com")

        assert registrar == "MarkMonitor Inc."
        assert reg_date == "1997-09-15T04:00:00Z"
        mock.assert_called_once_with("whois.example.com", "google.com")

    def test_no_whois_server_returns_none(self):
        with patch.object(whois_module, "_whois_query_raw", return_value="whois:        \n"):
            registrar, reg_date = whois_lookup("example.vn")

        assert registrar is None
        assert reg_date is None

    def test_jp_uses_domain_prefix(self):
        whois_module._whois_server_cache["jp"] = {"server": "whois.jprs.jp", "ts": 99999999999}
        raw = _load_fixture("whois_jprs_jp.txt")

        with patch.object(whois_module, "_whois_query_raw", return_value=raw) as mock:
            registrar, reg_date = whois_lookup("coreserver.jp")

        assert reg_date == "2006-05-09"
        mock.assert_called_once_with("whois.jprs.jp", "domain coreserver.jp")
