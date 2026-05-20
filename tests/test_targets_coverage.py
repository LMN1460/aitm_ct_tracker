import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.config import DOMAIN_REGEX
from ct_watcher.utils import extract_target_id


class TestTargetsCoverage:
    """Regression safety net: every target in targets.json must match the regex.

    This test would have caught the Morgan State bug (62a1edm3) immediately
    when it was added to targets.json, since the old regex only supported
    8-char hex IDs, not 8-char alphanumeric IDs.
    """

    def test_all_targets_match_regex(self, target_mapping):
        """Every target ID in targets.json must match DOMAIN_REGEX."""
        if not target_mapping:
            pytest.skip("targets.json not available")

        for target_id in target_mapping:
            test_domain = f"api-{target_id}.example.com"
            assert DOMAIN_REGEX.match(test_domain), (
                f"Target ID '{target_id}' ({target_mapping[target_id]['name']}) "
                f"does not match DOMAIN_REGEX"
            )

    def test_all_targets_extractable(self, target_mapping):
        """Every target ID must be extractable via extract_target_id."""
        if not target_mapping:
            pytest.skip("targets.json not available")

        for target_id in target_mapping:
            test_domain = f"api-{target_id}.example.com"
            extracted = extract_target_id(test_domain)
            assert extracted == target_id, (
                f"Failed to extract '{target_id}' from '{test_domain}' "
                f"(got '{extracted}')"
            )
