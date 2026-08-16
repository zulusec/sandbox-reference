"""The broker's decision logic is unit tested here. Its behaviour as a
running service is tested by the probes against the live reference sandbox.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference" / "broker"))

from broker import decide, host_of

_ALLOWLIST = ["example.invalid", "*.pypi.invalid"]


def test_exact_host_is_allowed():
    assert decide("example.invalid", _ALLOWLIST)


def test_unlisted_host_is_denied():
    assert not decide("blocked.invalid", _ALLOWLIST)


def test_wildcard_matches_one_label():
    assert decide("files.pypi.invalid", _ALLOWLIST)


def test_wildcard_does_not_match_the_bare_domain():
    assert not decide("pypi.invalid", _ALLOWLIST)


def test_wildcard_does_not_match_a_suffix_impostor():
    """evilpypi.invalid must not match *.pypi.invalid."""
    assert not decide("evilpypi.invalid", _ALLOWLIST)


def test_matching_is_case_insensitive():
    assert decide("EXAMPLE.INVALID", _ALLOWLIST)


def test_port_is_stripped_before_matching():
    assert host_of("example.invalid:443") == "example.invalid"


def test_denied_host_with_allowed_suffix_is_still_denied():
    assert not decide("example.invalid.attacker.invalid", _ALLOWLIST)
