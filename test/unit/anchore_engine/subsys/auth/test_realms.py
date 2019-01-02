import pytest
from anchore_engine.subsys.auth.realms import CaseSensitivePermission


def test_anchore_permissions():

    # Default, case-sensitive, exact match
    assert (CaseSensitivePermission(wildcard_string="Account1:listImages:*").implies(
        CaseSensitivePermission(wildcard_string="Account1:listImages:*")))

    # Ignore case
    assert (CaseSensitivePermission(wildcard_string="account1:listImages:*", case_sensitive=False).implies(
        CaseSensitivePermission(wildcard_string="Account1:listImages:*", case_sensitive=False)))

    # Mixed case, mismatch
    assert (not CaseSensitivePermission(wildcard_string="account1:listImages:*").implies(
        CaseSensitivePermission(wildcard_string="Account1:listImages:*")))

