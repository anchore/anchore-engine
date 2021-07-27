from anchore_engine.subsys import logger
from anchore_engine.subsys.auth.realms import CaseSensitivePermission

logger.enable_test_logging()


def test_anchore_permissions():
    """
    Test permission comparisons with mixed-case, wild-cards, etc

    :return:
    """

    logger.info("Testing permission wildcard matches and mixed-case comparisions")
    # Default, case-sensitive, exact match
    assert CaseSensitivePermission(wildcard_string="Account1:listImages:*").implies(
        CaseSensitivePermission(wildcard_string="Account1:listImages:*")
    )

    # Ignore case
    assert CaseSensitivePermission(
        wildcard_string="account1:listImages:*", case_sensitive=False
    ).implies(
        CaseSensitivePermission(
            wildcard_string="Account1:listImages:*", case_sensitive=False
        )
    )

    # Mixed case, mismatch
    assert not CaseSensitivePermission(wildcard_string="account1:listImages:*").implies(
        CaseSensitivePermission(wildcard_string="Account1:listImages:*")
    )
