from anchore_engine.common.models.policy_engine import (
    FixedArtifact,
    VulnerabilityMatch,
)
from anchore_engine.services.policy_engine.engine.vulns.providers import GrypeProvider
import pytest


class TestGrypeProvider:
    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix="true"))],
                id="str",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix="  "))],
                id="whitespace",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix=""))],
                id="blank",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix=False))],
                id="boolean_false",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=None)],
                id="fix_none",
            ),
        ],
    )
    def test_exclude_wont_fix_false(self, test_input):
        assert len(GrypeProvider._exclude_wont_fix(test_input)) == 1

    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix=True))],
                id="boolean_true",
            ),
        ],
    )
    def test_exclude_wont_fix_true(self, test_input):
        assert len(GrypeProvider._exclude_wont_fix(test_input)) == 0
