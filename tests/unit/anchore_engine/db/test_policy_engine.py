import pytest

from .fixtures import transformation_data
from anchore_engine.db.entities import policy_engine as pe


class TestPolicyEngine:
    @pytest.mark.parametrize("single", [transformation_data.signle_cve])
    def test_normalized_id(self, single):
        # import ipdb; ipdb.set_trace()
        vulndb = pe.VulnDBMetadata(references=single)
        res = vulndb.normalized_id
        assert res == "CVE-1999-0449"

    @pytest.mark.parametrize("multiple", [transformation_data.multiple_cve])
    def test_normalized_id_multi(self, multiple):
        # import ipdb; ipdb.set_trace()
        vulndb = pe.VulnDBMetadata(name="VULNDB-42", references=multiple)
        res = vulndb.normalized_id
        assert res == "VULNDB-42"

    @pytest.mark.parametrize("no_cve", [transformation_data.no_cve])
    def test_normalized_id_no_cve(self, no_cve):
        # import ipdb; ipdb.set_trace()
        vulndb = pe.VulnDBMetadata(name="FAKEVULNDB-42", references=no_cve)
        res = vulndb.normalized_id
        assert res == "FAKEVULNDB-42"
