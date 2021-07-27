from itertools import chain

import pytest

from anchore_engine.db.entities import policy_engine as pe

from .fixtures import transformation_data


class TestPolicyEngine:
    @pytest.mark.parametrize("single", [transformation_data.single_cve])
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

    @pytest.mark.parametrize(
        "references, expected",
        chain(
            transformation_data.single_cve_references,
            transformation_data.multiple_cve_references,
            transformation_data.no_cve_references,
        ),
    )
    def test_referenced_cves(self, references, expected):
        assert sorted(
            pe.VulnDBMetadata(name="VULNDB-1", references=references).referenced_cves
        ) == sorted(expected)
