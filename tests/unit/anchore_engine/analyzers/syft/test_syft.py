import json
import os

import pytest

from anchore_engine.analyzers.syft import convert_syft_to_engine, filter_artifacts


class TestFilterArtifacts:
    @pytest.mark.parametrize(
        "relationships",
        [
            [
                {
                    "parent": "parent-id",
                    "child": "child-id",
                    "type": "NOT-ownership-by-file-overlap",
                }
            ],
            [
                {
                    "parent": "parent-id",
                    "child": "NOT-child-id",
                    "type": "ownership-by-file-overlap",
                }
            ],
            [],
        ],
    )
    def test_does_not_filter_artifact_by_relationships(self, relationships):
        artifacts = [
            {
                "id": "child-id",
                "name": "child-pkg",
                "type": "rpm",
            },
            {
                "id": "parent-id",
                "name": "parent-pkg",
                "type": "rpm",
            },
        ]

        actual = filter_artifacts(artifacts, relationships)
        assert actual == artifacts

    @pytest.mark.parametrize(
        "relationships",
        [
            [
                {
                    "parent": "parent-id",
                    "child": "child-id",
                    "type": "ownership-by-file-overlap",
                }
            ],
            [
                {
                    "parent": "parent-id",
                    "child": "child-id",
                    "type": "ownership-by-file-overlap",
                },
                {
                    "parent": "another-parent-id",
                    "child": "child-id",
                    "type": "ownership-by-file-overlap",
                },
            ],
            [
                {
                    "parent": "UNCORRELATED-id",
                    "child": "child-id",
                    "type": "ownership-by-file-overlap",
                }
            ],
        ],
    )
    def test_filter_artifact_by_relationships(self, relationships):
        artifacts = [
            {
                "id": "child-id",
                "name": "child-pkg",
                "type": "rpm",
            },
            {
                "id": "parent-id",
                "name": "parent-pkg",
                "type": "rpm",
            },
        ]

        actual = filter_artifacts(artifacts, relationships)
        assert [a["name"] for a in actual] == ["parent-pkg"]

    def test_filter_artifact_missing_id(self):
        # we are ensuring that filtering is not applied if IDs & relationships are missing
        initial_artifacts = [
            {
                "name": "child-pkg",
                "type": "rpm",
            },
            {
                "name": "parent-pkg",
                "type": "rpm",
            },
        ]

        actual = filter_artifacts(initial_artifacts, [])
        assert actual == initial_artifacts

    @pytest.mark.parametrize(
        "pkg_type",
        [
            "npm",
            "apk",
            "deb",
            "jenkins-plugin",
            "java-archive",
        ],
    )
    def test_does_not_filter_artifact_by_type(self, pkg_type):
        artifacts = [
            {
                "id": "pkg-id",
                "name": "pkg-name",
                "type": pkg_type,
            },
        ]

        actual = filter_artifacts(artifacts, [])
        assert [a["name"] for a in actual] == ["pkg-name"]


@pytest.fixture
def test_sbom(request):
    module_path = os.path.dirname(request.module.__file__)
    test_name = os.path.splitext(os.path.basename(request.module.__file__))[0]
    with open(
        os.path.join(
            module_path, test_name, "{}.json".format(request.node.originalname)
        )
    ) as file:
        return json.load(file)


class TestConvertSyftToEngine:
    @pytest.mark.parametrize(
        "enable_package_filtering",
        [False, True],
    )
    def test_filter_artifact_by_type(self, test_sbom, enable_package_filtering):
        findings = convert_syft_to_engine(test_sbom, enable_package_filtering)
        for pkg_list in findings["package_list"]:
            if pkg_list == "pkgfiles.all":
                continue
            assert (
                "UNSUPPORTED-PACKAGE"
                not in findings["package_list"][pkg_list]["base"].keys()
            )
            assert (
                "SUPPORTED-PACKAGE" in findings["package_list"][pkg_list]["base"].keys()
            )
