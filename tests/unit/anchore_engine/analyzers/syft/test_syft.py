import pytest

from anchore_engine.analyzers.syft import filter_artifacts


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
            "bogus",
            "",
        ],
    )
    def test_filter_artifact_by_type(self, pkg_type):
        artifacts = [
            {
                "id": "pkg-id",
                "name": "pkg-name",
                "type": pkg_type,
            },
        ]

        actual = filter_artifacts(artifacts, [])
        assert not [a["name"] for a in actual]

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
