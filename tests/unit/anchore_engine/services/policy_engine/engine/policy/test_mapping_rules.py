import unittest

from anchore_engine.db.entities.policy_engine import Image
from anchore_engine.services.policy_engine.engine.policy.bundles import (
    PolicyMappingRule,
)


def matcher_for_tag(registry="*", repository="*", tag="*"):
    return {
        "registry": registry,
        "repository": repository,
        "image": {"type": "tag", "value": tag},
        "policy_ids": ["x"],
    }


def matcher_for_id(registry="*", repository="*", id="*"):
    return {
        "registry": registry,
        "repository": repository,
        "image": {"type": "id", "value": id},
        "policy_ids": ["x"],
    }


def matcher_for_digest(registry="*", repository="*", digest="*"):
    return {
        "registry": registry,
        "repository": repository,
        "image": {"type": "digest", "value": digest},
        "policy_ids": ["x"],
    }


class TestPolicyMappingRules(unittest.TestCase):
    def test_tag_mapping(self):
        test_rules = [
            {
                # All allowed
                "rule": matcher_for_tag(),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/nginx:latest",
                "match": True,
            },
            {
                # All allowed, none provided
                "rule": matcher_for_tag(),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "*/*:*",
                "match": True,
            },
            {
                # Case where tag not provided for eval, but rule requires it
                "rule": matcher_for_tag(tag="latest"),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "*/*:*",
                "match": False,
            },
            {
                # Registry match failure
                "rule": matcher_for_tag(registry="gcr.io"),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/nginx:latest",
                "match": False,
            },
            {
                # Repo match failure
                "rule": matcher_for_tag(repository="mysql"),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/nginx:latest",
                "match": False,
            },
            {
                # Tag match failure
                "rule": matcher_for_tag(
                    registry="docker.io", repository="mysql", tag="latest"
                ),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/mysql:alpine",
                "match": False,
            },
            {
                # Wildcard sub match
                "rule": matcher_for_tag(tag="*-dev"),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/nginx:1.8-dev",
                "match": True,
            },
            {
                # Registry only match
                "rule": matcher_for_tag(registry="docker.io"),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/nginx:latest",
                "match": True,
            },
            {
                # Registry & repo match
                "rule": matcher_for_tag(registry="docker.io", repository="nginx"),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/nginx:latest",
                "match": True,
            },
            {
                # Docker name handling should happen upstream
                "rule": matcher_for_tag(
                    registry="docker.io", repository="library/nginx"
                ),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/nginx:latest",
                "match": False,
            },
            {
                # Exact match
                "rule": matcher_for_tag(
                    registry="docker.io", repository="library/nginx", tag="latest"
                ),
                "id": "0",
                "digest": "sha256:123abc",
                "tag": "docker.io/library/nginx:latest",
                "match": True,
            },
        ]

        for test in test_rules:
            rule = PolicyMappingRule(test["rule"])
            test_img = Image()
            test_img.id = test["id"]
            test_img.digest = test["digest"]
            m = rule.matches(test_img, tag=test["tag"])
            self.assertEqual(
                test["match"],
                m,
                "Failed on: {} with tag {}".format(test["rule"], test["tag"]),
            )

    def test_digest_mapping(self):
        test_rules = [
            {
                # Digest only specified
                "rule": matcher_for_digest(digest="sha256:123abc"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abc",
                "match": True,
            },
            {
                # Registry fail
                "rule": matcher_for_digest(registry="gcr.io", digest="sha256:123abc"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
            {
                # Repository fail
                "rule": matcher_for_digest(repository="mysql", digest="sha256:123abc"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
            {
                # Case where no tag provided so default wildcard set
                "rule": matcher_for_digest(repository="mysql", digest="sha256:123abc"),
                "tag": "*/*:*",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
            {
                # Digest fail
                "rule": matcher_for_digest(digest="sha256:123abc"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abd",
                "match": False,
            },
            {
                # Repository fail
                "rule": matcher_for_digest(repository="mysql", digest="sha256:123abc"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abd",
                "match": False,
            },
            {
                # Repository wildcard
                "rule": matcher_for_digest(digest="sha256:123abc"),
                "tag": "*/*:*",
                "id": "0",
                "digest": "sha256:123abc",
                "match": True,
            },
            {
                # Repository wildcard, fail on digest match
                "rule": matcher_for_digest(digest="sha256:123abd"),
                "tag": "*/*:*",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
        ]

        for test in test_rules:
            rule = PolicyMappingRule(test["rule"])
            test_img = Image()
            test_img.id = test["id"]
            test_img.digest = test["digest"]
            m = rule.matches(test_img, tag=test["tag"])
            self.assertEqual(
                test["match"],
                m,
                "Failed on: {} with digest {}".format(test["rule"], test["digest"]),
            )

    def test_id_mapping(self):
        test_rules = [
            {
                # id only specified
                "rule": matcher_for_id(id="0"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abc",
                "match": True,
            },
            {
                # Registry fail
                "rule": matcher_for_id(registry="gcr.io", id="0"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
            {
                # Repository fail
                "rule": matcher_for_id(repository="mysql", id="0"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
            {
                # Case where no tag provided so default wildcard set
                "rule": matcher_for_id(repository="mysql", id="0"),
                "tag": "*/*:*",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
            {
                # ID fail
                "rule": matcher_for_id(id="1"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abd",
                "match": False,
            },
            {
                # Repository fail
                "rule": matcher_for_id(repository="mysql", id="0"),
                "tag": "docker.io/nginx:latest",
                "id": "0",
                "digest": "sha256:123abd",
                "match": False,
            },
            {
                # Repository wildcard
                "rule": matcher_for_id(id="0"),
                "tag": "*/*:*",
                "id": "0",
                "digest": "sha256:123abc",
                "match": True,
            },
            {
                # Repository wildcard, fail on digest match
                "rule": matcher_for_id(id="1"),
                "tag": "*/*:*",
                "id": "0",
                "digest": "sha256:123abc",
                "match": False,
            },
        ]

        for test in test_rules:
            rule = PolicyMappingRule(test["rule"])
            test_img = Image()
            test_img.id = test["id"]
            test_img.digest = test["digest"]
            m = rule.matches(test_img, tag=test["tag"])
            self.assertEqual(
                test["match"],
                m,
                "Failed on: {} with id {}".format(test["rule"], test["id"]),
            )


if __name__ == "__main__":
    unittest.main()
