from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Optional, Union

from anchore_engine.services.policy_engine.engine.policy.exceptions import (
    ValidationError,
)
from anchore_engine.util.docker import parse_dockerimage_string
from anchore_engine.util.matcher import is_match, regexify


class BaseMapping(ABC):
    def __init__(self, rule_json: Optional[Dict] = None):
        self._raw = rule_json

    @property
    def raw(self):
        return self._raw

    @abstractmethod
    def json(self):
        pass


class ImageMappingRule(BaseMapping):
    """
    A mapping rule that selects targets
    """

    def __init__(self, rule_json=None):
        super().__init__(rule_json)
        self.registry = rule_json.get("registry")
        self.repository = rule_json.get("repository")
        self.image_match_type = rule_json.get("image").get("type")

        if self.image_match_type == "tag":
            self.image_tag = rule_json.get("image").get("value")
        else:
            self.image_tag = None

        if self.image_match_type == "id":
            self.image_id = rule_json.get("image").get("value")
        else:
            self.image_id = None

        if self.image_match_type == "digest":
            self.image_digest = rule_json.get("image").get("value")
        else:
            self.image_digest = None

    def json(self):
        if self.raw:
            return self.raw
        else:
            return {
                "registry": self.registry,
                "repository": self.repository,
                "image": {
                    "type": self.image_match_type,
                    "value": self.image_tag
                    if self.image_tag
                    else self.image_digest
                    if self.image_digest
                    else self.image_id
                    if self.image_id
                    else None,
                },
            }

    def is_all_registry(self):
        return self.registry == "*"

    def is_all_repository(self):
        return self.repository == "*"

    def is_all_tags(self):
        return self.image_tag == "*"

    def is_tag(self):
        return self.image_match_type == "tag"

    def is_digest(self):
        return self.image_match_type == "digest"

    def is_id(self):
        return self.image_match_type == "id"

    def _registry_match(self, registry_str):
        return is_match(regexify, self.registry, registry_str)

    def _repository_match(self, repository_str):
        return is_match(regexify, self.repository, repository_str)

    def _tag_match(self, tag_str):
        return is_match(regexify, self.image_tag, tag_str)

    def _id_match(self, image_id):
        return self.image_id == image_id and image_id is not None

    def _digest_match(self, image_digest):
        return self.image_digest == image_digest and image_digest is not None

    def matches(self, image_obj, tag):
        """
        Returns true if this rule matches the given tag and image tuple according to the matching rules.

        :param image_obj: loaded image object
        :param tag: tag string
        :return: Boolean
        """
        # Special handling of 'dockerhub' -> 'docker.io' conversion.
        if tag and tag.startswith("dockerhub/"):
            target_tag = tag.replace("dockerhub/", "docker.io/")
        else:
            target_tag = tag

        if not target_tag:
            raise ValueError("Tag cannot be empty or null for matching evaluation")
        else:
            match_target = parse_dockerimage_string(target_tag, strict=False)

        # Must match registry and repo first
        if not (
            self._registry_match(match_target.get("registry"))
            and self._repository_match(match_target.get("repo"))
        ):
            return False

        if self.is_digest():
            return self._digest_match(image_obj.digest)
        elif self.is_id():
            return self._id_match(image_obj.id)
        elif self.is_tag():

            if image_obj:
                return (
                    self._tag_match(match_target.get("tag"))
                    or self._id_match(image_obj.id)
                    or self._digest_match(image_obj.digest)
                )
            else:
                return self._tag_match(match_target.get("tag"))


class PolicyMappingMixin:
    def set_policy_attribs(self: Union[BaseMapping, PolicyMappingMixin]):
        if self.raw.get("policy_id") and self.raw.get("policy_ids"):
            raise ValidationError(
                "Cannot specify both policy_id and policy_ids properties in mapping rule, must use one or the other"
            )
        if self.raw.get("policy_id"):
            self.policy_ids = [self.raw.get("policy_id")]
        elif self.raw.get("policy_ids"):
            self.policy_ids = self.raw.get("policy_ids", [])
        else:
            raise ValidationError(
                "No policy_id or policy_ids property found for mapping rule: {}".format(
                    self.raw
                )
            )
        self.whitelist_ids = self.raw.get("whitelist_ids", [])

    def to_json(self: Union[BaseMapping, PolicyMappingMixin]):
        if self.raw:
            return self.raw
        else:
            r = self.json()
            r["policy_ids"] = (self.policy_ids,)
            r["whitelist_ids"] = self.whitelist_ids
            return r


class ImagePolicyMappingRule(ImageMappingRule, PolicyMappingMixin):
    """
    A single mapping rule that can be evaluated against a tag and image
    """

    def __init__(self, rule_json=None):
        super(ImagePolicyMappingRule, self).__init__(rule_json)
        self.policy_ids = []
        self.whitelist_ids = []
        self.set_policy_attribs()

    def json(self):
        return self.to_json()
