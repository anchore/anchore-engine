from __future__ import annotations

from anchore_engine.services.policy_engine.engine.policy.exceptions import (
    UnsupportedVersionError,
)


class VersionedEntityMixin(object):
    __supported_versions__ = ["1_0"]

    def verify_version(self, json_obj):
        found_version = json_obj.get("version")
        if not found_version or found_version not in self.__supported_versions__:
            raise UnsupportedVersionError(
                got_version=found_version,
                supported_versions=self.__supported_versions__,
                message="Version not supported",
            )


class SimpleMemoryBundleCache(object):
    def __init__(self):
        self._bundles = {}

    def get(self, user_id, bundle_id):
        return self._bundles.get((user_id, bundle_id))

    def cache(self, user_id, bundle):
        self._bundles[(user_id, bundle.id)] = bundle

    def flush(self):
        self._bundles = {}
