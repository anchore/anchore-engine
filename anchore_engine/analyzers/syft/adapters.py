"""
Module for adapters that convert syft to other formats
"""
import collections

from anchore_engine.analyzers.syft.handlers import modules_by_artifact_type
from anchore_engine.analyzers.utils import defaultdict_to_dict, dig
from anchore_engine.subsys import logger


class IdentityAdapter:
    """
    Simple identity adapter for syft output that defines the interface.

    This implementation maps syft output to itself.

    """

    def __init__(self, syft_output: dict):
        self.syft_output = syft_output

    def convert(self) -> dict:
        return self.syft_output


def _filter_relationships(relationships, **kwargs):
    def filter_fn(relationship):
        for key, expected in kwargs.items():
            if relationship[key] != expected:
                return False
        return True

    return [r for r in relationships if filter_fn(r)]


def _filter_artifacts(artifacts, relationships):
    """
    Remove artifacts from the main list if they are a child package of another package.
    Package A is a child of Package B if all of Package A's files are managed by Package B per its file manifest.

    The most common examples are python packages that are installed via dpkg or rpms.

    :param artifacts:
    :param relationships:
    :return:
    """

    def filter_fn(artifact):
        # some packages are owned by other packages (e.g. a python package that was installed
        # from an RPM instead of with pip), filter out any packages that are not "root" packages.
        if _filter_relationships(
            relationships, child=dig(artifact, "id"), type="ownership-by-file-overlap"
        ):
            return False

        return True

    return [a for a in artifacts if filter_fn(a)]


def _convert_syft_to_engine(syft_output: dict, enable_package_filtering: bool) -> dict:
    """
    Do the conversion from syft format to engine format

    :param syft_output: raw syft analysis output as a dict
    :param enable_package_filtering: flag to indicate if packages in a child relationship with parent package should be filtered or not from final result
    :return: dict in the engine internal analysis report format generated from the syft output
    """

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # This is the only use case for consuming the top-level results from syft,
    # capturing the information needed for BusyBox. No artifacts should be
    # expected, and having outside of the artifacts loop ensure this will only
    # get called once.
    distro = syft_output.get("distro")
    if distro and distro.get("name", "").lower() == "busybox":
        findings["package_list"]["pkgs.all"]["base"]["BusyBox"] = distro["version"]
    elif not distro or not distro.get("name"):
        findings["package_list"]["pkgs.all"]["base"]["Unknown"] = "0"

    # take a sub-set of the syft findings and invoke the handler function to
    # craft the artifact document and inject into the "raw" analyzer json
    # document
    if enable_package_filtering:
        logger.info("filtering owned packages")
        artifacts = _filter_artifacts(
            syft_output["artifacts"],
            dig(syft_output, "artifactRelationships", force_default=[]),
        )
    else:
        artifacts = syft_output["artifacts"]
    for artifact in artifacts:
        # syft may do more work than what is supported in engine, ensure we only include artifacts
        # of select package types.
        if artifact["type"] not in modules_by_artifact_type:
            logger.warn(
                "Handler for artifact type {} not available. Skipping package {}.".format(
                    artifact["type"], artifact["name"]
                )
            )
            continue
        handler = modules_by_artifact_type[artifact["type"]]
        handler.translate_and_save_entry(findings, artifact)

    return defaultdict_to_dict(findings)


class FilteringEngineAdapter(IdentityAdapter):
    """
    Adapts syft output to Engine native analysis format
    """

    def __init__(self, syft_output: dict, enable_package_filtering: bool = True):
        super().__init__(syft_output)
        self.enable_package_filtering = enable_package_filtering

    def convert(self):
        return _convert_syft_to_engine(self.syft_output, self.enable_package_filtering)
