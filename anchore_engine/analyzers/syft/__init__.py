import collections

from anchore_engine.analyzers.syft.handlers import (
    modules_by_artifact_type,
    modules_by_engine_type,
)
from anchore_engine.analyzers.utils import content_hints, defaultdict_to_dict, dig
from anchore_engine.clients.syft_wrapper import run_syft
from anchore_engine.subsys import logger


def filter_relationships(relationships, **kwargs):
    def filter_fn(relationship):
        for key, expected in kwargs.items():
            if relationship[key] != expected:
                return False
        return True

    return [r for r in relationships if filter_fn(r)]


def filter_artifacts(artifacts, relationships):
    def filter_fn(artifact):
        # some packages are owned by other packages (e.g. a python package that was installed
        # from an RPM instead of with pip), filter out any packages that are not "root" packages.
        if filter_relationships(
            relationships, child=dig(artifact, "id"), type="ownership-by-file-overlap"
        ):
            return False

        return True

    return [a for a in artifacts if filter_fn(a)]


def catalog_image(imagedir, package_filtering_enabled=True):
    """
    Catalog the given image with syft, keeping only select artifacts in the returned results.
    """
    all_results = run_syft(imagedir)
    return convert_syft_to_engine(all_results, package_filtering_enabled)


def convert_syft_to_engine(all_results, enable_package_filtering=True):
    """
    Do the conversion from syft format to engine format

    :param all_results:
    :return:
    """

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # This is the only use case for consuming the top-level results from syft,
    # capturing the information needed for BusyBox. No artifacts should be
    # expected, and having outside of the artifacts loop ensure this will only
    # get called once.
    distro = all_results.get("distro")
    if distro and distro.get("name", "").lower() == "busybox":
        findings["package_list"]["pkgs.all"]["base"]["BusyBox"] = distro["version"]
    elif not distro or not distro.get("name"):
        findings["package_list"]["pkgs.all"]["base"]["Unknown"] = "0"

    # take a sub-set of the syft findings and invoke the handler function to
    # craft the artifact document and inject into the "raw" analyzer json
    # document
    if enable_package_filtering:
        logger.info("filtering owned packages")
        artifacts = filter_artifacts(
            all_results["artifacts"],
            dig(all_results, "artifactRelationships", force_default=[]),
        )
    else:
        artifacts = all_results["artifacts"]
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
