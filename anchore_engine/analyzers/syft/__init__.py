import collections

from anchore_engine.analyzers.utils import defaultdict_to_dict, content_hints
from anchore_engine.clients.syft_wrapper import run_syft
from .handlers import handlers_by_artifact_type, handlers_by_engine_type


def filter_artifacts(artifact):
    return artifact["type"] in handlers_by_artifact_type


def catalog_image(image, unpackdir):
    """
    Catalog the given image with syft, keeping only select artifacts in the returned results.
    """
    all_results = run_syft(image)
    return convert_syft_to_engine(all_results, unpackdir)


def convert_syft_to_engine(all_results, unpackdir, handle_hints=True):
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
    for artifact in filter(filter_artifacts, all_results["artifacts"]):
        handler = handlers_by_artifact_type[artifact["type"]]
        handler.translate_and_save_entry(findings, artifact)

    if handle_hints:
        # apply content hints, overriding values that are there
        for engine_entry in content_hints(unpackdir=unpackdir):
            pkg_type = engine_entry.get("type")
            if pkg_type:
                handler = handlers_by_engine_type[pkg_type]
                handler.save_entry(findings, engine_entry)

    return defaultdict_to_dict(findings)
