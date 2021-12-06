import collections
import dataclasses
import os
import re

from pkg_resources import resource_filename

import anchore_engine.utils
from anchore_engine.analyzers import binary, hints, syft, utils
from anchore_engine.analyzers.hints import HintsTypeError
from anchore_engine.configuration.localconfig import analyzer_paths
from anchore_engine.subsys import logger


@dataclasses.dataclass
class AnalysisResult:
    """
    Simple class for the results of an analysis pass
    """

    analysis_report: dict
    image_export: list
    syft_output: dict
    manifest: dict


def run(
    configdir,
    imageId,
    unpackdir,
    outputdir,
    copydir,
    owned_package_filtering_enabled=True,
) -> AnalysisResult:
    analyzer_report = collections.defaultdict(dict)
    _run_analyzer_modules(analyzer_report, configdir, imageId, unpackdir, outputdir)
    syft_output = _run_syft(
        analyzer_report,
        unpackdir,
        copydir,
        package_filtering_enabled=owned_package_filtering_enabled,
    )
    _run_internal_analyzers(analyzer_report, unpackdir)

    apply_hints(analyzer_report, unpackdir)

    # Make this a dict instead of a defaultdict to ensure functional tests (standalone.py) can dump
    # this output cleanly as a python object without the type prefix that just a 'defaultdict' adds.
    dict_analyzer_report = dict(analyzer_report)

    result = AnalysisResult(
        analysis_report=dict_analyzer_report,
        image_export=[],
        syft_output=syft_output,
        manifest={},
    )
    return result


def apply_hints(analyzer_report, unpackdir):
    # apply content hints, overriding values that are there
    # note: upstream of this processing overwrites the hints file location if
    # the config does not explicitly enable hints processing, effectively disabling
    # hints processing.
    for engine_entry in utils.content_hints(unpackdir=unpackdir):
        pkg_type = engine_entry.get("type", None)

        # Just in case it's set to null explicitly in the hint
        pkg_type = pkg_type.lower() if pkg_type else None
        if (
            pkg_type
            and pkg_type in syft.modules_by_engine_type
            and pkg_type in hints.hints_by_type
        ):
            handler = syft.modules_by_engine_type[pkg_type]
            try:
                hint = hints.hints_by_type[pkg_type](engine_entry).to_dict()
            except HintsTypeError:
                logger.exception("failed to process hint")
                continue
            handler.save_entry(analyzer_report, hint)
        else:
            logger.debug("pkg_type %s not supported for syft hints", pkg_type)


def _run_analyzer_modules(analyzer_report, configdir, imageId, unpackdir, outputdir):
    for f in list_modules():
        cmdstr = " ".join([f, configdir, imageId, unpackdir, outputdir, unpackdir])
        with anchore_engine.utils.timer(
            "Executing analyzer %s" % str(f), log_level="info"
        ):
            try:
                rc, sout, serr = anchore_engine.utils.run_command(cmdstr)
                sout = anchore_engine.utils.ensure_str(sout)
                serr = anchore_engine.utils.ensure_str(serr)
                if rc != 0:
                    logger.error(
                        "command failed: cmd=%s exitcode=%s stdout=%s stderr=%s",
                        repr(cmdstr),
                        repr(rc),
                        repr(sout.strip()),
                        repr(serr.strip()),
                    )
                else:
                    logger.debug(
                        "command succeeded: cmd=%s stdout=%s stderr=%s",
                        repr(cmdstr),
                        repr(sout.strip()),
                        repr(serr.strip()),
                    )
            except Exception:
                logger.exception(
                    "Unexpected exception while running analyzer module (%s)", repr(f)
                )

    analyzer_output_dir = os.path.join(outputdir, "analyzer_output")
    for analyzer_output in os.listdir(analyzer_output_dir):

        element_dir = os.path.join(analyzer_output_dir, analyzer_output)
        for element in os.listdir(element_dir):

            data_path = os.path.join(element_dir, element)
            data = utils.read_kvfile_todict(data_path)
            if data:
                analyzer_report[analyzer_output][element] = {"base": data}


def _run_internal_analyzers(analyzer_report, unpackdir):
    allpkgfiles = utils.dig(
        analyzer_report, "package_list", "pkgfiles.all", "base", force_default=[]
    )

    results = binary.catalog_image(allpkgfiles=allpkgfiles, unpackdir=unpackdir)

    utils.merge_nested_dict(analyzer_report, results)


def _run_syft(
    analyzer_report, unpackdir, copydir, package_filtering_enabled=True
) -> dict:
    """
    Execute syft and merge the results into the provided analyzer report

    :param analyzer_report:
    :param unpackdir:
    :param copydir: directory path to use fo r
    :param package_filtering_enabled: boolean to control if packages should be filtered out if they are "owned" by another package
    :return: the raw syft output dict
    """
    unified_results, raw_syft = syft.catalog_image(
        tmp_dir=unpackdir,
        image_oci_dir=copydir,
        package_filtering_enabled=package_filtering_enabled,
    )

    utils.merge_nested_dict(analyzer_report, unified_results)

    return raw_syft


def analyzer_name_from_path(path):
    return os.path.basename(path)


def list_modules(lookup_paths: list = None):
    """
    Return a list of the analyzer files

    :return: list of str that are the names of the analyzer modules
    """
    result = []

    if lookup_paths is None:
        lookup_paths = analyzer_paths()

    for path in lookup_paths:
        analyzer_module_root = resource_filename(path, "modules")
        # analyzer_root = os.path.join(anchore_module_root, "modules")
        for f in os.listdir(analyzer_module_root):
            thecmd = os.path.join(analyzer_module_root, f)
            if re.match(r".*\.py$", thecmd):
                result.append(thecmd)

    result.sort(key=lambda x: analyzer_name_from_path(x))
    return result
