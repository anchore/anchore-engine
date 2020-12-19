import os
import re
import time
import collections

import anchore_engine.utils
from anchore_engine.subsys import logger
from pkg_resources import resource_filename
from . import syft
from . import binary
from . import utils


def run(configdir, imageId, unpackdir, outputdir, copydir):
    analyzer_report = collections.defaultdict(dict)
    _run_analyzer_modules(analyzer_report, configdir, imageId, unpackdir, outputdir)
    _run_syft(analyzer_report, copydir, unpackdir)
    _run_internal_analyzers(analyzer_report, unpackdir)
    return analyzer_report


def _run_analyzer_modules(analyzer_report, configdir, imageId, unpackdir, outputdir):
    anchore_module_root = resource_filename("anchore_engine", "analyzers")
    analyzer_root = os.path.join(anchore_module_root, "modules")
    for f in list_modules():
        cmdstr = " ".join([f, configdir, imageId, unpackdir, outputdir, unpackdir])
        with anchore_engine.utils.timer(
            "Executing analyzer %s".format(repr(f)), log_level="debug"
        ):
            try:
                rc, sout, serr = anchore_engine.utils.run_command(cmdstr)
                sout = anchore_engine.utils.ensure_str(sout)
                serr = anchore_engine.utils.ensure_str(serr)
                if rc != 0:
                    logger.error(
                        "command failed: cmd=%s exitcode=%s stdout=%s stderr=%s".format(
                            repr(cmdstr),
                            repr(rc),
                            repr(sout.strip()),
                            repr(serr.strip()),
                        )
                    )
                else:
                    logger.debug(
                        "command succeeded: cmd=%s stdout=%s stderr=%s".format(
                            repr(cmdstr), repr(sout.strip()), repr(serr.strip())
                        )
                    )
            except Exception as err:
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


def _run_syft(analyzer_report, copydir, unpackdir):
    results = syft.catalog_image(imagedir=copydir, unpackdir=unpackdir)

    utils.merge_nested_dict(analyzer_report, results)


def list_modules():
    """
    Return a list of the analyzer files

    :return: list of str that are the names of the analyzer modules
    """

    anchore_module_root = resource_filename("anchore_engine", "analyzers")
    analyzer_root = os.path.join(anchore_module_root, "modules")
    result = []
    for f in os.listdir(analyzer_root):
        thecmd = os.path.join(analyzer_root, f)
        if re.match(r".*\.py$", thecmd):
            result.append(thecmd)

    result.sort()
    return result
