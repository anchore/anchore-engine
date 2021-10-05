from typing import DefaultDict, Union

from anchore_engine.analyzers.utils import merge_nested_dict
from anchore_engine.subsys import logger


def save_entry_to_findings(
    findings: Union[dict, DefaultDict], entry: dict, pkg_type: str, pkg_key: str
) -> None:
    """
    Intended to be used to save entries to the analysis report or placeholder that is eventually merged into report
    Prevents overwrite of already written pkgs
    Also ensures safe access to nested attributes by defining them if not already present

    :param findings: analysis report. Either actual report or a place hodler default dict used by syft converted
    :type findings: dict or defaultdict
    :param entry: actual artifact to be added to findings
    :type entry: dict
    :param pkg_type: the pkg_type that is used for the key in the findings path
    :type pkg_type: str
    :param pkg_key: pkg_key used to index the finding. Usually the name or location of package
    :type pkg_key: str
    :return: None
    :rtype: None
    """
    try:
        # If the path is already defined, log a message and do nothing because nothing should override values
        if findings["package_list"][pkg_type]["base"].get(pkg_key):
            logger.warn(
                "%s package already present under %s in the analysis report and will not be overwritten",
                pkg_key,
                pkg_type,
            )
        # Otherwise set it to value
        else:
            findings["package_list"][pkg_type]["base"][pkg_key] = entry
    except KeyError:
        # There is a chance that the specified path in the dictionary does not exist.
        # This happens if artifact type not found by syft but is present in the hints file
        # If that is the case this will create the path and merge it into the findings
        merge_nested_dict(
            findings,
            {"package_list": {pkg_type: {"base": {pkg_key: entry}}}},
        )
