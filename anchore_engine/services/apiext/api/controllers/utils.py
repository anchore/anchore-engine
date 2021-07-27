"""
Utility functions for the api controllers

These functions may raise/use api exception types

"""
import copy
import json
import re
from typing import Dict, List

import jsonschema

import anchore_engine.common
from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.common import nonos_package_types
from anchore_engine.common.models.policy_engine import (
    CVSS,
    ImageVulnerabilitiesReport,
    NVDReference,
    Vulnerability,
)
from anchore_engine.subsys import logger
from anchore_engine.util.docker import parse_dockerimage_string

REGISTRY_TAG_SOURCE_SCHEMA_DEFINITION_NAME = "RegistryTagSource"
REGISTRY_DIGEST_SOURCE_SCHEMA_DEFINITION_NAME = "RegistryDigestSource"
REGISTRY_ARCHIVE_SOURCE_SCHEMA_DEFINITION_NAME = "AnalysisArchiveSource"

DIGEST_REGEX = re.compile(r"^\W*sha256:[a-fA-F0-9]{64}\W*$")


eltemplate = {
    "vuln": "None",
    "severity": "None",
    "url": "None",
    "fix": "None",
    "package": "None",
    "package_name": "None",
    "package_version": "None",
    "package_type": "None",
    "package_cpe": "None",
    "package_cpe23": "None",
    "package_path": "None",
    "feed": "None",
    "feed_group": "None",
    "nvd_data": "None",
    "vendor_data": "None",
}


def validate_pullstring_is_tag(pullstring: str) -> bool:
    try:
        parsed = parse_dockerimage_string(pullstring)
        return parsed.get("tag") is not None
    except Exception as e:
        logger.debug_exception(
            "Error parsing pullstring {}. Err = {}".format(pullstring, e)
        )
        raise ValueError("Error parsing pullstring {}".format(pullstring))


def validate_pullstring_is_digest(pullstring: str) -> bool:
    try:
        parsed = parse_dockerimage_string(pullstring)
        return parsed.get("digest") is not None
    except Exception as e:
        logger.debug_exception(
            "Error parsing pullstring {}. Err = {}".format(pullstring, e)
        )
        raise ValueError("Error parsing pullstring {}".format(pullstring))


def validate_tag_source(tag_source: dict, api_schema: dict) -> bool:
    """
    This exists since the regular API validation doesn't apply to the normalized output.

    :param tag_source:
    :return:
    """
    schema = api_schema.get("definitions", {}).get(
        REGISTRY_TAG_SOURCE_SCHEMA_DEFINITION_NAME
    )

    try:
        jsonschema.validate(tag_source, schema)
    except jsonschema.ValidationError as e:
        raise BadRequest(
            "Validation error", detail={"validation_error": "{}".format(e)}
        )

    if not validate_pullstring_is_tag(tag_source["pullstring"]):
        raise BadRequest(
            "Must have tag-based pull string",
            detail={"invalid_value": tag_source["pullstring"]},
        )


def validate_digest_source(digest_source: dict, api_schema: dict) -> bool:
    schema = api_schema.get("definitions", {}).get(
        REGISTRY_DIGEST_SOURCE_SCHEMA_DEFINITION_NAME
    )

    try:
        jsonschema.validate(digest_source, schema)
    except jsonschema.ValidationError as e:
        raise BadRequest(
            "Validation error", detail={"validation_error": "{}".format(e)}
        )

    if not validate_pullstring_is_digest(digest_source["pullstring"]):
        raise BadRequest(
            "Must have digest-based pull string",
            detail={"invalid_value": digest_source["pullstring"]},
        )
    if not validate_pullstring_is_tag(digest_source["tag"]):
        raise BadRequest(
            "Must have tag-based pull string",
            detail={"invalid_value": digest_source["tag"]},
        )


def validate_archive_source(archive_source: dict, api_schema) -> bool:
    schema = api_schema.get("definitions", {}).get(
        REGISTRY_ARCHIVE_SOURCE_SCHEMA_DEFINITION_NAME
    )

    try:
        jsonschema.validate(archive_source, schema)
    except jsonschema.ValidationError as e:
        raise BadRequest(
            "Validation error", detail={"validation_error": "{}".format(e)}
        )


def normalize_image_add_source(analysis_request_dict):
    """
    Normalizes the ImageAnalysisRequest-schema input request (validated already at API marshalling) into using the 'source' property instead
    of the deprecated 'tag', 'digest', and 'dockerfile' properties.

    Returns a new dict with the normalized request

    :param analysis_request_dict:
    :return: normalized request dict
    """

    if not analysis_request_dict:
        raise ValueError("Invalid request object, must be a valid json object")

    normalized = copy.deepcopy(analysis_request_dict)

    if normalized.get("source"):
        # Already has a source, that should be validated
        return normalized

    source = {}
    digest = tag = dockerfile = created_at = None

    if "digest" in normalized:
        digest = normalized.pop("digest")

    if "tag" in normalized:
        tag = normalized.pop("tag")

    if "dockerfile" in normalized:
        dockerfile = normalized.pop("dockerfile")

    if "created_at" in normalized:
        created_at = normalized.pop("created_at")

    # use legacy fields and normalize to a source
    if digest:
        if DIGEST_REGEX.match(digest) is not None:
            # It's only a digest (e.g. sha256:abc), construct a pullstring
            if tag:
                parsed = parse_dockerimage_string(tag)
                digest_pullstring = (
                    parsed["registry"] + "/" + parsed["repo"] + "@" + digest
                )
            else:
                raise ValueError(
                    "For a digest-based analysis, the tag property must also be populated"
                )
        else:
            # assume pull string, so no-op
            digest_pullstring = digest

        source["digest"] = {
            "pullstring": digest_pullstring,
            "tag": tag,
        }
        if created_at:
            source["digest"]["creation_timestamp_override"] = created_at
        if dockerfile:
            source["digest"]["dockerfile"] = dockerfile

        normalized["source"] = source
    elif tag:
        source["tag"] = {"pullstring": tag}

        if dockerfile:
            source["tag"]["dockerfile"] = dockerfile

        normalized["source"] = source

    else:
        raise BadRequest(
            'Must include either "tag", "tag" and "digest", or "source" property in body',
            detail={},
        )

    return normalized


def validate_image_add_source(analysis_request_dict, api_schema):
    """
    Validates the normalized ImageAnalysisRequest Schema (swagger.yaml) with semantic checks
    Raises exceptions on validation errors:

    BadRequest exceptions if the request has properties that don't make sense in combination or violate format checks

    ValueError if the input dict does not have the data expected to perform validation (e.g. needed to be normalized first)

    :param analysis_request_dict: the analysis request object
    :param api_schema: the schema dict for the api to base validation on
    :return: True on success
    """

    source = analysis_request_dict.get("source")
    top_tag = analysis_request_dict.get("tag")
    top_digest = analysis_request_dict.get("digest")
    top_dockerfile = analysis_request_dict.get("dockerfile")

    if source:
        if top_digest is not None or top_tag is not None or top_dockerfile is not None:
            raise BadRequest(
                "Cannot use both source property and tag, digest, or dockerfile property at top level",
                detail={},
            )

        digest_source = source.get("digest")
        tag_source = source.get("tag")
        archive_source = source.get("archive")
        import_source = source.get("import")

        if digest_source:
            return validate_digest_source(digest_source, api_schema)
        elif tag_source:
            return validate_tag_source(tag_source, api_schema)
        elif archive_source:
            return validate_archive_source(archive_source, api_schema)
        elif import_source:
            return True
        else:
            raise BadRequest("Must have one source propery set", detail={})

    else:
        raise ValueError('Expected a "source" property in the input dict')


def make_cvss_scores(metrics):
    """
     [
        {
          "cvss_v2": {
            "base_metrics": {
              ...
            },
            "vector_string": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "version": "2.0"
          },
          "cvss_v3": {
            "base_metrics": {
             ...
            },
            "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "version": "3.0"
          },
          "id": "CVE-2019-1234"
        },
        {
          "cvss_v2": {
            "base_metrics": {
              ...
            },
            "vector_string": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "version": "2.0"
          },
          "cvss_v3": {
            "base_metrics": {
             ...
            },
            "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "version": "3.0"
          },
          "id": "CVE-2019-3134"
        },
     ]
    :param metrics:
    :return:
    """
    score_list = []

    for metric in metrics:
        new_score_packet = {
            "id": metric.get("id"),
        }
        score_list.append(new_score_packet)

        for i in [3, 2]:
            cvss_dict = metric.get("cvss_v{}".format(i), {})
            base_metrics = cvss_dict.get("base_metrics", {}) if cvss_dict else {}

            tmp = base_metrics.get("base_score", -1.0)
            base_score = float(tmp) if tmp else -1.0
            tmp = base_metrics.get("exploitability_score", -1.0)
            exploitability_score = float(tmp) if tmp else -1.0
            tmp = base_metrics.get("impact_score", -1.0)
            impact_score = float(tmp) if tmp else -1.0

            new_score_packet["cvss_v{}".format(i)] = {
                "base_score": base_score,
                "exploitability_score": exploitability_score,
                "impact_score": impact_score,
            }

    return score_list


def to_cvss_score(cvss: CVSS):
    """
    Utility function for transforming a CVSS object to dict. Returns a dict with cvss_v2 or cvss_v3 as the key.
    Other CVSS major versions are not currently supported by the API
    """
    if not cvss or not cvss.version:
        return None

    # parse major CVSS version
    major_version = cvss.version.split(".", 1)[0]

    # currently supported keys are cvss_v2 or cvss_v3, so ignore other versions for now
    if major_version not in ["2", "3"]:
        return None

    return {
        "cvss_v{}".format(major_version): {
            "base_score": cvss.base_score,
            "exploitability_score": cvss.exploitability_score,
            "impact_score": cvss.impact_score,
        }
    }


def get_nvd_data_from_nvd_references(nvd_refs: List[NVDReference]) -> List[Dict]:
    """
    Utility function for creating a list of cvss dicts from a list of NVDReference objects
    """
    results = []

    if not nvd_refs:
        return results

    for nvd_ref in nvd_refs:
        # generate nvd data item for each nvd reference
        nvd_dict = {
            "id": nvd_ref.vulnerability_id,
            # set defaults first for backwards compatibility, argh!
            "cvss_v2": {
                "base_score": -1.0,
                "exploitability_score": -1.0,
                "impact_score": -1.0,
            },
            "cvss_v3": {
                "base_score": -1.0,
                "exploitability_score": -1.0,
                "impact_score": -1.0,
            },
        }

        if nvd_ref.cvss:
            # get cvss_v2 or cvss_v3 dicts and update the nvd_dict
            for cvss_obj in nvd_ref.cvss:
                cvss_dict = to_cvss_score(cvss_obj)

                if cvss_dict:
                    nvd_dict.update(cvss_dict)

        results.append(nvd_dict)

    return results


def get_nvd_data_from_vulnerability(vulnerability: Vulnerability) -> List[Dict]:
    """
    Utility function for creating a list of cvss dicts from a vulnerability object
    """
    results = []

    if not vulnerability.cvss:
        return results

    # generate nvd data item for each nvd reference
    nvd_dict = {
        "id": vulnerability.vulnerability_id,
        # set defaults first for backwards compatibility, argh!
        "cvss_v2": {
            "base_score": -1.0,
            "exploitability_score": -1.0,
            "impact_score": -1.0,
        },
        "cvss_v3": {
            "base_score": -1.0,
            "exploitability_score": -1.0,
            "impact_score": -1.0,
        },
    }

    if vulnerability.cvss:
        # get cvss_v2 or cvss_v3 dicts and update the nvd_dict
        for cvss_obj in vulnerability.cvss:
            cvss_dict = to_cvss_score(cvss_obj)

            if cvss_dict:
                nvd_dict.update(cvss_dict)

    results.append(nvd_dict)

    return results


def get_vendor_data_from_vulnerability(vulnerability: Vulnerability) -> List:
    """
    Utility function for creating vendor_data cvss dict from Vulnerability object
    """
    results = []

    if not vulnerability.cvss:
        return results

    for cvss_obj in vulnerability.cvss:
        cvss_dict = to_cvss_score(cvss_obj)

        if cvss_dict:
            vendor_dict = {
                "id": vulnerability.vulnerability_id,
                # set defaults first for backwards compatibility, argh!
                "cvss_v2": {
                    "base_score": -1.0,
                    "exploitability_score": -1.0,
                    "impact_score": -1.0,
                },
                "cvss_v3": {
                    "base_score": -1.0,
                    "exploitability_score": -1.0,
                    "impact_score": -1.0,
                },
            }

            vendor_dict.update(cvss_dict)
            results.append(vendor_dict)

    return results


def is_type_match(report_type: str, package_type: str) -> bool:
    """
    Returns True if the report type is os and package types is rpm, dpkg or apkg.
    Returns True if the report type is non-os and package type is python, java, npm, gem, go etc
    Returns True if the report type is all regardless of the package

    :param report_type: type of vulnerabilities requested. Valid values: os, non-os, all
    :param package_type: package type such as rpm, apkg, python etc
    """
    if report_type == "all":
        return True
    elif report_type == "os":
        return package_type.lower() not in nonos_package_types
    elif report_type == "non-os":
        return package_type.lower() in nonos_package_types
    else:
        return True


def make_response_vulnerability_report(vulnerability_type, vulnerability_report):
    vulns = []

    # Convert the response from json to the model type
    image_vulnerabilities = ImageVulnerabilitiesReport.from_json(vulnerability_report)

    for result in image_vulnerabilities.results:
        if not result.vulnerability or not result.artifact:
            logger.warn(
                "Missing vulnerability and or artifact data in match record, skipping"
            )
            continue

        # process the item only if it matches the requested type, otherwise skip it
        if not is_type_match(
            report_type=vulnerability_type, package_type=result.artifact.pkg_type
        ):
            logger.debug(
                "%s package is not a match for %s vulnerabilities, skipping",
                result.artifact.pkg_type,
                vulnerability_type,
            )
            continue

        # backwards compatibility for filling in literal "None"
        vuln_dict = copy.deepcopy(eltemplate)

        vuln_dict["vuln"] = result.vulnerability.vulnerability_id
        vuln_dict["severity"] = result.vulnerability.severity
        if result.vulnerability.link:
            vuln_dict["url"] = result.vulnerability.link
        if result.fix and result.fix.versions:
            vuln_dict["fix"] = ",".join(result.fix.versions)
        vuln_dict["package"] = "{}-{}".format(
            result.artifact.name, result.artifact.version
        )
        vuln_dict["package_name"] = result.artifact.name
        vuln_dict["package_version"] = result.artifact.version
        vuln_dict["package_type"] = result.artifact.pkg_type
        if result.artifact.cpe:
            vuln_dict["package_cpe"] = result.artifact.cpe
        if result.artifact.cpes:
            # hack since api doesn't support multiples
            vuln_dict["package_cpe23"] = result.artifact.cpes[0]
        vuln_dict["package_path"] = result.artifact.location
        vuln_dict["feed"] = result.vulnerability.feed
        vuln_dict["feed_group"] = result.vulnerability.feed_group
        # backwards compatibility hack
        if result.vulnerability.feed_group and "nvd" in result.vulnerability.feed_group:
            vuln_dict["nvd_data"] = get_nvd_data_from_vulnerability(
                result.vulnerability
            )
            vuln_dict["vendor_data"] = []
        else:
            vuln_dict["nvd_data"] = get_nvd_data_from_nvd_references(result.nvd)
            vuln_dict["vendor_data"] = get_vendor_data_from_vulnerability(
                result.vulnerability
            )

        vulns.append(vuln_dict)

    return vulns


def make_response_vulnerability(vulnerability_type, vulnerability_data):
    ret = []

    if not vulnerability_data:
        logger.warn("empty query data given to format - returning empty result")
        return ret

    osvulns = []
    nonosvulns = []
    dedup_hash = {}

    keymap = {
        "vuln": "CVE_ID",
        "severity": "Severity",
        "package": "Vulnerable_Package",
        "fix": "Fix_Available",
        "url": "URL",
        "package_type": "Package_Type",
        "feed": "Feed",
        "feed_group": "Feed_Group",
        "package_name": "Package_Name",
        "package_path": "Package_Path",
        "package_version": "Package_Version",
    }
    scan_result = vulnerability_data["legacy_report"]
    try:
        for imageId in list(scan_result.keys()):
            header = scan_result[imageId]["result"]["header"]
            rows = scan_result[imageId]["result"]["rows"]
            for row in rows:
                el = {}
                el.update(eltemplate)
                for k in list(keymap.keys()):
                    try:
                        el[k] = row[header.index(keymap[k])]
                    except:
                        el[k] = "None"

                    # conversions
                    if el[k] == "N/A":
                        el[k] = "None"

                if el["package_type"].lower() in anchore_engine.common.os_package_types:
                    osvulns.append(el)
                else:
                    nonosvulns.append(el)

                el["nvd_data"] = []
                el["vendor_data"] = []
                if row[header.index("CVES")]:
                    all_data = json.loads(
                        row[header.index("CVES")]
                    )  # {'nvd_data': [], 'vendor_data': []}
                    el["nvd_data"] = make_cvss_scores(all_data.get("nvd_data", []))
                    el["vendor_data"] = make_cvss_scores(
                        all_data.get("vendor_data", [])
                    )
                    # gather nvd references and build package-path->CVE-IDs map. to be used by dedup
                    pkg_path = el.get("package_path")
                    if pkg_path not in dedup_hash:
                        dedup_hash[pkg_path] = set()
                    for nvd_el in el["nvd_data"]:
                        dedup_hash[pkg_path].add(nvd_el.get("id"))
    except Exception as err:
        logger.exception("could not prepare query response")
        logger.warn("could not prepare query response - exception: " + str(err))
        ret = []

    # non-os CPE search
    keymap = {
        "vuln": "vulnerability_id",
        "severity": "severity",
        "package_name": "name",
        "package_version": "version",
        "package_path": "pkg_path",
        "package_type": "pkg_type",
        "package_cpe": "cpe",
        "package_cpe23": "cpe23",
        "url": "link",
        "feed": "feed_name",
        "feed_group": "feed_namespace",
    }
    scan_result = vulnerability_data["cpe_report"]
    # gather nvd references of non-nvd vulnerabilities and build package-path->CVE-IDs map. to be used by dedup
    for vuln in scan_result:
        if vuln.get("feed_name") not in ["nvdv2", "nvd"]:
            pkg_path = vuln.get("pkg_path")
            if pkg_path not in dedup_hash:
                dedup_hash[pkg_path] = set()
            for nvd_item in vuln.get("nvd_data", []):
                dedup_hash[pkg_path].add(nvd_item.get("id"))

    # hash of non-os vulnerabilities in the final result, represented by a tuple containing feed, vuln_id and pkg_path
    included = set()
    for vuln in scan_result:
        feed_name = vuln.get("feed_name")
        vuln_id = vuln.get("vulnerability_id")
        pkg_path = vuln.get("pkg_path")

        # dedup pass for nvd vulnerabilities
        if (
            feed_name in ["nvdv2", "nvd"]
            and pkg_path in dedup_hash
            and vuln_id in dedup_hash[pkg_path]
        ):
            # non-nvd sources get priority, skip nvd record if non-nvd vuln exists
            continue

        # dedup pass for uniqueness, issue may be caused by fp corrections introducing repeats
        if (feed_name, vuln_id, pkg_path) in included:
            # Allow only one record for vulnerability per namespace affecting a package.
            # This will still allow dups (same vulnerability ID and package) across non-nvd namespaces such as github and vulndb
            continue

        # add the record to included hash
        included.add((feed_name, vuln_id, pkg_path))

        el = {}
        el.update(eltemplate)

        for k in list(keymap.keys()):
            el[k] = vuln[keymap[k]]

        if vuln["name"] != vuln["version"]:
            pkg_final = "{}-{}".format(vuln["name"], vuln["version"])
        else:
            pkg_final = vuln["name"]

        el["package"] = pkg_final

        # get nvd scores
        el["nvd_data"] = []
        el["nvd_data"] = make_cvss_scores(vuln.get("nvd_data", []))

        # get vendor scores
        el["vendor_data"] = []
        el["vendor_data"] = make_cvss_scores(vuln.get("vendor_data", []))

        fixed_in = vuln.get("fixed_in", [])
        el["fix"] = ", ".join(fixed_in) if fixed_in else "None"

        nonosvulns.append(el)

    if vulnerability_type == "os":
        ret = osvulns
    elif vulnerability_type == "non-os":
        ret = nonosvulns
    elif vulnerability_type == "all":
        ret = osvulns + nonosvulns
    else:
        ret = vulnerability_data

    return ret
