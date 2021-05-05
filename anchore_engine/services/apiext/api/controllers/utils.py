"""
Utility functions for the api controllers

These functions may raise/use api exception types

"""
import copy
import json

import jsonschema
import re

import anchore_engine.common
from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.utils import parse_dockerimage_string
from anchore_engine.subsys import logger

REGISTRY_TAG_SOURCE_SCHEMA_DEFINITION_NAME = "RegistryTagSource"
REGISTRY_DIGEST_SOURCE_SCHEMA_DEFINITION_NAME = "RegistryDigestSource"
REGISTRY_ARCHIVE_SOURCE_SCHEMA_DEFINITION_NAME = "AnalysisArchiveSource"

DIGEST_REGEX = re.compile(r"^\W*sha256:[a-fA-F0-9]{64}\W*$")


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


def make_response_vulnerability(vulnerability_type, vulnerability_data):
    ret = []

    if not vulnerability_data:
        logger.warn("empty query data given to format - returning empty result")
        return ret

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


def transform_grype_vulnerability(grype_raw_result):
    """
    Receives a single vulnerability_metadata record from grype_db and maps into the data structure engine expects.
    The vulnerability_metadata record may optionally (but in practice should always) have a nested record for the
    related vulnerability record.
    """
    # Create the templated output object
    output_vulnerability = {}
    return_el_template = {
        "id": None,
        "namespace": None,
        "severity": None,
        "link": None,
        "affected_packages": None,
        "description": None,
        "references": None,
        "nvd_data": None,
        "vendor_data": None,
    }
    output_vulnerability.update(return_el_template)

    # Set mapped field values
    output_vulnerability["id"] = grype_raw_result.id
    output_vulnerability["description"] = grype_raw_result.description
    output_vulnerability["severity"] = grype_raw_result.severity

    # TODO What should we do with multiple links. Currently just grabbing the first one
    if grype_raw_result.deserialized_links:
        output_vulnerability["link"] = grype_raw_result.deserialized_links[0]
    else:
        output_vulnerability["link"] = []

    # TODO Not sure yet how these should be mapped
    output_vulnerability["references"] = None

    vendor_data = {}
    vendor_data["id"] = grype_raw_result.id
    vendor_data["cvss_v2"] = grype_raw_result.deserialized_cvss_v2
    vendor_data["cvss_v3"] = grype_raw_result.deserialized_cvss_v3
    if grype_raw_result.record_source and grype_raw_result.record_source.startswith(
        "nvdv2"
    ):
        output_vulnerability["nvd_data"] = [vendor_data]
        output_vulnerability["vendor_data"] = []
    else:
        output_vulnerability["nvd_data"] = []
        output_vulnerability["vendor_data"] = [vendor_data]

    # Get fields from the nested vulnerability object, if it exists
    if grype_raw_result.vulnerability is not None:
        output_vulnerability["namespace"] = grype_raw_result.vulnerability.namespace

        affected_package = {}
        affected_package["name"] = grype_raw_result.vulnerability.package_name
        affected_package["type"] = grype_raw_result.vulnerability.version_format
        affected_package["version"] = grype_raw_result.vulnerability.version_constraint
        output_vulnerability["affected_packages"] = [affected_package]

    return output_vulnerability


def transform_grype_vulnerabilities(grype_raw_results):
    """
    Receives a list of vulnerability_metadata records from grype_db and returns a list of vulnerabilities mapped
    into the data structure engine expects.
    """
    transformed_vulnerabilities = []
    for grype_raw_result in grype_raw_results:
        transformed_vulnerabilities.append(
            transform_grype_vulnerability(grype_raw_result)
        )

    return transformed_vulnerabilities
