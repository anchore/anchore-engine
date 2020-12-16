"""
Utility functions for the api controllers

These functions may raise/use api exception types

"""
import copy
import jsonschema
import re
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
            "creation_timestamp_override": created_at,
        }
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
