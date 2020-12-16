"""
Common message types and marshalling helper functions
"""
import base64
import copy
import json
import time

from anchore_engine.subsys import logger


def make_response_error(errmsg, in_httpcode=None, details=None):
    if details is None:
        details = {}
    if not in_httpcode:
        httpcode = 500
    else:
        httpcode = in_httpcode

    msg = str(errmsg)

    ret = {"message": msg, "httpcode": int(httpcode), "detail": details}
    if "error_codes" not in ret["detail"]:
        ret["detail"]["error_codes"] = []

    if isinstance(errmsg, Exception):
        if not hasattr(errmsg, "anchore_error_json"):
            return ret

        # Try to load it as json
        try:
            anchore_error_json = getattr(errmsg, "anchore_error_json", None)
            if isinstance(anchore_error_json, dict):
                err_json = anchore_error_json
            else:
                err_json = json.loads(anchore_error_json)
        except (TypeError, ValueError):
            # Then it may just be a string, we cannot do anything with it
            logger.debug("Failed to parse anchore_error_json as json")
            return ret

        if {"message", "httpcode", "detail"}.issubset(set(err_json)):
            ret.update(err_json)

        try:
            if {"error_code"}.issubset(set(err_json)) and err_json.get(
                "error_code", None
            ):
                if "error_codes" not in ret["detail"]:
                    ret["detail"]["error_codes"] = []
                ret["detail"]["error_codes"].append(err_json.get("error_code"))
        except KeyError:
            logger.warn(
                "unable to marshal error details: source error {}".format(
                    errmsg.__dict__
                )
            )
    return ret


def make_anchore_exception(
    err,
    input_message=None,
    input_httpcode=None,
    input_detail=None,
    override_existing=False,
    input_error_codes=None,
):
    ret = Exception(err)

    if not input_message:
        message = str(err)
    else:
        message = input_message

    if input_detail != None:
        detail = input_detail
    else:
        detail = {"raw_exception_message": str(err)}

    if input_error_codes != None:
        error_codes = input_error_codes
    else:
        error_codes = []

    if not input_httpcode:
        httpcode = 500
    else:
        httpcode = input_httpcode

    anchore_error_json = {}
    try:
        if isinstance(err, Exception):
            if hasattr(err, "anchore_error_json"):
                anchore_error_json.update(getattr(err, "anchore_error_json"))

            if hasattr(err, "error_code"):
                error_codes.append(getattr(err, "error_code"))
    except:
        pass

    if override_existing or not anchore_error_json:
        ret.anchore_error_json = {
            "message": message,
            "detail": detail,
            "httpcode": httpcode,
        }
    else:
        ret.anchore_error_json = anchore_error_json

    if "detail" in ret.anchore_error_json:
        if "error_codes" not in ret.anchore_error_json["detail"]:
            ret.anchore_error_json["detail"]["error_codes"] = []

        if error_codes:
            ret.anchore_error_json["detail"]["error_codes"].extend(error_codes)

    return ret


def make_response_routes(apiversion, inroutes):
    return_object = {}
    httpcode = 500

    routes = []
    try:
        for route in inroutes:
            routes.append("/".join([apiversion, route]))
    except Exception as err:
        httpcode = 500
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    else:
        httpcode = 200
        return_object = routes

    return return_object, httpcode


def update_image_record_with_analysis_data(image_record, image_data):
    formatted_image_summary_data = {}
    image_summary_data = extract_analyzer_content(image_data, "metadata")

    try:
        image_summary_metadata = copy.deepcopy(image_summary_data)
        if image_summary_metadata:
            logger.debug("getting image summary data")

            summary_record = {}

            adm = image_summary_metadata["anchore_distro_meta"]

            summary_record["distro"] = adm.pop("DISTRO", "N/A")
            summary_record["distro_version"] = adm.pop("DISTROVERS", "N/A")

            air = image_summary_metadata["anchore_image_report"]
            airm = air.pop("meta", {})
            al = air.pop("layers", [])
            ddata = air.pop("docker_data", {})

            summary_record["layer_count"] = str(len(al))
            summary_record["dockerfile_mode"] = air.pop("dockerfile_mode", "N/A")
            summary_record["arch"] = ddata.pop("Architecture", "N/A")
            summary_record["image_size"] = str(int(airm.pop("sizebytes", 0)))

            formatted_image_summary_data = summary_record
    except Exception as err:
        formatted_image_summary_data = {}

    if formatted_image_summary_data:
        image_record.update(formatted_image_summary_data)

    dockerfile_content, dockerfile_mode = extract_dockerfile_content(image_data)
    if dockerfile_content and dockerfile_mode:
        image_record["dockerfile_mode"] = dockerfile_mode
        for image_detail in image_record["image_detail"]:
            logger.debug("setting image_detail: ")
            image_detail["dockerfile"] = str(
                base64.b64encode(dockerfile_content.encode("utf-8")), "utf-8"
            )

    return True


def extract_dockerfile_content(image_data):
    dockerfile_content = ""
    dockerfile_mode = "Guessed"

    try:
        dockerfile_content = image_data[0]["image"]["imagedata"]["image_report"][
            "dockerfile_contents"
        ]
        dockerfile_mode = image_data[0]["image"]["imagedata"]["image_report"][
            "dockerfile_mode"
        ]
    except Exception as err:
        dockerfile_content = ""
        dockerfile_mode = "Guessed"

    return dockerfile_content, dockerfile_mode


def extract_files_content(image_data):
    """
    Extract analyzed files content

    :param image_data:
    :return:
    """
    try:
        ret = {}
        fcsums = {}
        if (
            "files.sha256sums"
            in image_data["imagedata"]["analysis_report"]["file_checksums"]
        ):
            adata = image_data["imagedata"]["analysis_report"]["file_checksums"][
                "files.sha256sums"
            ]["base"]
            for k in list(adata.keys()):
                fcsums[k] = adata[k]

        if "files.allinfo" in image_data["imagedata"]["analysis_report"]["file_list"]:
            adata = image_data["imagedata"]["analysis_report"]["file_list"][
                "files.allinfo"
            ]["base"]
            for k in list(adata.keys()):
                avalue = safe_extract_json_value(adata[k])
                if k in fcsums:
                    avalue["sha256"] = fcsums[k]
                ret[k] = avalue
        return ret
    except Exception as err:
        raise Exception("could not extract/parse content info - exception: " + str(err))


def extract_os_content(image_data):
    ret = {}
    if "pkgs.allinfo" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_npm_content(image_data):
    ret = {}
    if "pkgs.npms" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"]["pkgs.npms"][
            "base"
        ]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_gem_content(image_data):
    ret = {}
    if "pkgs.gems" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"]["pkgs.gems"][
            "base"
        ]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_python_content(image_data):
    ret = {}
    if "pkgs.python" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_java_content(image_data):
    ret = {}
    if "pkgs.java" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"]["pkgs.java"][
            "base"
        ]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_pkg_content(image_data, content_type):
    # catchall for additional pkg types
    ret = {}
    adata = image_data["imagedata"]["analysis_report"]["package_list"][
        "pkgs.{}".format(content_type)
    ]["base"]
    for k in list(adata.keys()):
        ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_malware_content(image_data):
    # Extract malware scan
    ret = []
    clamav_content_name = "clamav"
    malware_scans = (
        image_data["imagedata"]["analysis_report"]
        .get("malware", {})
        .get("malware", {})
        .get("base", {})
    )

    for scanner_name, output in malware_scans.items():
        finding = safe_extract_json_value(output)
        ret.append(finding)

        # ret[scanner_name]
        # name = finding.get('name')
        # for result in finding.get('findings'):
        #     ret[path] = {'scanner': clamav_content_name, 'findings': path_findings }

    return ret


def extract_analyzer_content(image_data, content_type, manifest=None):
    ret = {}
    try:
        idata = image_data[0]["image"]
        imageId = idata["imageId"]

        if content_type == "files":
            return extract_files_content(idata)
        elif content_type == "os":
            return extract_os_content(idata)
        elif content_type == "npm":
            return extract_npm_content(idata)
        elif content_type == "gem":
            return extract_gem_content(idata)
        elif content_type == "python":
            return extract_python_content(idata)
        elif content_type == "java":
            return extract_java_content(idata)
        elif content_type == "malware":
            return extract_malware_content(idata)
        elif (
            "pkgs.{}".format(content_type)
            in idata["imagedata"]["analysis_report"]["package_list"]
        ):
            return extract_pkg_content(idata, content_type)
        elif content_type == "metadata":
            if (
                "image_report" in idata["imagedata"]
                and "analyzer_meta" in idata["imagedata"]["analysis_report"]
            ):
                ret = {
                    "anchore_image_report": image_data[0]["image"]["imagedata"][
                        "image_report"
                    ],
                    "anchore_distro_meta": image_data[0]["image"]["imagedata"][
                        "analysis_report"
                    ]["analyzer_meta"]["analyzer_meta"]["base"],
                }
        elif content_type == "manifest":
            ret = {}
            try:
                if manifest:
                    ret = json.loads(manifest)
            except:
                ret = {}
        elif content_type == "docker_history":
            ret = []
            try:
                ret = (
                    idata.get("imagedata", {})
                    .get("image_report", {})
                    .get("docker_history", [])
                )
            except:
                ret = []
        elif content_type == "dockerfile":
            ret = ""
            try:
                if (
                    idata.get("imagedata", {})
                    .get("image_report", {})
                    .get("dockerfile_mode", "")
                    .lower()
                    == "actual"
                ):
                    ret = (
                        idata.get("imagedata", {})
                        .get("image_report", {})
                        .get("dockerfile_contents", "")
                    )
            except:
                ret = ""

    except Exception as err:
        logger.error("could not extract/parse content info - exception: " + str(err))
        raise err

    return ret


def make_policy_record(userId, bundle, policy_source="local", active=False):
    payload = {}

    policyId = bundle["id"]

    payload["policyId"] = policyId
    payload["active"] = active
    payload["userId"] = userId
    payload["policybundle"] = bundle
    payload["policy_source"] = policy_source

    return payload


def make_eval_record(
    userId, evalId, policyId, imageDigest, tag, final_action, eval_url
):
    payload = {}

    payload["policyId"] = policyId
    payload["userId"] = userId
    payload["evalId"] = evalId
    payload["imageDigest"] = imageDigest
    payload["tag"] = tag
    payload["final_action"] = final_action
    payload["policyeval"] = eval_url
    payload["created_at"] = int(time.time())
    payload["last_updated"] = payload["created_at"]

    return payload


def safe_extract_json_value(value):
    # support the legacy serialized json string
    try:
        return json.loads(value)
    except (TypeError, json.decoder.JSONDecodeError):
        return value
