import base64
import json
import stat

import anchore_engine.configuration.localconfig
from anchore_engine import utils
from anchore_engine.subsys import logger
from anchore_engine.common import os_package_types


def make_image_content_response(content_type, content_data):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    all_content_types = localconfig.get("image_content_types", []) + localconfig.get(
        "image_metadata_types", []
    )

    if content_type not in all_content_types:
        logger.warn(
            "input content_type (%s) not supported (%s)",
            content_type,
            all_content_types,
        )
        return []

    if not content_data:
        logger.warn("empty content data given to format - returning empty result")
        return []

    builder = CONTENT_RESPONSE_BUILDER_DISPATCH.get(
        content_type, _build_default_response
    )
    return builder(content_data)


def _build_os_response(content_data):
    response = []
    for package_name, package_info in content_data.items():
        el = {}
        try:
            el["package"] = package_name
            for field in ["license", "origin", "size", "type", "version", "cpes"]:
                if field in package_info:
                    el[field] = package_info[field]
                else:
                    el[field] = None

                if field == "license":
                    if el[field]:
                        el["licenses"] = el[field].split(" ")
                    else:
                        el["licenses"] = []

            # Special formatting for os packages. Ensure that if there is a release field it is added to the version string
            if package_info.get("type", "").lower() in os_package_types:
                v = package_info.get("version", None)
                r = package_info.get("release", None)
                if (v and r) and (v.lower() != "n/a") and r.lower() != "n/a":
                    el["version"] = "{}-{}".format(v, r)
        except:
            continue
        response.append(el)
    return response


def _build_npm_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = "NPM"
            el["location"] = package
            el["version"] = content_data[package]["versions"][0]
            el["origin"] = ",".join(content_data[package]["origins"]) or "Unknown"
            el["license"] = " ".join(content_data[package]["lics"]) or "Unknown"
            el["licenses"] = content_data[package]["lics"] or ["Unknown"]
            el["cpes"] = content_data[package].get("cpes", [])
        except:
            continue
        response.append(el)
    return response


def _build_gem_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = "GEM"
            el["location"] = package
            el["version"] = content_data[package]["versions"][0]
            el["origin"] = ",".join(content_data[package]["origins"]) or "Unknown"
            el["license"] = " ".join(content_data[package]["lics"]) or "Unknown"
            el["licenses"] = content_data[package]["lics"] or ["Unknown"]
            el["cpes"] = content_data[package].get("cpes", [])
        except:
            continue
        response.append(el)
    return response


def _build_python_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = "PYTHON"
            el["location"] = content_data[package]["location"]
            el["version"] = content_data[package]["version"]
            el["origin"] = content_data[package]["origin"] or "Unknown"
            el["license"] = content_data[package]["license"] or "Unknown"
            el["licenses"] = content_data[package]["license"].split(" ") or ["Unknown"]
            el["cpes"] = content_data[package].get("cpes", [])
        except:
            continue
        response.append(el)
    return response


def _build_java_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = content_data[package]["type"].upper()
            el["location"] = content_data[package]["location"]
            el["specification-version"] = content_data[package]["specification-version"]
            el["implementation-version"] = content_data[package][
                "implementation-version"
            ]
            el["maven-version"] = content_data[package]["maven-version"]
            el["origin"] = content_data[package]["origin"] or "Unknown"
            el["cpes"] = content_data[package].get("cpes", [])
        except:
            continue
        response.append(el)
    return response


def _build_files_response(content_data):
    response = []
    elmap = {
        "linkdst": "linkdest",
        "size": "size",
        "mode": "mode",
        "sha256": "sha256",
        "type": "type",
        "uid": "uid",
        "gid": "gid",
    }
    for filename in list(content_data.keys()):
        el = {}
        try:
            el["filename"] = filename
            for elkey in list(elmap.keys()):
                try:
                    el[elmap[elkey]] = content_data[filename][elkey]
                except:
                    el[elmap[elkey]] = None

            # special formatting
            el["mode"] = format(stat.S_IMODE(el["mode"]), "05o")
            if el["sha256"] == "DIRECTORY_OR_OTHER":
                el["sha256"] = None
        except:
            continue
        response.append(el)
    return response


def _safe_base64_encode(data_provider):
    try:
        return utils.ensure_str(base64.encodebytes(utils.ensure_bytes(data_provider())))
    except Exception as err:
        logger.warn("could not base64 encode content - exception: %s", err)
    return ""


def _build_docker_history_response(content_data):
    return _safe_base64_encode(lambda: json.dumps(content_data))


def _build_dockerfile_response(content_data):
    return _safe_base64_encode(lambda: content_data)


def _build_manifest_response(content_data):
    return _safe_base64_encode(lambda: content_data)


def _build_default_response(content_data):
    response = []
    try:
        for package in list(content_data.keys()):
            el = {}
            try:
                el["package"] = content_data[package]["name"]
                el["type"] = content_data[package]["type"].upper()
                el["location"] = (
                    content_data[package].get("location", None) or "Unknown"
                )
                el["version"] = content_data[package].get("version", None) or "Unknown"
                el["origin"] = content_data[package].get("origin", None) or "Unknown"
                el["license"] = content_data[package].get("license", None) or "Unknown"
                el["licenses"] = (
                    content_data[package].get("license", "Unknown").split(" ")
                )
                el["cpes"] = content_data[package].get("cpes", [])
            except Exception as err:
                continue
            response.append(el)
        if not response:
            raise Exception("empty return list after generic element parse")
    except Exception as err:
        logger.debug(
            "couldn't parse any generic package elements, returning raw content_data - exception: %s",
            err,
        )
        response = content_data

    return response


def _build_malware_response(content_data):
    return content_data
    # response = []
    # try:
    #     logger.debug('Malware data to build: %s', content_data)
    #
    #     for result in content_data:
    #         name = result.get('name')
    #         response.extend([{'scanner': name, 'path': finding.get('path'), 'signature': finding.get('signature'), 'metadata': result.get('metadata')} for finding in result.get('findings')])
    #
    #     if not response:
    #         raise Exception("empty return list after generic element parse")
    # except Exception as err:
    #     logger.debug_exception("couldn't parse any generic package elements, returning raw content_data: %s", err)
    #     response = content_data
    #
    # return response


CONTENT_RESPONSE_BUILDER_DISPATCH = {
    "os": _build_os_response,
    "npm": _build_npm_response,
    "gem": _build_gem_response,
    "python": _build_python_response,
    "java": _build_java_response,
    "files": _build_files_response,
    "docker_history": _build_docker_history_response,
    "dockerfile": _build_dockerfile_response,
    "manifest": _build_manifest_response,
    "malware": _build_malware_response,
}
