import datetime
import io
import json
import re
import tarfile

from connexion import request
import typing

import anchore_engine.apis
import anchore_engine.common
import anchore_engine.common.images
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.metrics
from anchore_engine import utils
from anchore_engine.apis import exceptions as api_exceptions
from anchore_engine.apis.authorization import (
    get_authorizer,
    RequestingAccountValue,
    ActionBoundPermission,
)
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.common.helpers import make_response_error
from anchore_engine.db.entities.common import anchore_now
from anchore_engine.services.apiext.api import helpers
from anchore_engine.services.apiext.api.controllers.utils import (
    normalize_image_add_source,
    validate_image_add_source,
)
from anchore_engine.subsys import taskstate, logger
from anchore_engine.subsys.metrics import flask_metrics
from anchore_engine.utils import parse_dockerimage_string

authorizer = get_authorizer()


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
    id_cves_map = {}
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
                    for nvd_el in el["nvd_data"]:
                        id_cves_map[nvd_el.get("id")] = el.get("vuln")

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
    for vuln in scan_result:

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

        # dedup logic for filtering nvd cpes that are referred by vulndb
        if vuln.get("feed_name") == "vulndb":
            for nvd_item in vuln.get("nvd_data", []):
                try:
                    id_cves_map[nvd_item.get("id")] = el.get("vuln")
                except Exception as err:
                    logger.warn(
                        "failure during vulnerability dedup check (vulndbs over nvd) with {}".format(
                            err
                        )
                    )

        nonosvulns.append(el)

    # perform a de-dup pass
    final_nonosvulns = []
    for v in nonosvulns:
        include = True
        try:
            if v.get("vuln") in id_cves_map:
                include = False
        except Exception as err:
            logger.warn("failure during vulnerability dedup check: {}".format(str(err)))

        if include:
            final_nonosvulns.append(v)

    if vulnerability_type == "os":
        ret = osvulns
    elif vulnerability_type == "non-os":
        ret = final_nonosvulns
    elif vulnerability_type == "all":
        ret = osvulns + final_nonosvulns
    else:
        ret = vulnerability_data

    return ret


def make_response_policyeval(eval_record, params, catalog_client):
    ret = {}
    try:
        tag = eval_record["tag"]

        ret[tag] = {}

        if eval_record["evalId"] and eval_record["policyId"]:
            ret[tag]["detail"] = {}
            if params and "detail" in params and params["detail"]:
                eval_data = eval_record["result"]
                ret[tag]["detail"]["result"] = eval_data
                bundle_data = catalog_client.get_document(
                    "policy_bundles", eval_record["policyId"]
                )
                ret[tag]["detail"]["policy"] = bundle_data

            ret[tag]["policyId"] = eval_record["policyId"]

            if eval_record["final_action"].upper() in ["GO", "WARN"]:
                ret[tag]["status"] = "pass"
            else:
                ret[tag]["status"] = "fail"

            ret[tag]["last_evaluation"] = (
                datetime.datetime.utcfromtimestamp(
                    eval_record["created_at"]
                ).isoformat()
                + "Z"
            )

        else:
            ret[tag]["policyId"] = "N/A"
            ret[tag]["final_action"] = "fail"
            ret[tag]["last_evaluation"] = "N/A"
            ret[tag]["detail"] = {}

    except Exception as err:
        raise Exception("failed to format policy eval response: " + str(err))

    return ret


def make_response_image(image_record, include_detail=True):
    ret = image_record

    image_content = {"metadata": {}}
    for key in [
        "arch",
        "distro",
        "distro_version",
        "dockerfile_mode",
        "image_size",
        "layer_count",
    ]:
        val = image_record.pop(key, None)
        image_content["metadata"][key] = val
    image_record["image_content"] = image_content

    if image_record["annotations"]:
        try:
            annotation_data = json.loads(image_record["annotations"])
            image_record["annotations"] = annotation_data
        except:
            pass

    # try to assemble full strings
    if image_record and "image_detail" in image_record:
        for image_detail in image_record["image_detail"]:
            try:
                image_detail["fulldigest"] = (
                    image_detail["registry"]
                    + "/"
                    + image_detail["repo"]
                    + "@"
                    + image_detail["digest"]
                )
                image_detail["fulltag"] = (
                    image_detail["registry"]
                    + "/"
                    + image_detail["repo"]
                    + ":"
                    + image_detail["tag"]
                )
            except:
                image_detail["fulldigest"] = None
                image_detail["fulltag"] = None

            for removekey in ["record_state_val", "record_state_key"]:
                image_detail.pop(removekey, None)

            for datekey in ["last_updated", "created_at", "tag_detected_at"]:
                try:
                    image_detail[datekey] = (
                        datetime.datetime.utcfromtimestamp(
                            image_detail[datekey]
                        ).isoformat()
                        + "Z"
                    )
                except:
                    pass

    if not include_detail:
        image_record["image_detail"] = []

    for datekey in ["last_updated", "created_at", "analyzed_at"]:
        try:
            image_record[datekey] = (
                datetime.datetime.utcfromtimestamp(image_record[datekey]).isoformat()
                + "Z"
            )
        except:
            pass

    for removekey in ["record_state_val", "record_state_key"]:
        image_record.pop(removekey, None)

    return ret


def lookup_imageDigest_from_imageId(request_inputs, imageId):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    userId = request_inputs["userId"]
    ret = None

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        image_records = client.get_image_by_id(imageId=imageId)
        if image_records:
            image_record = image_records[0]

        imageDigest = image_record["imageDigest"]
        ret = imageDigest

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        raise err

    return ret


def vulnerability_query(
    account,
    digest,
    vulnerability_type,
    force_refresh=False,
    vendor_only=True,
    doformat=False,
):
    # user_auth = request_inputs['auth']
    # method = request_inputs['method']
    # bodycontent = request_inputs['bodycontent']
    # params = request_inputs['params']

    return_object = {}
    httpcode = 500
    # userId = request_inputs['userId']

    localconfig = anchore_engine.configuration.localconfig.get_config()
    system_user_auth = localconfig["system_user_auth"]
    verify = localconfig["internal_ssl_verify"]

    # force_refresh = params.get('force_refresh', False)
    # vendor_only = params.get('vendor_only', True)

    try:
        if (
            vulnerability_type
            not in anchore_engine.common.image_vulnerability_types + ["all"]
        ):
            httpcode = 404
            raise Exception(
                "content type (" + str(vulnerability_type) + ") not available"
            )

        # tag = params.pop('tag', None)
        # imageDigest = params.pop('imageDigest', None)
        # digest = params.pop('digest', None)
        catalog_client = internal_client_for(CatalogClient, account)

        image_report = catalog_client.get_image(digest)

        if image_report and image_report["analysis_status"] != taskstate.complete_state(
            "analyze"
        ):
            httpcode = 404
            raise Exception(
                "image is not analyzed - analysis_status: "
                + image_report["analysis_status"]
            )

        imageDigest = image_report["imageDigest"]
        try:
            image_detail = image_report["image_detail"][0]
            imageId = image_detail["imageId"]
            client = internal_client_for(PolicyEngineClient, account)
            resp = client.get_image_vulnerabilities(
                user_id=account,
                image_id=imageId,
                force_refresh=force_refresh,
                vendor_only=vendor_only,
            )
            if doformat:
                ret = make_response_vulnerability(vulnerability_type, resp)
                return_object[imageDigest] = ret
            else:
                return_object[imageDigest] = resp

            httpcode = 200
        except Exception as err:
            httpcode = 500
            raise Exception("could not fetch vulnerabilities - exception: " + str(err))

        httpcode = 200
    except Exception as err:
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


def get_content(request_inputs, content_type):
    params = request_inputs["params"]
    return_object = {}
    http_code = 500
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        all_content_types = localconfig.get(
            "image_content_types", []
        ) + localconfig.get("image_metadata_types", [])
        if content_type not in all_content_types:
            raise Exception("content type (" + str(content_type) + ") not available")

        image_digest = params.pop("imageDigest", None)
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        return_object[image_digest] = client.get_image_content(
            image_digest, content_type
        )
        http_code = 200

    except Exception as err:
        logger.exception("Failed content lookup")
        return_object = make_response_error(err, in_httpcode=http_code)
        http_code = return_object["httpcode"]

    return return_object, http_code


# repositories
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def add_repository(repository=None, autosubscribe=False, dryrun=False):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request,
            default_params={
                "autosubscribe": autosubscribe,
                "repository": repository,
                "dryrun": dryrun,
            },
        )
        return_object, httpcode = repositories(request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def repositories(request_inputs):
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = {}
    httpcode = 500

    input_repo = None
    if params and "repository" in params:
        input_repo = params["repository"]

    autosubscribe = False
    if params and "autosubscribe" in params:
        autosubscribe = params["autosubscribe"]

    lookuptag = None
    if params and "lookuptag" in params:
        lookuptag = params["lookuptag"]

    dryrun = False
    if params and "dryrun" in params:
        dryrun = params["dryrun"]

    try:
        if method == "POST":
            logger.debug("handling POST: ")
            try:
                client = internal_client_for(CatalogClient, request_inputs["userId"])
                return_object = []
                repo_records = client.add_repo(
                    regrepo=input_repo,
                    autosubscribe=autosubscribe,
                    lookuptag=lookuptag,
                    dryrun=dryrun,
                )
                for repo_record in repo_records:
                    return_object.append(repo_record)
                httpcode = 200
            except Exception as err:
                raise err

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


# images CRUD
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_imagetags(image_status=None):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})

        user_auth = request_inputs["auth"]
        method = request_inputs["method"]
        bodycontent = request_inputs["bodycontent"]
        params = request_inputs["params"]

        return_object = {}
        httpcode = 500

        client = internal_client_for(CatalogClient, request_inputs["userId"])

        return_object = client.get_imagetags(image_status)
        httpcode = 200

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def import_image_archive(archive_file):

    httpcode = 500
    try:
        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
        request_account = request_inputs["userId"]

        # TODO perform the archive format validation here, for now just a READ
        try:
            archive_buffer = archive_file.read()
        except Exception as err:
            httpcode = 409
            raise Exception(
                "invalid archive format (must be an image archive tar.gz generated by anchore) - exception: {}".format(
                    err
                )
            )

        # get some information out of the archive for input validation
        archive_account = None
        archive_digest = None
        with tarfile.open(
            fileobj=io.BytesIO(archive_buffer), format=tarfile.PAX_FORMAT
        ) as TFH:
            try:
                with TFH.extractfile("archive_manifest") as AMFH:
                    archive_manifest = json.loads(utils.ensure_str(AMFH.read()))
                    archive_account = archive_manifest["account"]
                    archive_digest = archive_manifest["image_digest"]
            except Exception as err:
                httpcode = 409
                raise Exception(
                    "cannot extract/parse archive_manifest from archive file - exception: {}".format(
                        err
                    )
                )

        # removed the bloe validation check as the checks are now performed in the archiving subsystem, based on the authenticated account
        # perform verification that the account set in the archive matches the calling account namespace
        # if (not request_account or not archive_account) or (request_account != archive_account):
        #     httpcode = 409
        #     raise Exception ("account in import archive ({}) does not match API request account ({})".format(archive_account, request_account))

        # make the import call to the catalog
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        catalog_import_return_object = client.import_archive(
            archive_digest, io.BytesIO(archive_buffer)
        )

        # finally grab the image record from the catalog, prep the respose and return
        image_record = client.get_image(archive_digest)
        return_object = [make_response_image(image_record, include_detail=True)]
        httpcode = 200

    except api_exceptions.AnchoreApiError as err:
        return_object = make_response_error(err, in_httpcode=err.__response_code__)
        httpcode = err.__response_code__
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_images(
    history=None,
    fulltag=None,
    detail=False,
    image_status="active",
    analysis_status=None,
):

    httpcode = 500
    try:
        digest = None
        return_object = do_list_images(
            account=ApiRequestContextProxy.namespace(),
            filter_digest=digest,
            filter_tag=fulltag,
            history=history,
            image_status=image_status,
            analysis_status=analysis_status,
        )

        httpcode = 200
    except api_exceptions.AnchoreApiError as err:
        return_object = make_response_error(err, in_httpcode=err.__response_code__)
        httpcode = err.__response_code__
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_images_async(imageDigests, force=False):
    return_object = {}
    httpcode = 500

    try:
        logger.debug("Handling DELETE on imageDigests: %s" % imageDigests)

        client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())

        rc = client.delete_images_async(imageDigests, force=force)

        if rc:
            return_object = rc
            httpcode = 200
        else:
            httpcode = 500
            raise Exception(
                "Operation failed due to an error/connectivity issue with catalog"
            )

    except Exception as err:
        logger.exception("Error in asynchronous deletion of images")
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


def validate_pullstring_is_tag(pullstring):
    try:
        parsed = parse_dockerimage_string(pullstring)
        return parsed.get("tag") is not None
    except Exception as e:
        logger.debug_exception(
            "Error parsing pullstring {}. Err = {}".format(pullstring, e)
        )
        raise ValueError("Error parsing pullstring {}".format(pullstring))


def validate_pullstring_is_digest(pullstring):
    try:
        parsed = parse_dockerimage_string(pullstring)
        return parsed.get("digest") is not None
    except Exception as e:
        logger.debug_exception(
            "Error parsing pullstring {}. Err = {}".format(pullstring, e)
        )
        raise ValueError("Error parsing pullstring {}".format(pullstring))


digest_regex = re.compile("sha256:[a-fA-F0-9]{64}")


def validate_archive_digest(digest: str):
    return digest is not None and digest_regex.match(digest.strip())


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def add_image(image, force=False, autosubscribe=False):

    # TODO: use for validation pass
    spec = ApiRequestContextProxy.get_service().api_spec

    httpcode = 500
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request, default_params={"force": force}
        )

        try:
            normalized = normalize_image_add_source(analysis_request_dict=image)
            validate_image_add_source(normalized, spec)
        except api_exceptions.AnchoreApiError:
            raise
        except Exception as e:
            raise api_exceptions.BadRequest(
                "Could not validate request due to error",
                detail={"validation_error": str(e)},
            )

        enable_subscriptions = ["analysis_update"]

        if autosubscribe:
            enable_subscriptions.append("tag_update")

        source = normalized["source"]

        return_object = analyze_image(
            ApiRequestContextProxy.namespace(),
            source,
            force,
            enable_subscriptions,
            image.get("annotations"),
        )
        httpcode = 200

    except api_exceptions.AnchoreApiError as err:
        raise err
        # httpcode = err.__response_code__
        # return_object = make_response_error(err.message, details=err.detail, in_httpcode=httpcode)
    except ValueError as err:
        httpcode = 400
        return_object = make_response_error(str(err), in_httpcode=400)
    except Exception as err:
        logger.debug("operation exception: {}".format(str(err)))
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_image(imageDigest, force=False):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request, default_params={"force": force}
        )
        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image(imageDigest, history=None):

    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request, default_params={"history": False}
        )
        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_by_imageId(imageId, history=None):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request, default_params={"history": False}
        )
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_image_by_imageId(imageId, force=False):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request, default_params={"force": force}
        )
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_policy_check(
    imageDigest, policyId=None, tag=None, detail=True, history=False
):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request,
            default_params={
                "tag": None,
                "detail": True,
                "history": False,
                "policyId": None,
            },
        )
        return_object, httpcode = images_imageDigest_check(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_policy_check_by_imageId(
    imageId, policyId=None, tag=None, detail=None, history=None
):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        request_inputs = anchore_engine.apis.do_request_prep(
            request,
            default_params={
                "tag": None,
                "detail": True,
                "history": False,
                "policyId": None,
            },
        )
        return_object, httpcode = images_imageDigest_check(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_image_metadata(imageDigest):
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        return_object = localconfig.get("image_metadata_types", [])
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_metadata_by_type(imageDigest, mtype):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request, default_params={"imageDigest": imageDigest}
        )

        return_object, httpcode = get_content(request_inputs, mtype)
        if httpcode == 200:
            return_object = {
                "imageDigest": imageDigest,
                "metadata_type": mtype,
                "metadata": list(return_object.values())[0],
            }

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_image_content(imageDigest):
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        return_object = localconfig.get("image_content_types", [])
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_image_content_by_imageid(imageId):
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        return_object = localconfig.get("image_content_types", [])
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_content_by_type(imageDigest, ctype):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            request, default_params={"imageDigest": imageDigest}
        )

        return_object, httpcode = get_content(request_inputs, ctype)
        if httpcode == 200:
            return_object = {
                "imageDigest": imageDigest,
                "content_type": ctype,
                "content": list(return_object.values())[0],
            }

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_content_by_type_files(imageDigest):
    return get_image_content_by_type(imageDigest, "files")


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_content_by_type_javapackage(imageDigest):
    return get_image_content_by_type(imageDigest, "java")


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_content_by_type_malware(imageDigest):
    return get_image_content_by_type(imageDigest, "malware")


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_content_by_type_imageId(imageId, ctype):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        return_object, httpcode = get_image_content_by_type(imageDigest, ctype)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_content_by_type_imageId_files(imageId):
    return get_image_content_by_type_imageId(imageId, "files")


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_content_by_type_imageId_javapackage(imageId):
    return get_image_content_by_type_imageId(imageId, "java")


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_vulnerability_types(imageDigest):
    try:
        return_object = anchore_engine.common.image_vulnerability_types + ["all"]
        httpcode = 200

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_vulnerability_types_by_imageId(imageId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        return_object, httpcode = get_image_vulnerability_types(imageDigest)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_vulnerabilities_by_type(
    imageDigest, vtype, force_refresh=False, vendor_only=True
):
    try:
        vulnerability_type = vtype

        return_object, httpcode = vulnerability_query(
            ApiRequestContextProxy.namespace(),
            imageDigest,
            vulnerability_type,
            force_refresh,
            vendor_only,
            doformat=True,
        )
        if httpcode == 200:
            return_object = {
                "imageDigest": imageDigest,
                "vulnerability_type": vulnerability_type,
                "vulnerabilities": list(return_object.values())[0],
            }

    except Exception as err:
        logger.exception("Exception getting vulns")
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_image_vulnerabilities_by_type_imageId(imageId, vtype):
    try:
        vulnerability_type = vtype
        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        return_object, httpcode = get_image_vulnerabilities_by_type(
            imageDigest, vulnerability_type
        )

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @flask_metrics.do_not_track()
# @authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
# def import_image(analysis_report):
#    try:
#        request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
#        return_object, httpcode = do_import_image(request_inputs, analysis_report)
#
#    except Exception as err:
#        httpcode = 500
#        return_object = str(err)
#
#    return return_object, httpcode


# def do_import_image(request_inputs, importRequest):
#    user_auth = request_inputs['auth']
#    method = request_inputs['method']
#    bodycontent = request_inputs['bodycontent']
#    params = request_inputs['params']
#
#    return_object = {}
#    httpcode = 500
#
#    userId, pw = user_auth
#
#    try:
#        client = internal_client_for(CatalogClient, request_inputs['userId'])
#        return_object = []
#        image_records = client.import_image(json.loads(bodycontent))
#        for image_record in image_records:
#            return_object.append(make_response_image(image_record))
#        httpcode = 200
#
#    except Exception as err:
#        logger.debug("operation exception: " + str(err))
#        return_object = make_response_error(err, in_httpcode=httpcode)
#        httpcode = return_object['httpcode']
#
#    return(return_object, httpcode)


def do_list_images(
    account,
    filter_tag=None,
    filter_digest=None,
    history=False,
    image_status=None,
    analysis_status=None,
):
    client = internal_client_for(CatalogClient, account)

    try:
        # Query param fulltag has precedence for search
        image_records = client.list_images(
            tag=filter_tag,
            digest=filter_digest,
            history=history,
            image_status=image_status,
            analysis_status=analysis_status,
        )

        return [
            make_response_image(image_record, include_detail=True)
            for image_record in image_records
        ]

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        raise err


def analyze_image(
    account, source, force=False, enable_subscriptions=None, annotations=None
):
    """
    Analyze an image from a source where a source can be one of:

    'digest': {
      'pullstring': str, (digest or tag, e.g docker.io/alpine@sha256:abc),
      'tag': str, the tag itself to associate (e.g. docker.io/alpine:latest),
      'creation_timestamp_override: str, rfc3339 format. necessary only if not doing a force re-analysis of existing image,
      'dockerfile': str, the base64 encoded dockerfile content to associate with this tag at analysis time. optional
    }

    'tag': {
      'pullstring': str, the full tag-style pull string for docker (e.g. docker.io/nginx:latest),
      'dockerfile': str optional base-64 encoded dockerfile content to associate with this tag at analysis time. optional
    }

    'archive': {
      'digest': str, the digest to restore from the analysis archive
    }

    :param account: str account id
    :param source: dict source object with keys: 'tag', 'digest', and 'archive', with associated config for pulling source from each. See the api spec for schema details
    :param force: bool, if true re-analyze existing image
    :param enable_subscriptions: the list of subscriptions to enable at add time. Optional
    :param annotations: Dict of k/v annotations. Optional.
    :return: resulting image record
    """

    if not source:
        raise Exception("Must have source to fetch image or analysis from")

    client = internal_client_for(CatalogClient, account)
    tag = None
    digest = None
    ts = None
    is_from_archive = False
    dockerfile = None
    image_check = None
    image_record = None
    try:
        logger.debug(
            "handling POST: source={}, force={}, enable_subscriptions={}, annotations={}".format(
                source, force, enable_subscriptions, annotations
            )
        )

        # if not, add it and set it up to be analyzed
        if source.get("import"):
            client = internal_client_for(
                CatalogClient, userId=ApiRequestContextProxy.namespace()
            )
            image_record = client.import_image(
                source.get("import"), annotations=annotations, force=force
            )
            # The import path will fail with an expected error if the image is already analyzed and not in a failed state
            # and the user did not specify a force re-load of the image. The regular image analysis path will allow such
            # a case for idempotent operation and to permit updates to things like annotations.
        else:
            if source.get("archive"):
                img_source = source.get("archive")
                # Do archive-based add
                digest = img_source["digest"]
                is_from_archive = True
            elif source.get("tag"):
                # Do tag-based add
                img_source = source.get("tag")
                tag = img_source["pullstring"]
                dockerfile = img_source.get("dockerfile")

            elif source.get("digest"):
                # Do digest-based add
                img_source = source.get("digest")

                tag = img_source["tag"]
                digest_info = anchore_engine.utils.parse_dockerimage_string(
                    img_source["pullstring"]
                )
                digest = digest_info["digest"]
                dockerfile = img_source.get("dockerfile")

                ts = img_source.get("creation_timestamp_override")
                if ts:
                    try:
                        ts = utils.rfc3339str_to_epoch(ts)
                    except Exception as err:
                        raise api_exceptions.InvalidDateFormat(
                            "source.creation_timestamp_override", ts
                        )

                if force:
                    # Grab the trailing digest sha section and ensure it exists
                    try:
                        image_check = client.get_image(digest)
                        if not image_check:
                            raise Exception(
                                "No image found for digest {}".format(digest)
                            )
                        if not ts:
                            # Timestamp required for analysis by digest & tag (if none specified,
                            # default to previous image's timestamp)
                            ts = image_check.get("created_at", anchore_now())
                    except Exception as err:
                        raise ValueError(
                            "image digest must already exist to force re-analyze using tag+digest"
                        )
                elif not ts:
                    # If a new analysis of an image by digest + tag, we need a timestamp to insert into the tag history
                    # properly. Therefore, if no timestamp is provided, we use the current time
                    ts = anchore_now()
            else:
                raise ValueError(
                    "The source property must have at least one of tag, digest, or archive set to non-null"
                )

            image_record = client.add_image(
                tag=tag,
                digest=digest,
                dockerfile=dockerfile,
                annotations=annotations,
                created_at=ts,
                from_archive=is_from_archive,
                allow_dockerfile_update=force,
            )

        # finally, do any state updates and return
        if image_record:
            imageDigest = image_record["imageDigest"]

            logger.debug("added image: " + str(imageDigest))

            initialize_subscriptions(client, image_record, enable_subscriptions)

            imageDigest = image_record["imageDigest"]

            # set the state of the image appropriately
            currstate = image_record["analysis_status"]
            if not currstate:
                newstate = taskstate.init_state("analyze", None)
            elif force or currstate == taskstate.fault_state("analyze"):
                newstate = taskstate.reset_state("analyze")
            elif image_record["image_status"] != taskstate.base_state("image_status"):
                newstate = taskstate.reset_state("analyze")
            else:
                newstate = currstate

            if (currstate != newstate) or (force):
                logger.debug(
                    "state change detected: " + str(currstate) + " : " + str(newstate)
                )
                image_record.update(
                    {
                        "image_status": taskstate.reset_state("image_status"),
                        "analysis_status": newstate,
                    }
                )
                updated_image_record = client.update_image(imageDigest, image_record)
                if updated_image_record:
                    image_record = updated_image_record[0]
            else:
                logger.debug(
                    "no state change detected: "
                    + str(currstate)
                    + " : "
                    + str(newstate)
                )

            return [make_response_image(image_record, include_detail=True)]
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        raise err


def initialize_subscriptions(
    catalog_client: CatalogClient, image_record, enable_subscriptions=None
):
    """
    Setup the subscriptions for an image record

    :param image_record:
    :param enable_subscriptions:
    :return:
    """
    for image_detail in image_record["image_detail"]:
        fulltag = (
            image_detail["registry"]
            + "/"
            + image_detail["repo"]
            + ":"
            + image_detail["tag"]
        )

        foundtypes = []
        try:
            subscription_records = catalog_client.get_subscription(
                subscription_key=fulltag
            )
        except Exception as err:
            subscription_records = []

        for subscription_record in subscription_records:
            if subscription_record["subscription_key"] == fulltag:
                foundtypes.append(subscription_record["subscription_type"])

        sub_types = anchore_engine.common.subscription_types
        for sub_type in sub_types:
            if sub_type in ["repo_update"]:
                continue
            if sub_type not in foundtypes:
                try:
                    default_active = False
                    if enable_subscriptions and sub_type in enable_subscriptions:
                        logger.debug("auto-subscribing image: " + str(sub_type))
                        default_active = True
                    catalog_client.add_subscription(
                        {
                            "active": default_active,
                            "subscription_type": sub_type,
                            "subscription_key": fulltag,
                        }
                    )
                except:
                    try:
                        catalog_client.update_subscription(
                            {
                                "subscription_type": sub_type,
                                "subscription_key": fulltag,
                            }
                        )
                    except:
                        pass
            else:
                if enable_subscriptions and sub_type in enable_subscriptions:
                    catalog_client.update_subscription(
                        {
                            "active": True,
                            "subscription_type": sub_type,
                            "subscription_key": fulltag,
                        }
                    )


def next_analysis_state(image_record, force=False):
    """
    Return the next state for the image record to transition to

    :param currstate:
    :param force:
    :return:
    """
    currstate = image_record["analysis_status"]

    if not currstate:
        newstate = taskstate.init_state("analyze", None)
    elif force or currstate == taskstate.fault_state("analyze"):
        newstate = taskstate.reset_state("analyze")
    elif image_record["image_status"] != taskstate.base_state("image_status"):
        newstate = taskstate.reset_state("analyze")
    else:
        newstate = currstate

    return newstate


def update_image_status(
    catalog_client: CatalogClient, image_record, to_status: str, force=False
) -> dict:
    """
    Update the image status to the requested new status, idempotently

    If not a valid transtion, an ConflictingRequest exception is raised

    :param image_record:
    :param to_status:
    :param force: bool to force the transition if the state machine doesn't already support it (e.g. re-analyze requested by user)
    :return:
    """

    analysis_status = image_record["analysis_status"]
    next_status = next_analysis_state(image_record, force=force)

    # Code carried over from previous impl. Not sure if this has any effect if force=True but the states are the same
    # The only thing may be annotation updates etc that force the body to update event though the status is the same
    # That needs to be fixed to use another route or PUT/PATCH explicitly rather than another POST
    if next_status != analysis_status or force:
        logger.debug(
            "state change detected: " + str(analysis_status) + " : " + str(next_status)
        )
        image_record.update(
            {
                "image_status": taskstate.reset_state("image_status"),
                "analysis_status": next_status,
            }
        )

        # Yes, this returns an array, need to fix that but is always an array of size 1
        updated_image_records = catalog_client.update_image(
            image_record["imageDigest"], image_record
        )
        if updated_image_records:
            image_record = updated_image_records[0]
        else:
            raise Exception("no response found from image update API call to catalog")
    else:
        logger.debug(
            "no state change detected: "
            + str(analysis_status)
            + " : "
            + str(next_status)
        )

    return image_record


def images_imageDigest(request_inputs, imageDigest):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs.get("params", {})

    return_object = {}
    httpcode = 500

    username, pw = user_auth
    userId = request_inputs["userId"]

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])

        if method == "GET":
            logger.debug("handling GET on imageDigest: " + str(imageDigest))

            image_record = client.get_image(imageDigest)
            if image_record:
                if "detail" in params and not params.get("detail"):
                    detail = False
                else:
                    detail = True
                return_object = [
                    make_response_image(image_record, include_detail=detail)
                ]
                httpcode = 200
            else:
                httpcode = 404
                raise Exception("cannot locate specified image")

        elif method == "DELETE":
            logger.debug("handling DELETE on imageDigest: " + str(imageDigest))

            rc = False
            try:
                rc = client.delete_image(imageDigest, force=params["force"])
            except Exception as err:
                raise err

            if rc:
                return_object = rc
                httpcode = 200
            else:
                httpcode = 500
                raise Exception("failed to delete")

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


def images_check_impl(request_inputs, image_records):
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500
    userId = request_inputs["userId"]

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])

        if "policyId" in params and params["policyId"]:
            bundle_records = client.get_policy(policyId=params["policyId"])
            policyId = params["policyId"]
        else:
            bundle_records = client.get_active_policy()
            policyId = None
        if not bundle_records:
            httpcode = 404
            raise Exception("user has no active policy to evaluate: " + str(userId))

        # this is to check that we got at least one evaluation in the response, otherwise routine should throw a 404
        atleastone = False

        if image_records:
            for image_record in image_records:
                imageDigest = image_record["imageDigest"]
                return_object_el = {}
                return_object_el[imageDigest] = {}

                tags = []
                if params and "tag" in params and params["tag"]:
                    image_info = anchore_engine.common.images.get_image_info(
                        userId,
                        "docker",
                        params["tag"],
                        registry_lookup=False,
                        registry_creds=[],
                    )
                    if "fulltag" in image_info and image_info["fulltag"]:
                        params["tag"] = image_info["fulltag"]
                    tags.append(params["tag"])

                else:
                    for image_detail in image_record["image_detail"]:
                        fulltag = (
                            image_detail["registry"]
                            + "/"
                            + image_detail["repo"]
                            + ":"
                            + image_detail["tag"]
                        )
                        tags.append(fulltag)

                for tag in tags:
                    if tag not in return_object_el[imageDigest]:
                        return_object_el[imageDigest][tag] = []

                    try:
                        if params and params.get("history", False):
                            results = client.get_evals(
                                imageDigest=imageDigest, tag=tag, policyId=policyId
                            )
                        elif params and params.get("interactive", False):
                            results = [
                                client.get_eval_interactive(
                                    imageDigest=imageDigest, tag=tag, policyId=policyId
                                )
                            ]
                        else:
                            results = [
                                client.get_eval_latest(
                                    imageDigest=imageDigest, tag=tag, policyId=policyId
                                )
                            ]

                    except Exception as err:
                        results = []

                    httpcode = 200
                    for result in results:
                        fresult = make_response_policyeval(result, params, client)
                        return_object_el[imageDigest][tag].append(fresult[tag])
                        atleastone = True

                if return_object_el:
                    return_object.append(return_object_el)
        else:
            httpcode = 404
            raise Exception("could not find image record(s) input imageDigest(s)")

        if not atleastone:
            httpcode = 404
            raise Exception("could not find any evaluations for input images")

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


def images_imageDigest_check(request_inputs, imageDigest):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = {}
    httpcode = 500
    username, pw = user_auth
    userId = request_inputs["userId"]
    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        image_record = client.get_image(imageDigest)

        if image_record and image_record["analysis_status"] != taskstate.complete_state(
            "analyze"
        ):
            httpcode = 404
            raise Exception(
                "image is not analyzed - analysis_status: "
                + str(image_record["analysis_status"])
            )

        # Use a list of records here for backwards compat of api
        return_object, httpcode = images_check_impl(request_inputs, [image_record])
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    return return_object, httpcode


def _get_image_ok(account, imageDigest):
    """
    Get the image id if the image exists and is analyzed, else raise error

    :param account:
    :param imageDigest:
    :return:
    """
    catalog_client = internal_client_for(CatalogClient, account)
    image_report = catalog_client.get_image(imageDigest)

    if image_report and image_report["analysis_status"] != taskstate.complete_state(
        "analyze"
    ):
        raise api_exceptions.ResourceNotFound(
            "artifacts",
            detail={
                "details": "image is not analyzed - analysis_status: "
                + image_report["analysis_status"]
            },
        )
    elif not image_report:
        raise api_exceptions.ResourceNotFound(imageDigest, detail={})

    image_detail = image_report["image_detail"][0]
    imageId = image_detail["imageId"]

    return imageId


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_retrieved_files(imageDigest):
    """
    GET /images/{imageDigest}/artifacts/retrieved_files
    :param imageDigest:
    :param artifactType:
    :return:
    """

    account = ApiRequestContextProxy.namespace()
    try:
        imageId = _get_image_ok(account, imageDigest)

        client = internal_client_for(PolicyEngineClient, account)
        resp = client.list_image_analysis_artifacts(
            user_id=account, image_id=imageId, artifact_type="retrieved_files"
        )
        return resp, 200
    except api_exceptions.AnchoreApiError:
        raise
    except Exception as err:
        raise api_exceptions.InternalError(str(err), detail={})


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_file_content_search_results(imageDigest):
    """
    GET /images/{imageDigest}/artifacts/file_content_search
    :param imageDigest:
    :param artifactType:
    :return:
    """

    account = ApiRequestContextProxy.namespace()
    try:
        imageId = _get_image_ok(account, imageDigest)

        client = internal_client_for(PolicyEngineClient, account)
        resp = client.list_image_analysis_artifacts(
            user_id=account, image_id=imageId, artifact_type="file_content_search"
        )
        return resp, 200
    except api_exceptions.AnchoreApiError:
        raise
    except Exception as err:
        raise api_exceptions.InternalError(str(err), detail={})


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_secret_search_results(imageDigest):
    """
    GET /images/{imageDigest}/artifacts/secret_search
    :param imageDigest:
    :param artifactType:
    :return:
    """

    account = ApiRequestContextProxy.namespace()
    try:
        imageId = _get_image_ok(account, imageDigest)

        client = internal_client_for(PolicyEngineClient, account)
        resp = client.list_image_analysis_artifacts(
            user_id=account, image_id=imageId, artifact_type="secret_search"
        )
        return resp, 200
    except api_exceptions.AnchoreApiError:
        raise
    except Exception as err:
        raise api_exceptions.InternalError(str(err), detail={})
