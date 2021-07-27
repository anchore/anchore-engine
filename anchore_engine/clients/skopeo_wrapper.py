import gzip
import hashlib
import json
import os
import re
import tempfile
from collections import OrderedDict
from urllib.request import urlretrieve

import anchore_engine.configuration.localconfig
from anchore_engine.common.errors import AnchoreError
from anchore_engine.subsys import logger
from anchore_engine.utils import (
    AnchoreException,
    ensure_str,
    run_command,
    run_command_list,
)


def manifest_to_digest_shellout(rawmanifest):
    ret = None
    tmpmanifest = None
    try:
        fd, tmpmanifest = tempfile.mkstemp()
        os.write(fd, rawmanifest.encode("utf-8"))
        os.close(fd)

        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get("skopeo_global_timeout", 0)
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        cmd = "skopeo {} manifest-digest {}".format(global_timeout_str, tmpmanifest)
        rc, sout, serr = run_command(cmd)
        if rc == 0 and re.match("^sha256:.*", str(sout, "utf-8")):
            ret = sout.strip()
        else:
            logger.warn(
                "failed to calculate digest from schema v1 manifest: cmd={} rc={} sout={} serr={}".format(
                    cmd, rc, sout, serr
                )
            )
            raise SkopeoError(
                cmd=cmd,
                rc=rc,
                err=serr,
                out=sout,
                msg="Failed to calculate digest from schema v1 manifest",
            )
    except Exception as err:
        raise err
    finally:
        if tmpmanifest:
            os.remove(tmpmanifest)

    return ret


def manifest_to_digest(rawmanifest):
    ret = None
    d = json.loads(rawmanifest, object_pairs_hook=OrderedDict)
    if d["schemaVersion"] != 1:
        ret = "sha256:" + str(hashlib.sha256(rawmanifest.encode("utf-8")).hexdigest())
    else:
        ret = manifest_to_digest_shellout(rawmanifest)

    ret = ensure_str(ret)
    return ret


def copy_image_from_docker_archive(source_archive, dest_dir, remove_signatures=True):
    if remove_signatures:
        remove_signatures_string = "--remove-signatures"
    else:
        remove_signatures_string = ""

    cmdstr = "skopeo copy {} docker-archive:{} oci:{}:image".format(
        remove_signatures_string, source_archive, dest_dir
    )
    cmd = cmdstr.split()
    try:
        rc, sout, serr = run_command_list(cmd)
        if rc != 0:
            raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
        else:
            logger.debug(
                "command succeeded: cmd="
                + str(cmdstr)
                + " stdout="
                + str(sout).strip()
                + " stderr="
                + str(serr).strip()
            )

    except Exception as err:
        logger.error("command failed with exception - " + str(err))
        raise err


def download_image(
    fulltag,
    copydir,
    user=None,
    pw=None,
    verify=True,
    manifest=None,
    parent_manifest=None,
    use_cache_dir=None,
    remove_signatures=True,
):
    try:
        proc_env = os.environ.copy()
        if user and pw:
            proc_env["SKOPUSER"] = user
            proc_env["SKOPPASS"] = pw
            credstr = '--src-creds "${SKOPUSER}":"${SKOPPASS}"'
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--src-tls-verify=true"
        else:
            tlsverifystr = "--src-tls-verify=false"

        if use_cache_dir and os.path.exists(use_cache_dir):
            cachestr = "--dest-shared-blob-dir " + use_cache_dir
        else:
            cachestr = ""

        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get("skopeo_global_timeout", 0)
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        os_overrides = [""]
        blobs_to_fetch = []

        if manifest:
            manifest_data = json.loads(manifest)

            for layer in manifest_data.get("layers", []):
                if "foreign.diff" in layer.get("mediaType", ""):
                    layer_digest_raw = layer.get("digest", "")
                    layer_digest = get_digest_value(layer_digest_raw)
                    layer_urls = layer.get("urls", [])

                    blobs_to_fetch.append({"digest": layer_digest, "urls": layer_urls})

            if parent_manifest:
                parent_manifest_data = json.loads(parent_manifest)
            else:
                parent_manifest_data = {}

            if parent_manifest_data:
                for mlist in parent_manifest_data.get("manifests", []):
                    imageos = mlist.get("platform", {}).get("os", "")
                    if imageos not in ["", "linux"]:
                        # add a windows os override to the list of override attempts, to complete the options that are supported by skopeo
                        os_overrides.insert(0, "windows")
                        break

        if remove_signatures:
            remove_signatures_string = "--remove-signatures"
        else:
            remove_signatures_string = ""

        for os_override in os_overrides:
            success = False
            if os_override not in ["", "linux"]:
                os_override_str = "--override-os {}".format(os_override)
            else:
                os_override_str = ""

            if manifest:
                with open(os.path.join(copydir, "manifest.json"), "w") as OFH:
                    OFH.write(manifest)

            if parent_manifest:
                with open(os.path.join(copydir, "parent_manifest.json"), "w") as OFH:
                    OFH.write(parent_manifest)

            cmd = [
                "/bin/sh",
                "-c",
                "skopeo {} {} copy {} {} {} {} docker://{} oci:{}:image".format(
                    os_override_str,
                    global_timeout_str,
                    remove_signatures_string,
                    tlsverifystr,
                    credstr,
                    cachestr,
                    fulltag,
                    copydir,
                ),
            ]

            cmdstr = " ".join(cmd)
            try:
                rc, sout, serr = run_command_list(cmd, env=proc_env)
                if rc != 0:
                    skopeo_error = SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
                    if skopeo_error.error_code != AnchoreError.OSARCH_MISMATCH.name:
                        raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
                else:
                    logger.debug(
                        "command succeeded: cmd="
                        + str(cmdstr)
                        + " stdout="
                        + str(sout).strip()
                        + " stderr="
                        + str(serr).strip()
                    )
                    success = True

            except Exception as err:
                logger.error("command failed with exception - " + str(err))
                raise err

            if success:
                blobs_dir = os.path.join(copydir, "blobs")

                if use_cache_dir:
                    # syft expects blobs to be nested inside of the oci image directory. If the --dest-shared-blob-dir skopeo option is used we need to
                    # provide access to the blobs via a symlink, as if the blobs were stored within the oci image directory
                    if os.path.exists(blobs_dir) and os.path.isdir(blobs_dir):
                        # if this directory is not empty, there is an issue and we should expect an exception
                        os.rmdir(blobs_dir)

                    os.symlink(use_cache_dir, blobs_dir)

                fetch_oci_blobs(blobs_dir, blobs_to_fetch)

                index_file_path = os.path.join(copydir, "index.json")
                ensure_no_nondistributable_media_types(index_file_path)
                ensure_layer_media_types_are_correct(copydir)

                break
        if not success:
            logger.error("could not download image")
            raise Exception("could not download image")
    except Exception as err:
        raise err

    return True


def fetch_oci_blobs(blobs_dir: str, blobs_to_fetch: list):
    for blob in blobs_to_fetch:
        for url in blob["urls"]:
            # try to retrieve, and if successful, break
            blob_destination_path = os.path.join(blobs_dir, "sha256", blob["digest"])

            try:
                urlretrieve(url, blob_destination_path)
                break
            except Exception:
                logger.exception(
                    "failed saving blob from URL (%s) to path (%s)",
                    url,
                    blob_destination_path,
                )
                continue


def get_digest_value(digest_with_algorithm_prefix: str):
    return digest_with_algorithm_prefix.split(":")[-1]


def ensure_layer_media_types_are_correct(oci_dir_path: str):
    index_path = os.path.join(oci_dir_path, "index.json")
    manifest_file_path = get_manifest_path_from_index(index_path)
    blobs_sha256_dir_path = os.path.join(oci_dir_path, "blobs", "sha256")

    with open(manifest_file_path, "r") as _f:
        manifest = json.load(_f)

    layers = manifest.get("layers", [])
    for layer in layers:
        blob_file = get_digest_value(layer.get("digest", ""))
        blob_path = os.path.join(blobs_sha256_dir_path, blob_file)

        tar_media_type = "application/vnd.oci.image.layer.v1.tar"
        tar_gzip_media_type = "application/vnd.oci.image.layer.v1.tar+gzip"

        blob_media_type = tar_gzip_media_type if is_gzip(blob_path) else tar_media_type

        layer["mediaType"] = blob_media_type

    with open(manifest_file_path, "w") as _f:
        json.dump(manifest, _f)


def is_gzip(path: str):
    try:
        with gzip.open(path) as _f:
            _f.read(1)
            return True
    except Exception:
        return False


def ensure_no_nondistributable_media_types(oci_index_file_path: str):
    manifest_file_path = get_manifest_path_from_index(oci_index_file_path)

    with open(manifest_file_path, "r") as _f:
        manifest = json.load(_f)

    layers = manifest.get("layers", [])
    updated_layers = list(map(remove_nondistributable, layers))
    manifest["layers"] = updated_layers

    with open(manifest_file_path, "w") as _f:
        json.dump(manifest, _f)


def get_manifest_path_from_index(oci_index_file_path: str):
    with open(oci_index_file_path, "r") as _f:
        index = json.load(_f)

    for m in index.get("manifests", []):
        manifest_digest_raw = m.get("digest", "")
        manifest_digest = get_digest_value(manifest_digest_raw)
        return os.path.join(
            os.path.dirname(oci_index_file_path), "blobs", "sha256", manifest_digest
        )

    raise Exception("No manifests found in OCI index ({})".format(oci_index_file_path))


def remove_nondistributable(layer: dict):
    updated_media_type = layer.get("mediaType", "").replace("nondistributable.", "")
    layer["mediaType"] = updated_media_type
    return layer


def get_repo_tags_skopeo(url, registry, repo, user=None, pw=None, verify=None):
    try:
        proc_env = os.environ.copy()
        if user and pw:
            proc_env["SKOPUSER"] = user
            proc_env["SKOPPASS"] = pw
            credstr = '--creds "${SKOPUSER}":"${SKOPPASS}"'
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--tls-verify=true"
        else:
            tlsverifystr = "--tls-verify=false"

        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get("skopeo_global_timeout", 0)
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        pullstring = registry + "/" + repo

        repotags = []

        cmd = [
            "/bin/sh",
            "-c",
            "skopeo {} list-tags {} {} docker://{}".format(
                global_timeout_str, tlsverifystr, credstr, pullstring
            ),
        ]
        cmdstr = " ".join(cmd)
        try:
            rc, sout, serr = run_command_list(cmd, env=proc_env)
            sout = str(sout, "utf-8") if sout else None
            if rc != 0:
                raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
            else:
                logger.debug(
                    "command succeeded: cmd="
                    + str(cmdstr)
                    + " stdout="
                    + str(sout).strip()
                    + " stderr="
                    + str(serr).strip()
                )
        except Exception as err:
            logger.error("command failed with exception - " + str(err))
            raise err

        data = json.loads(sout)
        repotags = data.get("Tags", [])
    except Exception as err:
        raise err

    if not repotags:
        raise Exception("no tags found for input repo from skopeo")

    return repotags


def get_image_manifest_skopeo_raw(pullstring, user=None, pw=None, verify=True):
    ret = None
    try:
        proc_env = os.environ.copy()
        if user and pw:
            proc_env["SKOPUSER"] = user
            proc_env["SKOPPASS"] = pw
            credstr = '--creds "${SKOPUSER}":"${SKOPPASS}"'
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--tls-verify=true"
        else:
            tlsverifystr = "--tls-verify=false"

        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get("skopeo_global_timeout", 0)
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        os_override_strs = ["", "--override-os windows"]
        try:
            success = False
            for os_override_str in os_override_strs:
                cmd = [
                    "/bin/sh",
                    "-c",
                    "skopeo {} {} inspect --raw {} {} docker://{}".format(
                        global_timeout_str,
                        os_override_str,
                        tlsverifystr,
                        credstr,
                        pullstring,
                    ),
                ]
                cmdstr = " ".join(cmd)
                try:
                    rc, sout, serr = run_command_list(cmd, env=proc_env)
                    if rc != 0:
                        skopeo_error = SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
                        if skopeo_error.error_code != AnchoreError.OSARCH_MISMATCH.name:
                            raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
                    else:
                        logger.debug(
                            "command succeeded: cmd="
                            + str(cmdstr)
                            + " stdout="
                            + str(sout).strip()
                            + " stderr="
                            + str(serr).strip()
                        )
                        success = True
                except Exception as err:
                    logger.error("command failed with exception - " + str(err))
                    raise err

                if success:
                    sout = str(sout, "utf-8") if sout else None
                    ret = sout
                    break

            if not success:
                logger.error("could not retrieve manifest")
                raise Exception("could not retrieve manifest")

        except Exception as err:
            raise err
    except Exception as err:
        raise err

    return ret


def get_image_manifest_skopeo(
    url,
    registry,
    repo,
    intag=None,
    indigest=None,
    topdigest=None,
    user=None,
    pw=None,
    verify=True,
    topmanifest=None,
):
    manifest = {}
    digest = None
    testDigest = None

    if indigest:
        pullstring = registry + "/" + repo + "@" + indigest
    elif intag:
        pullstring = registry + "/" + repo + ":" + intag
    else:
        raise Exception("invalid input - must supply either an intag or indigest")

    try:
        try:
            rawmanifest = get_image_manifest_skopeo_raw(
                pullstring, user=user, pw=pw, verify=verify
            )
            digest = manifest_to_digest(rawmanifest)
            manifest = json.loads(rawmanifest)
            if topmanifest is None:
                topmanifest = json.loads(rawmanifest)
            if not topdigest:
                topdigest = digest

            if (
                manifest.get("schemaVersion") == 2
                and manifest.get("mediaType")
                == "application/vnd.docker.distribution.manifest.list.v2+json"
            ):
                # Get the arch-specific version for amd64 and linux
                new_digest = None
                for entry in manifest.get("manifests"):
                    platform = entry.get("platform")
                    if (
                        platform
                        and platform.get("architecture") in ["amd64"]
                        and platform.get("os") in ["linux", "windows"]
                    ):
                        new_digest = entry.get("digest")
                        break

                return get_image_manifest_skopeo(
                    url=url,
                    registry=registry,
                    repo=repo,
                    intag=None,
                    indigest=new_digest,
                    user=user,
                    pw=pw,
                    verify=verify,
                    topdigest=topdigest,
                    topmanifest=topmanifest,
                )
        except Exception as err:
            logger.warn("CMD failed - exception: " + str(err))
            raise err

    except Exception as err:
        import traceback

        traceback.print_exc()
        raise err

    if not manifest or not digest:
        raise SkopeoError(msg="No digest/manifest from skopeo")

    return manifest, digest, topdigest, topmanifest


class SkopeoError(AnchoreException):
    def __init__(
        self,
        cmd=None,
        rc=None,
        err=None,
        out=None,
        msg="Error encountered in skopeo operation",
    ):
        self.cmd = " ".join(cmd) if isinstance(cmd, list) else cmd
        self.exitcode = rc
        self.stderr = (
            str(err).replace("\r", " ").replace("\n", " ").strip() if err else None
        )
        self.stdout = (
            str(out).replace("\r", " ").replace("\n", " ").strip() if out else None
        )
        self.msg = msg
        try:
            if "unauthorized" in self.stderr:
                self.error_code = AnchoreError.REGISTRY_PERMISSION_DENIED.name
            elif "manifest unknown" in self.stderr:
                self.error_code = AnchoreError.REGISTRY_IMAGE_NOT_FOUND.name
            elif (
                "connection refused" in self.stderr or "no route to host" in self.stderr
            ):
                self.error_code = AnchoreError.REGISTRY_NOT_ACCESSIBLE.name
            elif "error pinging registry" in self.stderr:
                self.error_code = AnchoreError.REGISTRY_NOT_SUPPORTED.name
            elif (
                "no image found in manifest list for architecture amd64, OS linux"
                in self.stderr
            ):
                self.error_code = AnchoreError.OSARCH_MISMATCH.name
            else:
                self.error_code = AnchoreError.SKOPEO_UNKNOWN_ERROR.name
        except:
            self.error_code = AnchoreError.UNKNOWN.name

    def __repr__(self):
        return "{}. cmd={}, rc={}, stdout={}, stderr={}, error_code={}".format(
            self.msg, self.cmd, self.exitcode, self.stdout, self.stderr, self.error_code
        )

    def __str__(self):
        return "{}. cmd={}, rc={}, stdout={}, stderr={}, error_code={}".format(
            self.msg, self.cmd, self.exitcode, self.stdout, self.stderr, self.error_code
        )
