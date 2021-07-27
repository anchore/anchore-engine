import base64
import copy
import filecmp
import json
import os
import re
import shutil
import tarfile
import threading
import time
import uuid

import retrying
import treelib
import yaml

import anchore_engine.auth.common
import anchore_engine.clients.skopeo_wrapper
import anchore_engine.common
import anchore_engine.common.images
import anchore_engine.configuration
from anchore_engine import utils
from anchore_engine.analyzers import manager as analyzer_manager
from anchore_engine.util.docker import (
    DockerV1ManifestMetadata,
    DockerV2ManifestMetadata,
)
from anchore_engine.utils import AnchoreException

anchorelock = threading.Lock()
anchorelocks = {}

IMAGE_PULL_RETRIES = 3
IMAGE_PULL_RETRY_WAIT_MS = 1000
IMAGE_PULL_RETRY_WAIT_INCREMENT_MS = 1000


try:
    # Separate logger for use during bootstrap when logging may not be fully configured
    from anchore_engine.subsys import logger  # pylint: disable=C0412
except:
    import logging

    logger = logging.getLogger(__name__)
    logger.setLevel("DEBUG")
    log = logger


def get_layertarfile(unpackdir, cachedir, layer):
    layer_candidates = [
        os.path.join(unpackdir, "raw", layer + ".tar"),
        os.path.join(unpackdir, "raw", layer),
        os.path.join(unpackdir, "raw", "blobs", "sha256", layer),
    ]
    if cachedir:
        layer_candidates.append(os.path.join(cachedir, "sha256", layer))

    layerfound = False
    for layer_candidate in layer_candidates:
        try:
            if os.path.exists(layer_candidate):
                try:
                    # try to update atime for the file
                    os.utime(layer_candidate, None)
                except:
                    pass
                return layer_candidate
        except:
            pass

    return None


def handle_tar_error_post(unpackdir=None, rootfsdir=None, handled_post_metadata={}):
    if not unpackdir or not rootfsdir or not handled_post_metadata:
        # nothing to do
        return True

    logger.debug("handling post with metadata: {}".format(handled_post_metadata))
    if handled_post_metadata.get("temporary_file_adds", []):
        for tfile in handled_post_metadata.get("temporary_file_adds", []):
            rmfile = os.path.join(rootfsdir, tfile)
            if os.path.exists(rmfile):
                logger.debug("removing temporary image file: {}".format(rmfile))
                if os.path.isfile(rmfile):
                    os.remove(rmfile)

    if handled_post_metadata.get("temporary_dir_adds", []):
        for tfile in sorted(
            handled_post_metadata.get("temporary_dir_adds", []), reverse=True
        ):
            rmfile = os.path.join(rootfsdir, tfile)
            if os.path.exists(rmfile):
                logger.debug(
                    "removing temporary image dir, only if terminal (empty): {}".format(
                        rmfile
                    )
                )
                if os.path.isdir(rmfile):
                    try:
                        os.rmdir(rmfile)
                    except:
                        pass

    return True


def handle_tar_error(
    tarcmd,
    rc,
    sout,
    serr,
    unpackdir=None,
    rootfsdir=None,
    cachedir=None,
    layer=None,
    layertar=None,
    layers=[],
):
    handled = False

    handled_post_metadata = {
        "temporary_file_adds": [],
        "temporary_dir_adds": [],
    }

    slinkre = "tar: (.*): Cannot open: File exists"
    hlinkre = "tar: (.*): Cannot hard link to .(.*).: No such file or directory"
    missingfiles = []
    missingdirs = []
    for errline in serr.splitlines():
        patt = re.match(slinkre, errline)
        patt1 = re.match(hlinkre, errline)
        if patt:
            matchfile = patt.group(1)
            logger.debug("found 'file exists' error on name: " + str(matchfile))
            if matchfile:
                badfile = os.path.join(rootfsdir, patt.group(1))
                if os.path.exists(badfile):
                    logger.debug("removing hierarchy: " + str(badfile))
                    shutil.rmtree(badfile)
                    handled = True
        elif patt1:
            missingfile = patt1.group(2)
            basedir = os.path.dirname(missingfile)
            logger.debug("found 'hard link' error on name: {}".format(missingfile))
            if not os.path.exists(os.path.join(rootfsdir, missingfile)):
                missingfiles.append(missingfile)

            missingdir = None
            if not os.path.exists(os.path.join(rootfsdir, basedir)):
                missingdir = basedir
                missingdirs.append(missingdir)

    # only move on to further processing if the error is still not handled
    if not handled:
        if missingfiles:
            logger.info(
                "found {} missing hardlink destination files to extract from lower layers".format(
                    len(missingfiles)
                )
            )

            for l in layers[layers.index("sha256:" + layer) :: -1]:
                dighash, lname = l.split(":")
                ltar = get_layertarfile(unpackdir, cachedir, lname)

                tarcmd = "tar -C {} -x -f {}".format(rootfsdir, ltar)
                tarcmd_list = tarcmd.split() + missingfiles
                logger.debug(
                    "attempting to run command to extract missing hardlink targets from layer {}: {}.....".format(
                        l, tarcmd_list[:16]
                    )
                )

                rc, sout, serr = utils.run_command_list(tarcmd_list)
                sout = utils.ensure_str(sout)
                serr = utils.ensure_str(serr)
                # logger.debug("RESULT attempting to run command to extract missing hardlink target: {} : rc={} : serr={} : sout={}".format(tarcmd_list[:16], rc, serr, sout))

                newmissingfiles = []
                logger.debug(
                    "missing file count before extraction at layer {}: {}".format(
                        l, len(missingfiles)
                    )
                )
                for missingfile in missingfiles:
                    tmpmissingfile = os.path.join(rootfsdir, missingfile)
                    if os.path.exists(tmpmissingfile):
                        if (
                            missingfile
                            not in handled_post_metadata["temporary_file_adds"]
                        ):
                            handled_post_metadata["temporary_file_adds"].append(
                                missingfile
                            )
                    else:
                        if missingfile not in newmissingfiles:
                            newmissingfiles.append(missingfile)
                missingfiles = newmissingfiles
                logger.debug(
                    "missing file count after extraction at layer {}: {}".format(
                        l, len(missingfiles)
                    )
                )

                newmissingdirs = []
                for missingdir in missingdirs:
                    tmpmissingdir = os.path.join(rootfsdir, missingdir)
                    if os.path.exists(tmpmissingdir):
                        if (
                            missingdir
                            not in handled_post_metadata["temporary_dir_adds"]
                        ):
                            handled_post_metadata["temporary_dir_adds"].append(
                                missingdir
                            )
                    else:
                        if missingdir not in newmissingdirs:
                            newmissingdirs.append(missingdir)
                missingdirs = newmissingdirs

                if not missingfiles:
                    logger.info(
                        "extraction of all missing files complete at layer {}".format(l)
                    )
                    handled = True
                    break
                else:
                    logger.info(
                        "extraction of all missing files not complete at layer {}, moving on to next layer".format(
                            l
                        )
                    )

    logger.debug("tar error handled: {}".format(handled))
    return handled, handled_post_metadata


def get_tar_filenames(layertar):
    ret = []
    layertarfile = None
    try:
        logger.debug(
            "using tarfile library to get file names from tarfile={}".format(layertar)
        )
        layertarfile = tarfile.open(layertar, mode="r", format=tarfile.PAX_FORMAT)
        ret = layertarfile.getnames()
    except:
        # python tarfile fils to unpack some docker image layers due to PAX header issue, try another method
        logger.debug(
            "using tar command to get file names from tarfile={}".format(layertar)
        )
        tarcmd = "tar tf {}".format(layertar)
        try:
            ret = []
            rc, sout, serr = utils.run_command(tarcmd)
            sout = utils.ensure_str(sout)
            serr = utils.ensure_str(serr)
            if rc == 0 and sout:
                for line in sout.splitlines():
                    re.sub("/+$", "", line)
                    ret.append(line)
            else:
                raise Exception("rc={} sout={} serr={}".format(rc, sout, serr))
        except Exception as err:
            logger.error("command failed with exception - " + str(err))
            raise err

    finally:
        if layertarfile:
            layertarfile.close()

    return ret


def tree_id(id):
    toks = id.split("/")
    return toks[-1], id, "/".join(toks[:-1])


def tree_create_branch(ftree, id, data, stree=None, populate_intermediate_nodes=False):
    ftoks = id.split("/")

    for i in range(1, len(ftoks)):
        (fname, fid, fparent) = tree_id("/".join(ftoks[0:i]))

        if not ftree.get_node(fid):
            idata = {}
            if populate_intermediate_nodes:
                idata.update(data)
            ftree.create_node(fname, fid, parent=fparent, data=idata)
            if stree and stree.get_node(fid):
                ftree[fid].data.update(stree[fid].data)

    (fname, fid, fparent) = tree_id(id)
    if not ftree.get_node(fid):
        ftree.create_node(fname, fid, parent=fparent, data=data)


def squash(unpackdir, cachedir, layers):
    rootfsdir = unpackdir + "/rootfs"

    if os.path.exists(unpackdir + "/squashed.tar"):
        return True

    tree_time = time.time()
    ftree = treelib.Tree()
    ftree.create_node("", "", data={"latest_layer_tar": "", "exists": True})
    tarfiles = {}
    tarfiles_members = {}
    whpatt = re.compile(r"\.wh\..*")
    whopqpatt = re.compile(r"\.wh\.\.wh\.\.opq")
    slashprefixpatt = re.compile(r"^/+|\.+/+")
    deferred_hardlinks_destination = {}
    hardlink_destinations = {}
    try:
        logger.debug("Layers to process: {}".format(layers))
        logger.debug("Pass 1: generating layer file timeline")
        for l in layers:
            htype, layer = l.split(":", 1)
            # layertar = os.path.join(copydir, layer)
            layertar = get_layertarfile(unpackdir, cachedir, layer)
            logger.debug("processing layer {} - {}".format(l, layertar))
            tarfiles[l] = tarfile.open(layertar, mode="r", format=tarfile.PAX_FORMAT)
            tarfiles_members[l] = {}
            layerfiles = []
            lftree = treelib.Tree()
            lftree.create_node("", "", data={"latest_layer_tar": "", "exists": True})

            for member in tarfiles[l].getmembers():
                # clean up any prefix on the member names for history tracking purposes
                tarfilename = member.name
                member.name = slashprefixpatt.sub("", member.name)
                if member.islnk() and member.linkname:
                    member.linkname = slashprefixpatt.sub("", member.linkname)
                    member.linkpath = member.linkname
                member.pax_headers["path"] = member.name

                # regular processing starts here
                tarfiles_members[l][member.name] = member
                filename = member.name
                tree_create_branch(
                    lftree,
                    filename,
                    {"latest_layer_tar": l, "exists": True},
                    stree=ftree,
                    populate_intermediate_nodes=True,
                )

                ftoks = filename.split("/")
                # logger.debug("FILENAME: {} {}".format(filename, time.time()))
                for i in range(1, len(ftoks)):
                    f = ftoks[0:i][-1]
                    parent = "/".join(ftoks[0 : i - 1])
                    b = "/".join(ftoks[0:i])

                    if not lftree.get_node(b):
                        lftree.create_node(
                            f,
                            b,
                            parent=parent,
                            data={"latest_layer_tar": l, "exists": True},
                        )

                    lftree[b].data["latest_layer_tar"] = l
                    lftree[b].data["exists"] = True

                f = ftoks[-1]
                parent = "/".join(ftoks[0:-1])
                if not lftree.get_node(filename):
                    lftree.create_node(
                        f,
                        filename,
                        parent=parent,
                        data={"latest_layer_tar": l, "exists": True},
                    )

                lftree[filename].data["latest_layer_tar"] = l
                lftree[filename].data["exists"] = True

                if whopqpatt.match(os.path.basename(filename)):
                    lftree[filename].data["exists"] = False
                    fsub = re.sub(r"\.wh\.\.wh\.\.opq", "", filename, 1)
                    fsub = re.sub("/+$", "", fsub)

                    if not lftree.get_node(fsub):
                        (fname, fid, fparent) = tree_id(fsub)
                        lftree.create_node(fname, fid, parent=fparent, data={})
                        if ftree.get_node(fsub):
                            lftree[fsub].data.update(ftree[fsub].data)

                    parent_node = ftree.get_node(fsub)
                    if parent_node:
                        for n in ftree.expand_tree(nid=fsub):
                            if not lftree.get_node(n):
                                (fname, fid, fparent) = tree_id(n)
                                lftree.create_node(fname, fid, parent=fparent, data={})
                                lftree[fid].data.update(ftree[fid].data)
                            if n != fsub:
                                lftree[n].data["exists"] = False

                elif whpatt.match(os.path.basename(filename)):
                    logger.debug("WH handler {} {}".format(filename, time.time()))
                    # never include the wh itself
                    lftree[filename].data["exists"] = False

                    fsub = re.sub(r"\.wh\.", "", filename, 1)
                    if not lftree.get_node(fsub):
                        (fname, fid, fparent) = tree_id(fsub)
                        lftree.create_node(fname, fid, parent=fparent, data={})
                        if ftree.get_node(fsub):
                            lftree[fsub].data.update(ftree[fsub].data)

                    lftree[fsub].data["exists"] = False

                    parent_node = ftree.get_node(fsub)
                    if parent_node:
                        for n in ftree.expand_tree(nid=fsub):
                            if not lftree.get_node(n):
                                (fname, fid, fparent) = tree_id(n)
                                lftree.create_node(fname, fid, parent=fparent, data={})
                                lftree[fid].data.update(ftree[fid].data)

                            lftree[n].data["exists"] = False

                if lftree[filename].data["exists"] and member.islnk():
                    el = {
                        "hl_target_layer": l,
                        "hl_target_name": member.linkname,
                        "hl_replace": False,
                    }
                    lftree[filename].data.update(el)
                    if member.linkname not in hardlink_destinations:
                        hardlink_destinations[member.linkname] = []
                    el = {
                        "filename": filename,
                        "layer": l,
                    }
                    hardlink_destinations[member.linkname].append(el)

            for filename in lftree.expand_tree():
                if filename in hardlink_destinations:
                    for el in hardlink_destinations[filename]:
                        if el["layer"] != l:
                            if not lftree.get_node(el["filename"]):
                                tree_create_branch(
                                    lftree,
                                    el["filename"],
                                    ftree[el["filename"]].data,
                                    stree=ftree,
                                )
                            lftree[el["filename"]].data["hl_replace"] = True

            for n in lftree.expand_tree():
                if not ftree.get_node(n):
                    (fname, fid, fparent) = tree_id(n)
                    ftree.create_node(fname, fid, parent=fparent, data={})
                ftree[n].data.update(lftree[n].data)

        logger.debug("Pass 2: creating squashtar from layers")
        allexcludes = []
        with tarfile.open(
            os.path.join(unpackdir, "squashed.tar"), mode="w", format=tarfile.PAX_FORMAT
        ) as oltf:
            imageSize = 0
            deferred_hardlinks = {}

            for l in tarfiles_members.keys():
                for filename in tarfiles_members[l].keys():
                    if (
                        ftree[filename].data["exists"]
                        and ftree[filename].data["latest_layer_tar"] == l
                    ):
                        member = tarfiles_members[l].get(filename)
                        if member.isreg():
                            memberfd = tarfiles[l].extractfile(member)
                            oltf.addfile(member, fileobj=memberfd)
                        elif member.islnk():
                            if ftree[filename].data["hl_replace"]:
                                deferred_hardlinks[filename] = ftree[filename].data
                            else:
                                oltf.addfile(member)
                        else:
                            oltf.addfile(member)

            for filename in deferred_hardlinks.keys():
                l = ftree[filename].data["latest_layer_tar"]
                member = tarfiles_members[l].get(filename)
                logger.debug("deferred hardlink {}".format(ftree[filename].data))
                try:
                    logger.debug(
                        "attempt to lookup deferred {} content source".format(filename)
                    )
                    content_layer = ftree[filename].data["hl_target_layer"]
                    content_filename = ftree[filename].data["hl_target_name"]

                    logger.debug(
                        "attempt to extract deferred {} from layer {} (for lnk {})".format(
                            content_filename, content_layer, filename
                        )
                    )
                    content_member = tarfiles_members[content_layer].get(
                        content_filename
                    )
                    content_memberfd = tarfiles[content_layer].extractfile(
                        content_member
                    )

                    logger.debug(
                        "attempt to construct new member for deferred {}".format(
                            filename
                        )
                    )
                    new_member = copy.deepcopy(content_member)

                    new_member.name = member.name
                    new_member.pax_headers["path"] = member.name

                    logger.debug(
                        "attempt to add final to squashed tar {} -> {}".format(
                            filename, new_member.name
                        )
                    )
                    oltf.addfile(new_member, fileobj=content_memberfd)
                except Exception as err:
                    import traceback

                    traceback.print_exc()
                    logger.warn(
                        "failed to store hardlink ({} -> {}) - exception: {}".format(
                            member.name, member.linkname, err
                        )
                    )

    finally:
        logger.debug("Pass 3: closing layer tarfiles")
        for l in tarfiles.keys():
            if tarfiles[l]:
                try:
                    tarfiles[l].close()
                except Exception as err:
                    logger.error(
                        "failure closing tarfile {} - exception: {}".format(l, err)
                    )

    imageSize = 0
    if os.path.exists(os.path.join(unpackdir, "squashed.tar")):
        imageSize = os.path.getsize(os.path.join(unpackdir, "squashed.tar"))

    return "done", imageSize


def make_staging_dirs(rootdir, use_cache_dir=None):
    if not os.path.exists(rootdir):
        raise Exception("passed in root directory must exist (" + str(rootdir) + ")")

    rando = str(uuid.uuid4())
    unpackdir = os.path.join(rootdir, rando)

    ret = {
        "unpackdir": unpackdir,
        "copydir": os.path.join(rootdir, rando, "raw"),
        "rootfs": os.path.join(rootdir, rando, "rootfs"),
        "outputdir": os.path.join(rootdir, rando, "output"),
        "cachedir": use_cache_dir,
    }

    for k in list(ret.keys()):
        if not ret[k]:
            continue

        try:
            if not os.path.exists(ret[k]):
                logger.debug("making dir: " + k + " : " + str(ret[k]))
                os.makedirs(ret[k])
        except Exception as err:
            raise Exception("unable to prep staging directory - exception: " + str(err))

    # XXX This highly questionable environment variable usage is the only way
    # found to programmatically inject hintsfiles without requiring the
    # hintsfile to exist in the image. Otherwise, it would require every
    # permutation of a hintsfile to be an actual unique image. It leverages the
    # fact that Anchore Engine will not try to extract the hinstfile if it has
    # already been unpacked in the unpack directory.
    try:
        if os.environ.get("ANCHORE_TEST_HINTSFILE"):
            test_hints = os.environ["ANCHORE_TEST_HINTSFILE"]
            destination = os.path.join(unpackdir, "anchore_hints.json")
            shutil.copyfile(test_hints, destination)
    except Exception as err:
        logger.debug("testing injection of hintsfile failed: %s", str(err))

    return ret


def _rmtree_error_handler(infunc, inpath, inerr):
    (cls, exc, trace) = inerr
    try:
        # attempt to change the permissions and then retry removal
        os.chmod(inpath, 0o777)
    except Exception as err:
        logger.warn(
            "unable to change permissions in error handler for path {} in shutil.rmtree".format(
                inpath
            )
        )
    finally:
        try:
            infunc(inpath)
        except Exception as err:
            logger.debug(
                "unable to remove in error handler for path {} - this will be retried".format(
                    err
                )
            )


def rmtree_force(inpath):
    if os.path.exists(inpath):
        try:
            shutil.rmtree(inpath, False, _rmtree_error_handler)
        finally:
            if os.path.exists(inpath):
                shutil.rmtree(inpath)

    return True


def delete_staging_dirs(staging_dirs):
    for k in list(staging_dirs.keys()):
        if k == "cachedir":
            continue

        localconfig = anchore_engine.configuration.localconfig.get_config()
        myconfig = localconfig.get("services", {}).get("analyzer", {})
        if not myconfig.get("keep_image_analysis_tmpfiles", False):
            try:
                if os.path.exists(staging_dirs[k]):
                    logger.debug("removing dir: " + k + " : " + str(staging_dirs[k]))
                    rmtree_force(staging_dirs[k])
            except Exception as err:
                raise Exception(
                    "unable to delete staging directory - exception: " + str(err)
                )
        else:
            logger.debug(
                "keep_image_analysis_tmpfiles is enabled - leaving analysis tmpdir in place {}".format(
                    staging_dirs
                )
            )

    return True


def pull_image(
    staging_dirs, pullstring, registry_creds=None, manifest=None, parent_manifest=None
):
    copydir = staging_dirs["copydir"]
    cachedir = staging_dirs["cachedir"]

    user = pw = None
    registry_verify = False

    # extract user/pw/verify from registry_creds
    if registry_creds:
        image_info = anchore_engine.common.images.get_image_info(
            None, "docker", pullstring, registry_lookup=False
        )
        user, pw, registry_verify = anchore_engine.auth.common.get_creds_by_registry(
            image_info["registry"], image_info["repo"], registry_creds=registry_creds
        )

    # download
    logger.info("Downloading image {} for analysis to {}".format(pullstring, copydir))
    return anchore_engine.clients.skopeo_wrapper.download_image(
        pullstring,
        copydir,
        user=user,
        pw=pw,
        verify=registry_verify,
        manifest=manifest,
        parent_manifest=parent_manifest,
        use_cache_dir=cachedir,
    )


@retrying.retry(
    stop_max_attempt_number=IMAGE_PULL_RETRIES,
    wait_incrementing_start=IMAGE_PULL_RETRY_WAIT_MS,
    wait_incrementing_increment=IMAGE_PULL_RETRY_WAIT_INCREMENT_MS,
)
def retrying_pull_image(
    staging_dirs, pullstring, registry_creds=None, manifest=None, parent_manifest=None
):
    """
    Retry-wrapper on pull image

    :param staging_dirs:
    :param registry_creds:
    :param manifest:
    :param parent_manifest:
    :param dest_type:
    :return:
    """

    try:
        result = pull_image(
            staging_dirs, pullstring, registry_creds, manifest, parent_manifest
        )
        if not result:
            # This is an unexpected case, pull_image() will return True or throw exception, but handle weird case anyway to ensure retry works
            raise Exception(
                "Could not pull image for unknown reason. This is an unexpected error path"
            )
    except Exception as err:
        # Intentionally broad, just for logging since retry will swallow individual errors
        logger.debug_exception(
            "Could not pull image due to error: {}. Will retry".format(str(err))
        )
        raise

    return result


def get_blob_list(copydir, cachedir):
    blobdir = None
    blobs = []
    index_path = os.path.join(copydir, "index.json")
    if os.path.exists(index_path):
        if cachedir:
            blobdir = os.path.join(cachedir, "sha256")
        else:
            blobdir = os.path.join(copydir, "blobs", "sha256")

        if os.path.exists(blobdir):
            blobs = os.listdir(blobdir)

    return blobdir, blobs


def get_image_config(copydir, cachedir, image_id) -> dict:
    """
    Load the image config from disk

    :param copydir:
    :param cachedir:
    :param image_id:
    :return: Image Config json object
    """

    # Try the tar from the image id
    for ifile in ["{}.tar".format(image_id), "{}".format(image_id)]:
        if os.path.exists(os.path.join(copydir, ifile)):
            image_config = os.path.join(copydir, ifile)
            with open(image_config, "r") as FH:
                return json.loads(FH.read())

    # Not found in the tar directly, so lookup using the index.json
    blobdir, blobs = get_blob_list(copydir, cachedir)
    if not blobdir:
        raise Exception("No blob directory found to read image configuration")

    dfile = nfile = None
    with open(os.path.join(copydir, "index.json"), "r") as FH:
        idata = json.loads(FH.read())
        d_digest = idata["manifests"][0]["digest"].split(":", 1)[1]
        dfile = os.path.join(blobdir, d_digest)

    if not dfile:
        raise Exception(
            "could not find intermediate digest - no blob digest data file found in index.json"
        )

    with open(dfile, "r") as FH:
        n_data = json.loads(FH.read())
        n_digest = n_data["config"]["digest"].split(":", 1)[1]
        nfile = os.path.join(blobdir, n_digest)

    if not nfile:
        raise Exception(
            "could not find final digest - no blob config file found in digest file: {}".format(
                dfile
            )
        )

    with open(nfile, "r") as FH:
        return json.loads(FH.read())


def get_image_metadata_v1(
    staging_dirs,
    manifest_data,
    dockerfile_contents="",
    dockerfile_mode="",
):
    """
    Extract image metadata from the manifest and content/dockerfile

    :param staging_dirs:
    :param manifest_data:
    :param dockerfile_contents:
    :param dockerfile_mode:
    :return:
    """
    unpackdir = staging_dirs["unpackdir"]

    parser = DockerV1ManifestMetadata(manifest_data)
    docker_history = parser.history
    layers = parser.layer_ids
    architecture = parser.architecture

    if dockerfile_contents:
        dockerfile_mode = "Actual"
    else:
        dockerfile_contents = parser.inferred_dockerfile
        dockerfile_mode = "Guessed"

    with open(os.path.join(unpackdir, "docker_history.json"), "w") as OFH:
        OFH.write(json.dumps(docker_history))

    return docker_history, layers, dockerfile_contents, dockerfile_mode, architecture


def get_image_metadata_v2(
    staging_dirs,
    imageId,
    manifest_data,
    dockerfile_contents="",
):
    """
    Load the image metadata such as building docker history, best effort dockerfile, and layers from the metadata and on-disk image data

    :param staging_dirs:
    :param imageDigest:
    :param imageId:
    :param manifest_data:
    :param dockerfile_contents:
    :param dockerfile_mode:
    :return:
    """
    unpackdir = staging_dirs["unpackdir"]
    copydir = staging_dirs["copydir"]
    cachedir = staging_dirs["cachedir"]

    image_config = get_image_config(copydir, cachedir, imageId)
    parser = DockerV2ManifestMetadata(manifest_data, image_config)
    docker_history = parser.history
    layers = parser.layer_ids

    if dockerfile_contents:
        dockerfile_mode = "Actual"
    else:
        dockerfile_contents = parser.inferred_dockerfile
        dockerfile_mode = "Guessed"

    with open(os.path.join(unpackdir, "docker_history.json"), "w") as OFH:
        OFH.write(json.dumps(docker_history))

    architecture = parser.architecture

    return docker_history, layers, dockerfile_contents, dockerfile_mode, architecture


def unpack(staging_dirs, layers):
    outputdir = staging_dirs["outputdir"]
    unpackdir = staging_dirs["unpackdir"]
    copydir = staging_dirs["copydir"]
    cachedir = staging_dirs["cachedir"]

    squashtar, imageSize = squash(unpackdir, cachedir, layers)

    return imageSize


def list_analyzers():
    """
    Return a list of the analyzer files

    :return: list of str that are the names of the analyzer modules
    """

    return analyzer_manager.list_modules()


def run_anchore_analyzers(
    staging_dirs,
    imageDigest,
    imageId,
    localconfig,
    owned_package_filtering_enabled: bool = True,
):
    outputdir = staging_dirs["outputdir"]
    unpackdir = staging_dirs["unpackdir"]
    copydir = staging_dirs["copydir"]
    configdir = localconfig["service_dir"]

    myconfig = localconfig.get("services", {}).get("analyzer", {})
    if not myconfig.get("enable_hints", False):
        # install an empty hints file to ensure that any discovered hints overrides is ignored during analysis
        with open(os.path.join(unpackdir, "anchore_hints.json"), "w") as OFH:
            OFH.write(json.dumps({}))

    analyzer_report = analyzer_manager.run(
        configdir,
        imageId,
        unpackdir,
        outputdir,
        copydir,
        owned_package_filtering_enabled,
    )

    return dict(analyzer_report)


def generate_image_export(
    imageId,
    analyzer_report,
    imageSize,
    fulltag,
    docker_history,
    dockerfile_mode,
    dockerfile_contents,
    layers,
    familytree,
    imageArch,
    rdigest,
    analyzer_manifest,
):
    image_report = []
    image_report.append(
        {
            "image": {
                "imageId": imageId,
                "imagedata": {
                    "analyzer_manifest": analyzer_manifest,
                    "analysis_report": analyzer_report,
                    "image_report": {
                        "meta": {
                            "shortparentId": "",
                            "sizebytes": imageSize,
                            "imageId": imageId,
                            "usertype": None,
                            "shortId": imageId[0:12],
                            "imagename": imageId,
                            "parentId": "",
                            "shortname": imageId[0:12],
                            "humanname": fulltag,
                        },
                        "docker_history": docker_history,
                        "dockerfile_mode": dockerfile_mode,
                        "dockerfile_contents": dockerfile_contents,
                        # 'dockerfile': utils.ensure_str(base64.encodebytes(dockerfile_contents.encode('utf-8'))),
                        "layers": layers,
                        "familytree": familytree,
                        "docker_data": {
                            "Architecture": imageArch,
                            "RepoDigests": [rdigest],
                            "RepoTags": [fulltag],
                        },
                    },
                },
            }
        }
    )
    return image_report


def get_manifest_from_staging(staging_dirs):
    copydir = staging_dirs["copydir"]
    ret = ""
    with open(os.path.join(copydir, "index.json"), "r") as FH:
        idata = json.loads(FH.read())
        d_digest = idata["manifests"][0]["digest"].split(":", 1)[1]
        dfile = os.path.join(copydir, "blobs", "sha256", d_digest)
        with open(dfile, "r") as FFH:
            ret = FFH.read()

    return ret


def analyze_image(
    userId,
    manifest,
    image_record,
    tmprootdir,
    localconfig,
    registry_creds=[],
    use_cache_dir=None,
    image_source="registry",
    image_source_meta=None,
    parent_manifest=None,
    owned_package_filtering_enabled: bool = True,
):
    # need all this

    imageId = None
    imageDigest = None
    layers = []
    rawlayers = []
    familytree = []
    imageSize = 0
    analyzer_manifest = {}
    analyzer_report = {}
    imageArch = ""
    dockerfile_mode = ""
    docker_history = {}
    rdigest = ""
    staging_dirs = None
    manifest_schema_version = 0
    event = None
    pullstring = None
    fulltag = None

    try:
        imageDigest = image_record["imageDigest"]

        dockerfile_mode = image_record.get("dockerfile_mode", "")

        image_detail = image_record["image_detail"][0]
        pullstring = (
            image_detail["registry"]
            + "/"
            + image_detail["repo"]
            + "@"
            + image_detail["imageDigest"]
        )
        fulltag = (
            image_detail["registry"]
            + "/"
            + image_detail["repo"]
            + ":"
            + image_detail["tag"]
        )
        imageId = image_detail["imageId"]
        if image_detail["dockerfile"]:
            dockerfile_contents = str(
                base64.decodebytes(image_detail["dockerfile"].encode("utf-8")), "utf-8"
            )
        else:
            dockerfile_contents = None

        staging_dirs = make_staging_dirs(tmprootdir, use_cache_dir=use_cache_dir)
        unpackdir = staging_dirs["unpackdir"]

        if image_source == "docker-archive":
            rc = anchore_engine.clients.skopeo_wrapper.copy_image_from_docker_archive(
                image_source_meta, staging_dirs["copydir"]
            )

            manifest = get_manifest_from_staging(staging_dirs)

        manifest_data = json.loads(manifest)

        if image_source != "docker-archive":
            rc = retrying_pull_image(
                staging_dirs,
                pullstring,
                registry_creds=registry_creds,
                manifest=manifest,
                parent_manifest=parent_manifest,
            )

        if manifest_data["schemaVersion"] == 1:
            (
                docker_history,
                layers,
                dockerfile_contents,
                dockerfile_mode,
                imageArch,
            ) = get_image_metadata_v1(
                staging_dirs,
                manifest_data,
                dockerfile_contents=dockerfile_contents,
            )
        elif manifest_data["schemaVersion"] == 2:
            (
                docker_history,
                layers,
                dockerfile_contents,
                dockerfile_mode,
                imageArch,
            ) = get_image_metadata_v2(
                staging_dirs,
                imageId,
                manifest_data,
                dockerfile_contents=dockerfile_contents,
            )
        else:
            raise ManifestSchemaVersionError(
                schema_version=manifest_data["schemaVersion"],
                pull_string=pullstring,
                tag=fulltag,
            )

        familytree = layers

        timer = time.time()
        imageSize = unpack(staging_dirs, layers)
        logger.debug(
            "timing: total unpack time: {} - {}".format(pullstring, time.time() - timer)
        )

        familytree = layers

        timer = time.time()
        analyzer_report = run_anchore_analyzers(
            staging_dirs,
            imageDigest,
            imageId,
            localconfig,
            owned_package_filtering_enabled,
        )

        logger.debug(
            "timing: total analyzer time: {} - {}".format(
                pullstring, time.time() - timer
            )
        )

        image_report = generate_image_export(
            imageId,
            analyzer_report,
            imageSize,
            fulltag,
            docker_history,
            dockerfile_mode,
            dockerfile_contents,
            layers,
            familytree,
            imageArch,
            pullstring,
            analyzer_manifest,
        )
    except Exception as err:
        raise AnalysisError(
            cause=err,
            pull_string=pullstring,
            tag=fulltag,
            msg="failed to download, unpack, analyze, and generate image export",
        )
    finally:
        if staging_dirs:
            delete_staging_dirs(staging_dirs)

    # if not imageDigest or not imageId or not manifest or not image_report:
    if not image_report:
        raise Exception("failed to analyze")

    return image_report, manifest


class AnalysisError(AnchoreException):
    def __init__(self, cause, pull_string, tag, msg):
        self.cause = str(cause)
        self.msg = msg
        self.pull_string = str(pull_string)
        self.tag = str(tag)

    def __repr__(self):
        return "{} ({}) - exception: {}".format(self.msg, self.pull_string, self.cause)

    def __str__(self):
        return "{} ({}) - exception: {}".format(self.msg, self.pull_string, self.cause)

    def to_dict(self):
        return {
            self.__class__.__name__: dict(
                (
                    key,
                    "{}...(truncated)".format(value[:256])
                    if key == "cause" and isinstance(value, str) and len(value) > 256
                    else value,
                )
                for key, value in vars(self).items()
                if not key.startswith("_")
            )
        }


class ManifestSchemaVersionError(AnalysisError):
    def __init__(
        self,
        schema_version,
        pull_string,
        tag,
        msg="Manifest schema version unsupported",
    ):
        super(ManifestSchemaVersionError, self).__init__(
            "No handlers for schemaVersion {}".format(schema_version),
            pull_string,
            tag,
            msg,
        )


def get_anchorelock(lockId=None, driver=None):
    global anchorelock, anchorelocks
    ret = anchorelock

    # first, check if we need to update the anchore configs
    localconfig = anchore_engine.configuration.localconfig.get_config()

    if not driver or driver in ["localanchore"]:
        if "anchore_scanner_config" not in localconfig:
            localconfig["anchore_scanner_config"] = get_config()
            anchore_config = localconfig["anchore_scanner_config"]
        anchore_config = localconfig["anchore_scanner_config"]
        anchore_data_dir = anchore_config["anchore_data_dir"]
    else:
        # anchore_data_dir = "/root/.anchore"
        anchore_data_dir = "{}/.anchore".format(os.getenv("HOME", "/tmp/anchoretmp"))
        if not os.path.exists(os.path.join(anchore_data_dir, "conf")):
            try:
                os.makedirs(os.path.join(anchore_data_dir, "conf"))
            except:
                pass

    try:
        for src, dst in [
            (
                localconfig["anchore_scanner_analyzer_config_file"],
                os.path.join(anchore_data_dir, "conf", "analyzer_config.yaml"),
            ),
            (
                os.path.join(localconfig["service_dir"], "anchore_config.yaml"),
                os.path.join(anchore_data_dir, "conf", "config.yaml"),
            ),
        ]:
            logger.debug("checking defaults against installed: " + src + " : " + dst)
            if os.path.exists(src):
                default_file = src
                installed_file = dst

                do_copy = False
                try:
                    same = filecmp.cmp(default_file, installed_file)
                    if not same:
                        do_copy = True
                except:
                    do_copy = True

                # if not filecmp.cmp(default_file, installed_file):
                if do_copy:
                    logger.debug("checking source yaml (" + str(default_file) + ")")
                    # check that it is at least valid yaml before copying in place
                    with open(default_file, "r") as FH:
                        yaml.safe_load(FH)

                    logger.info(
                        "copying new config into place: " + str(src) + " -> " + str(dst)
                    )
                    shutil.copy(default_file, installed_file)

    except Exception as err:
        logger.warn(
            "could not check/install analyzer anchore configurations (please check yaml format of your configuration files), continuing with default - exception: "
            + str(err)
        )

    if lockId:
        lockId = base64.encodebytes(lockId.encode("utf-8"))
        if lockId not in anchorelocks:
            anchorelocks[lockId] = threading.Lock()
        ret = anchorelocks[lockId]
        logger.spew("all locks: " + str(anchorelocks))
    else:
        ret = anchorelock

    return ret


def get_config():
    ret = {}
    logger.debug("fetching local anchore anchore_engine.configuration")
    if True:
        cmd = ["anchore", "--json", "system", "status", "--conf"]
        try:
            rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
            sout = utils.ensure_str(sout)
            serr = utils.ensure_str(serr)
            ret = json.loads(sout)
        except Exception as err:
            logger.error(str(err))

    return ret
