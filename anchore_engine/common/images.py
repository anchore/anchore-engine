import json
import re

import anchore_engine.services
import anchore_engine.utils
from anchore_engine import db
from anchore_engine.clients import docker_registry
from anchore_engine.subsys import logger


def lookup_registry_image(userId, image_info, registry_creds):
    digest = None
    manifest = None

    # TODO: push this upstream in the call chain or wrap with an authz checker
    #if not registry_access(userId, image_info['registry']):
    #    raise Exception("access denied for user ("+str(userId)+") registry ("+str(image_info['registry'])+")")
    #else:
    # try clause from below is in the else-clause
    try:
        manifest,digest,parentdigest = docker_registry.get_image_manifest(userId, image_info, registry_creds)
    except Exception as err:
        raise anchore_engine.common.helpers.make_anchore_exception(err, input_message="cannot fetch image digest/manifest from registry", input_httpcode=400)

    return(digest, manifest)


def get_image_info(userId, image_type, input_string, registry_lookup=False, registry_creds=[]):
    ret = {}
    if image_type == 'docker':
        try:
            image_info = anchore_engine.utils.parse_dockerimage_string(input_string)
        except Exception as err:
            raise anchore_engine.common.helpers.make_anchore_exception(err, input_message="cannot handle image input string", input_httpcode=400)

        ret.update(image_info)

        if registry_lookup and image_info['registry'] != 'localbuild':
            #digest, manifest = lookup_registry_image(userId, image_info, registry_creds)
            try:
                manifest,digest,parentdigest = docker_registry.get_image_manifest(userId, image_info, registry_creds)
            except Exception as err:
                raise anchore_engine.common.helpers.make_anchore_exception(err, input_message="cannot fetch image digest/manifest from registry", input_httpcode=400)
            image_info['digest'] = digest
            image_info['fulldigest'] = image_info['registry']+"/"+image_info['repo']+"@"+digest
            image_info['manifest'] = manifest
            image_info['parentdigest'] = parentdigest

            # if we got a manifest, and the image_info does not yet contain an imageId, try to get it from the manifest
            if manifest and not image_info['imageId']:
                try:
                    imageId = re.sub("^sha256:", "", manifest['config']['digest'])
                    image_info['imageId'] = imageId
                except Exception as err:
                    logger.debug("could not extract imageId from fetched manifest - exception: " + str(err))
                    logger.debug("using digest hash as imageId due to incomplete manifest ("+str(image_info['fulldigest'])+")")
                    htype, image_info['imageId'] = image_info['digest'].split(":", 1)

            ret.update(image_info)
        else:
            image_info['manifest'] = {}

    else:
        raise Exception ("image type ("+str(image_type)+") not supported")

    return(ret)


def clean_docker_image_details_for_update(image_details):
    ret = []

    for image_detail in image_details:
        el = {}
        for k in list(image_detail.keys()):
            if image_detail[k] != None:
                el[k] = image_detail[k]
        ret.append(el)
    return(ret)


def make_image_record(userId, image_type, input_string, image_metadata={}, registry_lookup=True, registry_creds=[]):
    if image_type == 'docker':
        try:
            dockerfile = image_metadata.get('dockerfile', None)
        except:
            dockerfile = None

        try:
            dockerfile_mode = image_metadata.get('dockerfile_mode', None)
        except:
            dockerfile_mode = None

        try:
            tag = image_metadata.get('tag', None)
        except:
            tag = None

        try:
            imageId = image_metadata.get('imageId', None)
        except:
            imageId = None

        try:
            digest = image_metadata.get('digest', None)
        except:
            digest = None

        try:
            annotations = image_metadata.get('annotations', {})
        except:
            annotations = {}

        parentdigest = image_metadata.get('parentdigest', None)
        created_at = image_metadata.get('created_at', None)

        return(make_docker_image(userId, input_string=input_string, tag=tag, digest=digest, imageId=imageId, parentdigest=parentdigest, created_at=created_at, dockerfile=dockerfile, dockerfile_mode=dockerfile_mode, registry_lookup=registry_lookup, registry_creds=registry_creds, annotations=annotations))

    else:
        raise Exception("image type ("+str(image_type)+") not supported")

    return(None)


def make_docker_image(userId, input_string=None, tag=None, digest=None, imageId=None, parentdigest=None, created_at=None, dockerfile=None, dockerfile_mode=None, registry_lookup=True, registry_creds=[], annotations={}):
    ret = {}

    if input_string:
        image_info = get_image_info(userId, "docker", input_string, registry_lookup=registry_lookup, registry_creds=registry_creds)
    else:
        if digest:
            image_info = get_image_info(userId, "docker", digest, registry_lookup=registry_lookup, registry_creds=registry_creds)
            digest = image_info['digest']

        if tag:
            image_info = get_image_info(userId, "docker", tag, registry_lookup=registry_lookup, registry_creds=registry_creds)
            if digest and not image_info['digest']:
                image_info['digest'] = digest

    if 'digest' in image_info:
        imageDigest = str(image_info['digest'])
    else:
        raise Exception("input image_info needs to have a digest")

    if imageId:
        image_info['imageId'] = imageId

    new_input = db.CatalogImage().make()
    new_input['imageDigest'] = imageDigest
    new_input['userId'] = userId
    new_input['image_type'] = 'docker'
    new_input['dockerfile_mode'] = dockerfile_mode

    if not parentdigest:
        parentdigest = imageDigest
    new_input['parentDigest'] = parentdigest

    if created_at:
        new_input['created_at'] = created_at

    final_annotation_data = {}
    for k,v in list(annotations.items()):
        if v != 'null':
            final_annotation_data[k] = v
    new_input['annotations'] = json.dumps(final_annotation_data)

    new_image_obj = db.CatalogImage(**new_input)
    new_image = dict((key,value) for key, value in vars(new_image_obj).items() if not key.startswith('_'))
    new_image['image_detail'] = []

    if image_info['tag']:
        new_input = db.CatalogImageDocker().make()
        new_input['imageDigest'] = imageDigest
        new_input['userId'] = userId
        new_input['dockerfile'] = dockerfile

        for t in ['registry', 'repo', 'tag', 'digest', 'imageId']:
            if t in image_info:
                new_input[t] = image_info[t]

        new_docker_image_obj = db.CatalogImageDocker(**new_input)
        new_docker_image = dict((key,value) for key, value in vars(new_docker_image_obj).items() if not key.startswith('_'))
        new_image['image_detail'] = [new_docker_image]

    ret = new_image
    return(ret)
