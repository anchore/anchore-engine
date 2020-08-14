from anchore_engine import utils
from anchore_engine.db.entities import common

def add_image_from_source(client, source, force=False, enable_subscriptions=None, annotations=None):
    """
    Add an image to the catalog from a source where a source can be one of:

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

    :param client: CatalogClient to fetch any existing details and add the image to the catalog
    :param source: dict source object with keys: 'tag', 'digest', and 'archive', with associated config for pulling source from each. See the api spec for schema details
    :param force: bool, if true re-analyze existing image
    :param enable_subscriptions: the list of subscriptions to enable at add time. Optional
    :param annotations: Dict of k/v annotations. Optional.
    :return: resulting image record
    """
    tag = None
    digest = None
    ts = None
    is_from_archive = False
    dockerfile = None
    image_check = None

    # if not, add it and set it up to be analyzed
    if source.get('archive'):
        img_source = source.get('archive')
        # Do archive-based add
        digest = img_source['digest']
        is_from_archive = True
    elif source.get('tag'):
        # Do tag-based add
        img_source= source.get('tag')
        tag = img_source['pullstring']
        dockerfile = img_source.get('dockerfile')

    elif source.get('digest'):
        # Do digest-based add
        img_source = source.get('digest')

        tag = img_source['tag']
        digest_info = utils.parse_dockerimage_string(img_source['pullstring'])
        digest = digest_info['digest']
        dockerfile = img_source.get('dockerfile')

        ts = img_source.get('creation_timestamp_override')
        if ts:
            try:
                ts = utils.rfc3339str_to_epoch(ts)
            except Exception as err:
                raise api_exceptions.InvalidDateFormat('source.creation_timestamp_override', ts)

        if force:
            # Grab the trailing digest sha section and ensure it exists
            try:
                image_check = client.get_image(digest)
                if not image_check:
                    raise Exception('No image found for digest {}'.format(digest))
                if not ts:
                    # Timestamp required for analysis by digest & tag (if none specified,
                    # default to previous image's timestamp)
                    ts = image_check.get('created_at', common.anchore_now())
            except Exception as err:
                raise ValueError("image digest must already exist to force re-analyze using tag+digest")
        elif not ts:
            # If a new analysis of an image by digest + tag, we need a timestamp to insert into the tag history
            # properly. Therefore, if no timestamp is provided, we use the current time
            ts = common.anchore_now()
    else:
        raise ValueError("The source property must have at least one of tag, digest, or archive set to non-null")

    # add the image to the catalog
    return client.add_image(tag=tag, digest=digest, dockerfile=dockerfile, annotations=annotations,
                            created_at=ts, from_archive=is_from_archive, allow_dockerfile_update=force)
