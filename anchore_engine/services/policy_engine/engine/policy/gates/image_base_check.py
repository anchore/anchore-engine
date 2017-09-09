import re

from anchore_engine.clients.catalog import get_image, get_user
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate, TriggerEvaluationError
from anchore_engine.db import db_users
from anchore_engine.services.policy_engine.engine.logs import get_logger
log = get_logger()

class BaseOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'BASEOUTOFDATE'
    __description__ = 'triggers if the image\'s base image has been updated since the image was built/analyzed'
    __params__ = {}

    _catalog_creds = None

    def _get_catalog_creds(self, session):
        if not self._catalog_creds:
            self._catalog_creds = db_users.get(userId='admin', session=session)
        return self._catalog_creds

    def discover_fromline(self, dockerfile_contents):
        fromline = re.match(".*FROM\s+(\S+).*", dockerfile_contents).group(1)
        if fromline:
            fromline = fromline.lower()
        return fromline

    def lookup_image_id_by_ref(self, context, fromline_ref):
        """
        Find the image id for the fromline_reference value. The FROM line of a Dockerfile. Either a tag reference
        or a digest reference. Scans the service db, not the source registry.

        :param context:
        :param fromline_ref:
        :return: image_id mapped to tag (as far as we know) or None if there isn't one or the reference is a digest rather than tag
        """

        if re.match('@sha256:[a-f0-9]+$', fromline_ref):
            # it's a digest, no match since those are immutable
            return
        else:
            name_type = 'tag'

        creds = self._get_catalog_creds(context.db)

        if name_type == 'tag':
            if not creds:
                raise TriggerEvaluationError(self, 'Could not locate credentials for querying the catalog')
            try:
                record = get_image(userId=(creds['userId'], creds['password']), tag=fromline_ref)
                return record[0]['image_detail'][0]['imageId']
            except Exception as e:
                log.exception('Received exception looking up image in catalog by ref: {}. {}'.format(fromline_ref, e))
                # Assume this means the image is not available
                return None

        elif name_type == 'digest':
            try:
                record = get_image(userId=(creds['userId'], creds['password']), digest=fromline_ref)
                return record[0]['image_detail'][0]['imageDigest']
            except Exception as e:
                # Assume this means the image is not available
                log.exception('Received exception looking up image in catalog by ref: {}'.format(fromline_ref, e))
                return None
        else:
            return None

    def evaluate(self, image_obj, context):
        if image_obj.dockerfile_mode == 'Actual':
            realbaseid = None
            if len(image_obj.familytree_json) > 0:
                realbaseid = image_obj.familytree_json[0]

            # Use db to find current image id mapped to the tag
            thefrom_value = self.discover_fromline(image_obj.dockerfile_contents)
            if re.match('.+@sha256:.+', thefrom_value):
                # Assume this is a digest
                return

            thefromid = self.lookup_image_id_by_ref(context, thefrom_value)
            log.info('Checking base status: image id = {}, base = {}, base from line = {}, fromid = {}'.format(image_obj.id, realbaseid, thefrom_value, thefromid))

            if thefromid and realbaseid != thefromid:
                self._fire(msg="Image base image (" + str(thefrom_value) + ") ID is (" + str(realbaseid)[0:12] +
                                "), but the latest ID for (" + str(thefrom_value) + ") is (" + str(thefromid)[0:12] + ")")
        else:
            return
            # Not supported for guessed dockerfiles


class ImageCheckGate(Gate):
    __gate_name__ =  "IMAGECHECK"
    __triggers__ = [BaseOutOfDateTrigger]

    def prepare_context(self, image_obj, context):
        return context
