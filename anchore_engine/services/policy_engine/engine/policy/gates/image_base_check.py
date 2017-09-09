import re

from anchore_engine.clients.catalog import get_image
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.db import db_users

class BaseOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'BASEOUTOFDATE'
    __description__ = 'triggers if the image\'s base image has been updated since the image was built/analyzed'
    __params__ = {}

    _catalog_creds = None

    def _get_catalog_creds(self):
        if not self._catalog_creds:
            self._catalog_creds = db_users.get('admin')
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
        # TODO: test and fix this.
        if re.match('@sha256:[a-f0-9]+$', fromline_ref):
            name_type = 'digest'
            # it's a digest, no match since those are immutable
            return
        else:
            name_type = 'tag'

        if name_type == 'tag':
            record = get_image(userId=(self._get_catalog_creds()['userId'], self._get_catalog_creds()['password']), tag=fromline_ref)
            image_id = record['imageId']
        elif name_type == 'digest':
            record = get_image(userId=(self._get_catalog_creds()['userId'], self._get_catalog_creds()['password']), digest=fromline_ref)
            image_id = record['imageId']
        else:
            image_id = None

        return image_id

    def evaluate(self, image_obj, context):
        if image_obj.dockerfile_mode == 'Actual':
            # TODO: this is untested, but unused for hosted service...for now.
            realbaseid = None
            if len(image_obj.familytree_json) > 0:
                realbaseid = image_obj.familytree_json[0]

            # Use db to find current image id mapped to the tag
            thefrom_value = self.discover_fromline(image_obj.dockerfile_contents)
            if re.match('.+@sha256:.+', thefrom_value):
                # Assume this is a digest
                return

            #(thefrom, thefromid) = anchore.anchore_utils.discover_from_info(idata['dockerfile_contents'])
            thefromid = self.lookup_image_id_by_ref(context, thefrom_value)

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
