import base64
import json

import anchore_engine
from anchore_engine import db, utils
from anchore_engine.apis.exceptions import BadRequest, ResourceNotFound
from anchore_engine.common.helpers import make_anchore_exception
from anchore_engine.db import db_catalog_image
from anchore_engine.services.apiext.api import helpers
from anchore_engine.subsys import logger, taskstate


class ImageContentGetter:
    __normalize_to_user_format_on_load__ = True
    __verify_content_type__ = True

    def __init__(self, account_id, content_type, image_digest):
        self.account_id = account_id
        self.content_type = content_type
        self.image_digest = image_digest
        self.obj_mgr = anchore_engine.subsys.object_store.manager.get_manager()

    def get_error_detail(self):
        return {
            "account_id": self.account_id,
            "content_type": self.content_type,
            "image_digest": self.image_digest,
        }

    def verify_analysis_status(self, image_report, allow_analyzing_state=False):
        """
        Raises an exception if the image analysis is not complete. Images in "analyzing" state can optionally be permitted by passing in the allow_analyzing_state argument.

        :param image_report: image report
        :type image_report: dict
        :param allow_analyzing_state: whether or not to permit images in "analyzing" state
        :type allow_analyzing_state: bool
        :rtype: None
        """
        allowed_states = [taskstate.complete_state("analyze")]
        if allow_analyzing_state:
            allowed_states.append(taskstate.working_state("analyze"))
        if image_report and image_report["analysis_status"] not in allowed_states:
            raise ResourceNotFound(
                "image is not analyzed - analysis_status: %s"
                % image_report["analysis_status"],
                detail=self.get_error_detail(),
            )

    def get(self, allow_analyzing_state=False):
        with db.session_scope() as session:
            image_report = db_catalog_image.get(
                self.image_digest, self.account_id, session=session
            )
        if not image_report:
            raise ResourceNotFound("Image not found", detail=self.get_error_detail())

        self.verify_analysis_status(
            image_report, allow_analyzing_state=allow_analyzing_state
        )

        image_content_data = self.get_image_content_data(self.image_digest)

        if self.__verify_content_type__ and self.content_type not in image_content_data:
            raise BadRequest(
                "image content of type (%s) was not an available type at analysis time for this image"
                % str(self.content_type),
                detail=self.get_error_detail(),
            )

        if self.__normalize_to_user_format_on_load__:
            image_content_data = helpers.make_image_content_response(
                self.content_type, image_content_data[self.content_type]
            )

        return self.hydrate_additional_data(image_content_data, image_report)

    def get_image_content_data(self, image_digest):
        try:
            return json.loads(
                utils.ensure_str(
                    self.obj_mgr.get(
                        self.account_id, "image_content_data", image_digest
                    )
                )
            )["document"]
        except Exception as err:
            logger.error("Failed to load image content data")
            raise make_anchore_exception(
                err,
                input_message="cannot fetch content data from archive",
                input_httpcode=500,
            )

    def hydrate_additional_data(self, image_content_data, image_report):
        return image_content_data


class ImageManifestContentGetter(ImageContentGetter):
    def get_image_content_data(self, image_digest):
        try:
            image_manifest_data = json.loads(
                utils.ensure_str(
                    self.obj_mgr.get(self.account_id, "manifest_data", image_digest)
                )
            )["document"]
        except Exception as err:
            logger.error("Failed to load image content data")
            raise make_anchore_exception(
                err,
                input_message="cannot fetch content data %s from archive"
                % self.content_type,
                input_httpcode=500,
            )

        return {"manifest": image_manifest_data}


class ImageDockerfileContentGetter(ImageContentGetter):
    __normalize_to_user_format_on_load__ = False

    def hydrate_additional_data(self, image_content_data, image_report):
        if image_content_data.get("dockerfile", None):
            # Nothing to do here
            return helpers.make_image_content_response(
                self.content_type, image_content_data[self.content_type]
            )
        try:
            if image_report.get("dockerfile_mode", None) != "Actual":
                # Nothing to do here
                return helpers.make_image_content_response(
                    self.content_type, image_content_data[self.content_type]
                )

            for image_detail in image_report.get("image_detail", []):
                if not image_detail.get("dockerfile", None):
                    # Nothing to do here
                    continue

                logger.debug("migrating old dockerfile content form into new")
                image_content_data["dockerfile"] = utils.ensure_str(
                    base64.decodebytes(
                        utils.ensure_bytes(image_detail.get("dockerfile", ""))
                    )
                )
                jsonbytes = utils.ensure_bytes(
                    json.dumps({"document": image_content_data})
                )
                self.obj_mgr.put(
                    self.account_id,
                    "image_content_data",
                    image_report["imageDigest"],
                    jsonbytes,
                )
                break
        except Exception as err:
            logger.warn(
                "cannot fetch/decode dockerfile contents from image_detail - {}".format(
                    err
                )
            )
        return helpers.make_image_content_response(
            self.content_type, image_content_data[self.content_type]
        )
