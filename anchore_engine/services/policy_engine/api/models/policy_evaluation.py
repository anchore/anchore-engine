# coding: utf-8


from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from anchore_engine.services.policy_engine.api.models.base_model_ import Model
from anchore_engine.services.policy_engine.api.models.policy_evaluation_problem import (
    PolicyEvaluationProblem,
)  # noqa: F401,E501
from anchore_engine.services.policy_engine.api import util


class PolicyEvaluation(Model):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    def __init__(
        self,
        user_id=None,
        image_id=None,
        tag=None,
        bundle=None,
        matched_mapping_rule=None,
        matched_whitelisted_images_rule=None,
        matched_blacklisted_images_rule=None,
        result=None,
        created_at=None,
        last_modified=None,
        final_action=None,
        final_action_reason=None,
        evaluation_problems=None,
    ):  # noqa: E501
        """PolicyEvaluation - a model defined in Swagger

        :param user_id: The user_id of this PolicyEvaluation.  # noqa: E501
        :type user_id: str
        :param image_id: The image_id of this PolicyEvaluation.  # noqa: E501
        :type image_id: str
        :param tag: The tag of this PolicyEvaluation.  # noqa: E501
        :type tag: str
        :param bundle: The bundle of this PolicyEvaluation.  # noqa: E501
        :type bundle: object
        :param matched_mapping_rule: The matched_mapping_rule of this PolicyEvaluation.  # noqa: E501
        :type matched_mapping_rule: object
        :param matched_whitelisted_images_rule: The matched_whitelisted_images_rule of this PolicyEvaluation.  # noqa: E501
        :type matched_whitelisted_images_rule: object
        :param matched_blacklisted_images_rule: The matched_blacklisted_images_rule of this PolicyEvaluation.  # noqa: E501
        :type matched_blacklisted_images_rule: object
        :param result: The result of this PolicyEvaluation.  # noqa: E501
        :type result: object
        :param created_at: The created_at of this PolicyEvaluation.  # noqa: E501
        :type created_at: int
        :param last_modified: The last_modified of this PolicyEvaluation.  # noqa: E501
        :type last_modified: int
        :param final_action: The final_action of this PolicyEvaluation.  # noqa: E501
        :type final_action: str
        :param final_action_reason: The final_action_reason of this PolicyEvaluation.  # noqa: E501
        :type final_action_reason: str
        :param evaluation_problems: The evaluation_problems of this PolicyEvaluation.  # noqa: E501
        :type evaluation_problems: List[PolicyEvaluationProblem]
        """
        self.swagger_types = {
            "user_id": str,
            "image_id": str,
            "tag": str,
            "bundle": object,
            "matched_mapping_rule": object,
            "matched_whitelisted_images_rule": object,
            "matched_blacklisted_images_rule": object,
            "result": object,
            "created_at": int,
            "last_modified": int,
            "final_action": str,
            "final_action_reason": str,
            "evaluation_problems": List[PolicyEvaluationProblem],
        }

        self.attribute_map = {
            "user_id": "user_id",
            "image_id": "image_id",
            "tag": "tag",
            "bundle": "bundle",
            "matched_mapping_rule": "matched_mapping_rule",
            "matched_whitelisted_images_rule": "matched_whitelisted_images_rule",
            "matched_blacklisted_images_rule": "matched_blacklisted_images_rule",
            "result": "result",
            "created_at": "created_at",
            "last_modified": "last_modified",
            "final_action": "final_action",
            "final_action_reason": "final_action_reason",
            "evaluation_problems": "evaluation_problems",
        }

        self._user_id = user_id
        self._image_id = image_id
        self._tag = tag
        self._bundle = bundle
        self._matched_mapping_rule = matched_mapping_rule
        self._matched_whitelisted_images_rule = matched_whitelisted_images_rule
        self._matched_blacklisted_images_rule = matched_blacklisted_images_rule
        self._result = result
        self._created_at = created_at
        self._last_modified = last_modified
        self._final_action = final_action
        self._final_action_reason = final_action_reason
        self._evaluation_problems = evaluation_problems

    @classmethod
    def from_dict(cls, dikt):
        """Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The PolicyEvaluation of this PolicyEvaluation.  # noqa: E501
        :rtype: PolicyEvaluation
        """
        return util.deserialize_model(dikt, cls)

    @property
    def user_id(self):
        """Gets the user_id of this PolicyEvaluation.

        Unique identifier (UUID) for the catalog user  # noqa: E501

        :return: The user_id of this PolicyEvaluation.
        :rtype: str
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        """Sets the user_id of this PolicyEvaluation.

        Unique identifier (UUID) for the catalog user  # noqa: E501

        :param user_id: The user_id of this PolicyEvaluation.
        :type user_id: str
        """

        self._user_id = user_id

    @property
    def image_id(self):
        """Gets the image_id of this PolicyEvaluation.


        :return: The image_id of this PolicyEvaluation.
        :rtype: str
        """
        return self._image_id

    @image_id.setter
    def image_id(self, image_id):
        """Sets the image_id of this PolicyEvaluation.


        :param image_id: The image_id of this PolicyEvaluation.
        :type image_id: str
        """
        if image_id is None:
            raise ValueError(
                "Invalid value for `image_id`, must not be `None`"
            )  # noqa: E501

        self._image_id = image_id

    @property
    def tag(self):
        """Gets the tag of this PolicyEvaluation.


        :return: The tag of this PolicyEvaluation.
        :rtype: str
        """
        return self._tag

    @tag.setter
    def tag(self, tag):
        """Sets the tag of this PolicyEvaluation.


        :param tag: The tag of this PolicyEvaluation.
        :type tag: str
        """
        if tag is None:
            raise ValueError(
                "Invalid value for `tag`, must not be `None`"
            )  # noqa: E501

        self._tag = tag

    @property
    def bundle(self):
        """Gets the bundle of this PolicyEvaluation.

        The bundle used for evaluation  # noqa: E501

        :return: The bundle of this PolicyEvaluation.
        :rtype: object
        """
        return self._bundle

    @bundle.setter
    def bundle(self, bundle):
        """Sets the bundle of this PolicyEvaluation.

        The bundle used for evaluation  # noqa: E501

        :param bundle: The bundle of this PolicyEvaluation.
        :type bundle: object
        """
        if bundle is None:
            raise ValueError(
                "Invalid value for `bundle`, must not be `None`"
            )  # noqa: E501

        self._bundle = bundle

    @property
    def matched_mapping_rule(self):
        """Gets the matched_mapping_rule of this PolicyEvaluation.

        The bundle mapping rule that was evaluated to result in the evaluated policy and whitelists being selected  # noqa: E501

        :return: The matched_mapping_rule of this PolicyEvaluation.
        :rtype: object
        """
        return self._matched_mapping_rule

    @matched_mapping_rule.setter
    def matched_mapping_rule(self, matched_mapping_rule):
        """Sets the matched_mapping_rule of this PolicyEvaluation.

        The bundle mapping rule that was evaluated to result in the evaluated policy and whitelists being selected  # noqa: E501

        :param matched_mapping_rule: The matched_mapping_rule of this PolicyEvaluation.
        :type matched_mapping_rule: object
        """
        if matched_mapping_rule is None:
            raise ValueError(
                "Invalid value for `matched_mapping_rule`, must not be `None`"
            )  # noqa: E501

        self._matched_mapping_rule = matched_mapping_rule

    @property
    def matched_whitelisted_images_rule(self):
        """Gets the matched_whitelisted_images_rule of this PolicyEvaluation.

        The trusted image entry matched if any  # noqa: E501

        :return: The matched_whitelisted_images_rule of this PolicyEvaluation.
        :rtype: object
        """
        return self._matched_whitelisted_images_rule

    @matched_whitelisted_images_rule.setter
    def matched_whitelisted_images_rule(self, matched_whitelisted_images_rule):
        """Sets the matched_whitelisted_images_rule of this PolicyEvaluation.

        The trusted image entry matched if any  # noqa: E501

        :param matched_whitelisted_images_rule: The matched_whitelisted_images_rule of this PolicyEvaluation.
        :type matched_whitelisted_images_rule: object
        """
        if matched_whitelisted_images_rule is None:
            raise ValueError(
                "Invalid value for `matched_whitelisted_images_rule`, must not be `None`"
            )  # noqa: E501

        self._matched_whitelisted_images_rule = matched_whitelisted_images_rule

    @property
    def matched_blacklisted_images_rule(self):
        """Gets the matched_blacklisted_images_rule of this PolicyEvaluation.

        The image blacklist entry matched if any  # noqa: E501

        :return: The matched_blacklisted_images_rule of this PolicyEvaluation.
        :rtype: object
        """
        return self._matched_blacklisted_images_rule

    @matched_blacklisted_images_rule.setter
    def matched_blacklisted_images_rule(self, matched_blacklisted_images_rule):
        """Sets the matched_blacklisted_images_rule of this PolicyEvaluation.

        The image blacklist entry matched if any  # noqa: E501

        :param matched_blacklisted_images_rule: The matched_blacklisted_images_rule of this PolicyEvaluation.
        :type matched_blacklisted_images_rule: object
        """
        if matched_blacklisted_images_rule is None:
            raise ValueError(
                "Invalid value for `matched_blacklisted_images_rule`, must not be `None`"
            )  # noqa: E501

        self._matched_blacklisted_images_rule = matched_blacklisted_images_rule

    @property
    def result(self):
        """Gets the result of this PolicyEvaluation.

        Object containing the evaluation result for the given policy and whitelists against the image  # noqa: E501

        :return: The result of this PolicyEvaluation.
        :rtype: object
        """
        return self._result

    @result.setter
    def result(self, result):
        """Sets the result of this PolicyEvaluation.

        Object containing the evaluation result for the given policy and whitelists against the image  # noqa: E501

        :param result: The result of this PolicyEvaluation.
        :type result: object
        """
        if result is None:
            raise ValueError(
                "Invalid value for `result`, must not be `None`"
            )  # noqa: E501

        self._result = result

    @property
    def created_at(self):
        """Gets the created_at of this PolicyEvaluation.

        Epoch time on server of record creation  # noqa: E501

        :return: The created_at of this PolicyEvaluation.
        :rtype: int
        """
        return self._created_at

    @created_at.setter
    def created_at(self, created_at):
        """Sets the created_at of this PolicyEvaluation.

        Epoch time on server of record creation  # noqa: E501

        :param created_at: The created_at of this PolicyEvaluation.
        :type created_at: int
        """

        self._created_at = created_at

    @property
    def last_modified(self):
        """Gets the last_modified of this PolicyEvaluation.

        Epoch time on server of last modification  # noqa: E501

        :return: The last_modified of this PolicyEvaluation.
        :rtype: int
        """
        return self._last_modified

    @last_modified.setter
    def last_modified(self, last_modified):
        """Sets the last_modified of this PolicyEvaluation.

        Epoch time on server of last modification  # noqa: E501

        :param last_modified: The last_modified of this PolicyEvaluation.
        :type last_modified: int
        """

        self._last_modified = last_modified

    @property
    def final_action(self):
        """Gets the final_action of this PolicyEvaluation.

        The overall outcome of the evaluation. STOP|GO|WARN  # noqa: E501

        :return: The final_action of this PolicyEvaluation.
        :rtype: str
        """
        return self._final_action

    @final_action.setter
    def final_action(self, final_action):
        """Sets the final_action of this PolicyEvaluation.

        The overall outcome of the evaluation. STOP|GO|WARN  # noqa: E501

        :param final_action: The final_action of this PolicyEvaluation.
        :type final_action: str
        """
        if final_action is None:
            raise ValueError(
                "Invalid value for `final_action`, must not be `None`"
            )  # noqa: E501

        self._final_action = final_action

    @property
    def final_action_reason(self):
        """Gets the final_action_reason of this PolicyEvaluation.

        The reason for the final result  # noqa: E501

        :return: The final_action_reason of this PolicyEvaluation.
        :rtype: str
        """
        return self._final_action_reason

    @final_action_reason.setter
    def final_action_reason(self, final_action_reason):
        """Sets the final_action_reason of this PolicyEvaluation.

        The reason for the final result  # noqa: E501

        :param final_action_reason: The final_action_reason of this PolicyEvaluation.
        :type final_action_reason: str
        """
        allowed_values = [
            "whitelisted",
            "blacklisted",
            "policy_evaluation",
        ]  # noqa: E501
        if final_action_reason not in allowed_values:
            raise ValueError(
                "Invalid value for `final_action_reason` ({0}), must be one of {1}".format(
                    final_action_reason, allowed_values
                )
            )

        self._final_action_reason = final_action_reason

    @property
    def evaluation_problems(self):
        """Gets the evaluation_problems of this PolicyEvaluation.

        list of error objects indicating errors encountered during evaluation execution  # noqa: E501

        :return: The evaluation_problems of this PolicyEvaluation.
        :rtype: List[PolicyEvaluationProblem]
        """
        return self._evaluation_problems

    @evaluation_problems.setter
    def evaluation_problems(self, evaluation_problems):
        """Sets the evaluation_problems of this PolicyEvaluation.

        list of error objects indicating errors encountered during evaluation execution  # noqa: E501

        :param evaluation_problems: The evaluation_problems of this PolicyEvaluation.
        :type evaluation_problems: List[PolicyEvaluationProblem]
        """

        self._evaluation_problems = evaluation_problems
