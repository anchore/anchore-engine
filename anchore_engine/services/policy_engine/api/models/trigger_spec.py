# coding: utf-8


from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from anchore_engine.services.policy_engine.api.models.base_model_ import Model
from anchore_engine.services.policy_engine.api.models.trigger_param_spec import (
    TriggerParamSpec,
)  # noqa: F401,E501
from anchore_engine.services.policy_engine.api import util


class TriggerSpec(Model):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    def __init__(
        self,
        name=None,
        description=None,
        state=None,
        superceded_by=None,
        parameters=None,
    ):  # noqa: E501
        """TriggerSpec - a model defined in Swagger

        :param name: The name of this TriggerSpec.  # noqa: E501
        :type name: str
        :param description: The description of this TriggerSpec.  # noqa: E501
        :type description: str
        :param state: The state of this TriggerSpec.  # noqa: E501
        :type state: str
        :param superceded_by: The superceded_by of this TriggerSpec.  # noqa: E501
        :type superceded_by: str
        :param parameters: The parameters of this TriggerSpec.  # noqa: E501
        :type parameters: List[TriggerParamSpec]
        """
        self.swagger_types = {
            "name": str,
            "description": str,
            "state": str,
            "superceded_by": str,
            "parameters": List[TriggerParamSpec],
        }

        self.attribute_map = {
            "name": "name",
            "description": "description",
            "state": "state",
            "superceded_by": "superceded_by",
            "parameters": "parameters",
        }

        self._name = name
        self._description = description
        self._state = state
        self._superceded_by = superceded_by
        self._parameters = parameters

    @classmethod
    def from_dict(cls, dikt):
        """Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The TriggerSpec of this TriggerSpec.  # noqa: E501
        :rtype: TriggerSpec
        """
        return util.deserialize_model(dikt, cls)

    @property
    def name(self):
        """Gets the name of this TriggerSpec.

        Name of the trigger as it would appear in a policy document  # noqa: E501

        :return: The name of this TriggerSpec.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this TriggerSpec.

        Name of the trigger as it would appear in a policy document  # noqa: E501

        :param name: The name of this TriggerSpec.
        :type name: str
        """

        self._name = name

    @property
    def description(self):
        """Gets the description of this TriggerSpec.

        Trigger description for what it tests and when it will fire during evaluation  # noqa: E501

        :return: The description of this TriggerSpec.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this TriggerSpec.

        Trigger description for what it tests and when it will fire during evaluation  # noqa: E501

        :param description: The description of this TriggerSpec.
        :type description: str
        """

        self._description = description

    @property
    def state(self):
        """Gets the state of this TriggerSpec.

        State of the trigger  # noqa: E501

        :return: The state of this TriggerSpec.
        :rtype: str
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this TriggerSpec.

        State of the trigger  # noqa: E501

        :param state: The state of this TriggerSpec.
        :type state: str
        """
        allowed_values = ["active", "deprecated", "eol"]  # noqa: E501
        if state not in allowed_values:
            raise ValueError(
                "Invalid value for `state` ({0}), must be one of {1}".format(
                    state, allowed_values
                )
            )

        self._state = state

    @property
    def superceded_by(self):
        """Gets the superceded_by of this TriggerSpec.

        The name of another trigger that supercedes this on functionally if this is deprecated  # noqa: E501

        :return: The superceded_by of this TriggerSpec.
        :rtype: str
        """
        return self._superceded_by

    @superceded_by.setter
    def superceded_by(self, superceded_by):
        """Sets the superceded_by of this TriggerSpec.

        The name of another trigger that supercedes this on functionally if this is deprecated  # noqa: E501

        :param superceded_by: The superceded_by of this TriggerSpec.
        :type superceded_by: str
        """

        self._superceded_by = superceded_by

    @property
    def parameters(self):
        """Gets the parameters of this TriggerSpec.

        The list of parameters that are valid for this trigger  # noqa: E501

        :return: The parameters of this TriggerSpec.
        :rtype: List[TriggerParamSpec]
        """
        return self._parameters

    @parameters.setter
    def parameters(self, parameters):
        """Sets the parameters of this TriggerSpec.

        The list of parameters that are valid for this trigger  # noqa: E501

        :param parameters: The parameters of this TriggerSpec.
        :type parameters: List[TriggerParamSpec]
        """

        self._parameters = parameters
