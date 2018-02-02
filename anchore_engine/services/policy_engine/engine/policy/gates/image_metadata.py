import re
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.gates.conditions import CheckOperation, CheckOperations, AttributeListValidator
from anchore_engine.services.policy_engine.engine.policy.params import EnumCommaDelimStringListParameter, EnumStringParameter, TypeValidator, TriggerParameter
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()


class ImageMetadataAttributeCheckTrigger(BaseTrigger):
    __trigger_name__ = 'attributecheck'
    __description__ = 'triggers if a named image attribute matches the given condition'

    __ops__ = {
        '=': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x == y),
        '!=': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x != y),
        '>': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x > y),
        '<': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x < y),
        '>=': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x >= y),
        '<=': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x <= y),
        'exists': CheckOperation(requires_rvalue=False, eval_function=lambda x, y: bool(x)),
        'not_exists': CheckOperation(requires_rvalue=False, eval_function=lambda x, y: not bool(x)),
        'like': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: bool(re.match(y, x))),
        'not_like': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: not bool(re.match(y, x)))
    }

    __valid_attributes__ = {
        'size': lambda x: x.size,
        'architecture': lambda x: x.docker_data_json.get('Architecture') if x.docker_data_json else None,
        'os_type': lambda x: x.docker_data_json.get('Os') if x.docker_data_json else None,
        'distro': lambda x: x.distro_name,
        'distro_version': lambda x: x.distro_version,
        'like_distro': lambda x: x.like_distro,
        'layer_count': lambda x: len(x.layers_json) if x.layers_json else 0
    }

    __checks__ = CheckOperations(__ops__)
    __value_validator__ = lambda x: True

    attributes = EnumCommaDelimStringListParameter(name='attributes', description='List of attribute names to apply as rvalues to the check operation', enum_values=__valid_attributes__)
    check = EnumStringParameter(name='check', description='The operation to perform the evaluation', enum_values=__ops__.keys())
    check_value = TriggerParameter(name='check_value', description='The lvalue in the check operation.', validator=TypeValidator('string'))

    def evaluate(self, image_obj, context):
        attrs = self.attributes.value()
        check = self.check.value()
        rval = self.check_value.value()

        if not attrs or not check:
            return

        if self.__checks__.get_op(check).requires_rvalue and not rval:
            # Raise exception or fall thru
            return

        for attr in attrs:
            img_val = self.__valid_attributes__[attr](image_obj)
            # Make consistent types (specifically for int/float/str)
            if type(img_val) in [str, int, float, unicode]:
                rval = type(img_val)(rval)

            if self.__checks__.get_op(check).eval_function(img_val, rval):
                self._fire(msg="Attribute check for attribute: '{}' check: '{}' check_value: '{}' matched image value: '{}'".format(attr, check, (str(rval) if rval is not None else ''), img_val))


class ImageMetadataGate(Gate):
    __gate_name__ = 'metadatacheck'
    __description__ = 'Check Image Metadata'

    __triggers__ = [
        ImageMetadataAttributeCheckTrigger,
    ]

    def prepare_context(self, image_obj, context):
        """
        Pre-processes the image's dockerfile.
        Leaves the context with a dictionary of dockerfile lines by directive.
        e.g.
        context.data['dockerfile']['RUN'] = ['RUN apt-get update', 'RUN blah']
        context.data['dockerfile']['VOLUME'] = ['VOLUME /tmp', 'VOLUMN /var/log']

        :return: updated context
        """

        # Optimization by single-pass parsing the docker file instead of one per trigger eval.
        # unknown/known is up to each trigger

        return context
