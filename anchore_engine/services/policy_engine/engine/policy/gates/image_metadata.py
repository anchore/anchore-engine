import re
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.gates.util import CheckOperation
from anchore_engine.services.policy_engine.engine.policy.params import EnumStringParameter, TypeValidator, TriggerParameter
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()


class ImageMetadataAttributeCheckTrigger(BaseTrigger):
    __trigger_name__ = 'attribute'
    __description__ = 'Triggers if a named image metadata value matches the given condition.'

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
        'not_like': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: not bool(re.match(y, x))),
        'in': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x in [z.strip() for z in y.split(',')]),
        'not_in': CheckOperation(requires_rvalue=True, eval_function=lambda x, y: x not in [z.strip() for z in y.split(',')])
    }

    __valid_attributes__ = {
        'size': lambda x: x.size,
        'architecture': lambda x: x.docker_data_json.get('Architecture') if x.docker_data_json else None,
        'os_type': lambda x: x.docker_data_json.get('Os', x.docker_data_json.get('os')) if x.docker_data_json else None,
        'distro': lambda x: x.distro_name,
        'distro_version': lambda x: x.distro_version,
        'like_distro': lambda x: x.like_distro,
        'layer_count': lambda x: len(x.layers_json) if x.layers_json else 0
    }

    attribute = EnumStringParameter(name='attribute', example_str='size', description='Attribute name to be checked.', enum_values=list(__valid_attributes__.keys()), is_required=True, sort_order=1)
    check = EnumStringParameter(name='check', example_str='>', description='The operation to perform the evaluation.', enum_values=list(__ops__.keys()), is_required=True, sort_order=2)
    check_value = TriggerParameter(name='value', example_str='1073741824', description='Value used in comparison.', validator=TypeValidator('string'), is_required=False, sort_order=3)

    def evaluate(self, image_obj, context):
        attr = self.attribute.value()
        check = self.check.value()
        rval = self.check_value.value()

        if not attr or not check:
            return

        op = self.__ops__.get(check)
        if op is None or op.requires_rvalue and not rval:
            # Raise exception or fall thru
            return

        img_val = self.__valid_attributes__[attr](image_obj)
        # Make consistent types (specifically for int/float/str)
        if type(img_val) in [str, int, float, str]:
            rval = type(img_val)(rval)

        if op.eval_function(img_val, rval):
            self._fire(msg="Attribute check for attribute: '{}' check: '{}' check_value: '{}' matched image value: '{}'".format(attr, check, (str(rval) if rval is not None else ''), img_val))


class ImageMetadataGate(Gate):
    __gate_name__ = 'metadata'
    __description__ = 'Checks against image metadata, such as size, OS, distro, architecture, etc.'

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

        :rtype:
        :return: updated context
        """

        # Optimization by single-pass parsing the docker file instead of one per trigger eval.
        # unknown/known is up to each trigger

        return context
