from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
#
#
# class MetadataConditionGate(Gate):
#     """
#     A generic conditional check gate on specific data items in the image metadata.
#     """
#     __gate_name__ = 'attribute_condition'
#
#     class ExistsTrigger(BaseTrigger):
#         __trigger_name__ = 'exists'
#         __params__ = {'key': str}
#
#     class LikeTrigger(BaseTrigger):
#         __trigger_name__ = 'like_match'
#         __params__ = {
#             'key': str,
#             'pattern': str,
#             }
#
#     class EqualsTrigger(BaseTrigger):
#         __trigger_name__ = 'equals'
#         __params__ = {
#             'key': str,
#             'value': str
#         }
#
#     class NotExists(BaseTrigger):
#         __trigger_name__ = 'not_exists'
#         __params__ = {'key': str}
#
#     @staticmethod
#     def resolve_key(key, image_obj):
#         """
#         Resolves a text key to a specific attribute of an image and returns it.
#         Examples:
#         $image.dockerfile.from -> image.dockerfile_contents['from']
#
#
#         :param key:
#         :param image_obj:
#         :return:
#         """
#         # Resolves a key to a specific image element and retrieves it from the image object
#         key_components = key.split('.')
#         if key_components[0] != '$image':
#             raise ValueError('Invalid key format: {}. Must be $image.p1.p2.p3...pN')
#         else:
#             key_components.pop()
#
#         obj = image_obj
#         for k in key_components:
#             obj = model.get_lookup(k, obj)
#
#
#
# # TODO: zhill - Just jotted down these notes for future work
#
# # Powerful, but need to ensure consistency, may need to add statement Ids to the language to facilitate
# # direct references here
# class BooleanOperatorGate(Gate):
#     __gate_name__ = 'combiner'
#
#     class AndTrigger(BaseTrigger):
#         __trigger_name__ = 'and'
#         __params__ = {
#             'gate_1': str,
#             'trigger_1': str,
#             'result_1': str,
#             'gate_2': str,
#             'trigger_2': str,
#             'result_2': str
#             }
#
#     class OrTrigger(BaseTrigger):
#         __trigger_name__ = 'or'
#         __params__ = {
#             'gate_1': str,
#             'trigger_1': str,
#             'result_1': str,
#             'gate_2': str,
#             'trigger_2': str,
#             'result_2': str
#         }
#
#     class XorTrigger(BaseTrigger):
#         __trigger_name__ = 'xor'
#         __params__ = {
#             'gate_1': str,
#             'trigger_1': str,
#             'result_1': str,
#             'gate_2': str,
#             'trigger_2': str,
#             'result_2': str
#         }
#
#     class NotTrigger(BaseTrigger):
#         __trigger_name__ = 'not'
#         __params__ = {
#             'gate_1': str,
#             'trigger_1': str,
#             'result_1': str
#         }
#
#
#
