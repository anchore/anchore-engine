"""
Tools for using marshmallow/toastedmarshmallow for json->obj->json marshalling stuff.
"""

import toastedmarshmallow
from marshmallow import Schema, fields, post_load


class JitSchema(Schema):
    class Meta:
        jit = toastedmarshmallow.Jit


class JsonSerializationException(Exception):
    pass


class JsonDeserializationException(Exception):
    pass


class JsonMappedMixin(object):
    """
    Simple type wrapper mixin for json serialize/deserialize of objects to reduce boilerplate.

    To use: add as a parent type and set __schema__ at the class level to the JitSchema-subclassed object that is the json schema to use.
    Then call <class>.from_json(dict) and <obj>.to_json()

    Example:
        {'bucket': 'xx', 'key': 'blah'} -> obj
        obj = ObjectStoreLocation.from_json(json.loads(input_string))
        obj.to_json() # Gives a dict
        obj.to_json_str() # Gives a string serialized json output

        class ObjectStoreLocation(JsonMappedMixin):
          class ObjectStoreLocationV1Schema(JitSchema):
            bucket = fields.Str()
            key = fields.Str()

            # This tells the system to return the actual object type rather than a serialization result
            @post_load
            def make(self, data):
              return ObjectStoreLocation(**data)


          # Set the schema ref. This doesn't strictly have to be a child-class, could be outside the parent type. Done here for clarity
          __schema__ = ObjectStoreLocationV1Schema()

          # Needs a kwargs-style constructor for the @post_load/make() call to work
          def __init__(self, bucket=None, key=None):
            self.bucket = bucket
            self.key = key


    """

    __schema__ = None

    @classmethod
    def from_json(cls, data):
        result = cls.__schema__.load(data)
        if not result.errors and result.data:
            return result.data
        else:
            raise JsonDeserializationException(
                "deserialization from json failed with errors: {}".format(result.errors)
            )

    def to_json(self):
        result = self.__schema__.dump(self)
        if result.errors:
            raise JsonSerializationException(
                "serialization to json failed with errors: {}".format(result.errors)
            )
        return result.data

    def to_json_str(self):
        result = self.__schema__.dumps(self)
        if result.errors:
            raise JsonSerializationException(
                "serialization to json failed with errors: {}".format(result.errors)
            )
        return result.data
